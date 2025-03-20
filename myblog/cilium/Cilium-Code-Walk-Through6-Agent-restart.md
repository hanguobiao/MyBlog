---
title: (转+译)Cilium Code Walk Through 6 - Conntrack (CT) related BPF Maps on Agent Restart
date: 2025-02-27
update: 2025-02-28
comment: false
tags:
  - Cilium
categories:
  - Cilium
---

使用Cilium的时候可能会有这样的担心，在agent重启后，网络通信是否会出现问题？这里就探究一下BPF Maps在重启时的逻辑

*<!--more-->*
# Cilium: Handle Conntrack (CT) related BPF Maps on Agent Restart

![img](https://myblog-1307634347.cos.ap-guangzhou.myqcloud.com/blog/bpf-maps.png)

# 1 Prerequisites and background knowledge

## 1.1 BPF maps

BPF Maps用于在不同BPF程序、内核与用户空间之间共享数据

BPF Maps 可以被挂载到 BPFFS（BPF 文件系统），这使得它们能够在代理重启和节点重启后依然保留。

## 1.2 BPF maps in Cilium

Cilium agent 严重依赖 BPF maps，其中大多数都被固定到 bpffs。让我们首先在工作节点上简单浏览一下它们：

```
root@node:/sys/fs/bpf/tc/globals $ ls
cilium_call_policy    cilium_calls_00571    cilium_calls_hostns_01320 cilium_calls_netdev_00008 cilium_ct4_global
cilium_ct_any4_global cilium_encrypt_state  cilium_events             cilium_ipcache            cilium_ipv4_frag_datagrams
cilium_lb4_affinity   cilium_lb4_backends   cilium_lb4_reverse_nat    cilium_lb4_services_v2    cilium_lb_affinity_match
cilium_lxc            cilium_metrics        cilium_policy_01955       cilium_signals            cilium_tunnel_map
...
```

上面的 BPF maps可以按照功能分类

1. 尾调用
   1. `cilium_calls_<ep_id>`
   2. `cilium_calls_hostns_<ep_id>`
   3. `cilium_calls_netdev_<ep_id>`

用于在不同BPF程序之间进行尾调用。

尾调用是一种特殊形式的函数调用，关于在Cilium中如何执行尾调用，请参见[1]。

2. 连接跟踪（conntrack, CT）
   1. `cilium_ct4_global`
   2. `cilium_ct4_<ep_id>`: if per-endpoint CT (`ConntrackLocal=true`) is enabled
   3. `cilium_ct_any4_global`

3. 加密

​	cilium_encrypt_state 

4. 负载均衡或K8s服务处理

​	cilium_lb4_xxx 

用于客户端负载均衡，例如K8s服务处理（将ServiceIP/ExternalIPs/NodePorts映射到后端PodIPs）。更多信息请参考[3]。

5. **Network policy**

​	cilium_policy_<ep_id>`

 用于执行CiliumNetworkPolicy（CNP），它实现并扩展了K8s的NetworkPolicy模型。

6. events, metrics, etc

## 1.3 Inspect CT entries in Cilium

```
(node) $ cilium bpf ct list global | head
TCP IN  192.168.139.13:44808 -> 192.168.64.97:4240 expires=3553147 RxPackets=6 RxBytes=506 RxFlagsSeen=0x03 LastRxReport=3553137 TxPackets=4 TxBytes=347 TxFlagsSeen=0x03 LastTxReport=3553137 Flags=0x0013 [ RxClosing TxClosing SeenNonSyn ] RevNAT=0 SourceSecurityID=2 IfIndex=0
TCP OUT 192.168.54.113:36260 -> 192.168.198.12:4240 expires=3553014 RxPackets=14 RxBytes=1090 RxFlagsSeen=0x03 LastRxReport=3553004 TxPackets=9 TxBytes=704 TxFlagsSeen=0x03 LastTxReport=3553004 Flags=0x0013 [ RxClosing TxClosing SeenNonSyn ] RevNAT=0 SourceSecurityID=0 IfIndex=0
...
```

# 2 Functionality test: adjust CT table (map) size

如果连接跟踪表（CT表）因为连接过多而满，我们必须调整表的大小（相当于CT映射的大小），例如，通过命令行参数：

--bpf-ct-global-any-max=262144
 --bpf-ct-global-tcp-max=524288

然后重启代理以加载配置更改。

## 2.1 Concern: will existing connections be interrupted?

这个操作会中断现有的连接吗？例如，该节点上已经存在数十万条已建立的连接。

## 2.2 Test case 1: inbound connection

首先，测试该节点上Pod的入站/入口连接，如下图所示：

![img](https://myblog-1307634347.cos.ap-guangzhou.myqcloud.com/blog/ingress-connection.png)

### Step 1. Create an inbound connection

On another node: initiate a TCP connection and leave it there,

```
(node2) $ telnet 10.5.5.5 80
Connected to 10.5.5.5.
Escape character is '^]'.
```

### Step 2. Enlarge CT (map) size and restart agent

### Step 3. Check connection liveliness

回到node2，可以注意到连接并没有断开

```
(node2) $ telnet 10.5.5.5 80
Connected to 10.5.5.5.
Escape character is '^]'.
```

然后通过发送一些数据来恢复此连接：输入一些内容（例如 aaaaa）然后按回车键，

```
(node2) $ telnet 10.5.5.5 80
Connected to 10.5.5.5.
Escape character is '^]'.

aaaaa
HTTP/1.1 400 Bad Request
Server: nginx/1.11.1
...
```

该Pod返回了HTTP 400错误，这表明我们的TCP连接仍然正常（400是L7层的错误代码，因为我们输入了一些无效的HTTP数据，这意味着L4层是正常的）。

# 3 The code: BPF maps handling on agent restart

## 3.1 High-level overview (call stack)

```
d.initMaps()
|- lxcmap.LXCMap().OpenOrCreate()
|- ipcachemap.IPCacheMap().Recreate()
|- tunnel.TunnelMap().Recreate()
|- d.svc.InitMaps
|- policymap.InitCallMaps()
|- for ep in d.endpointManager.GetEndpoints():
|  |- ep.InitMap()
|- for ep in d.endpointManager.GetEndpoints():
|  |- for m in ctmap.LocalMaps()
|  |  |- m.Create()
|- for m in ctmap.GlobalMaps():
|  |- m.Create()
|- ipmasq.IPMasq4Map().OpenOrCreate();
```

## 3.2 Init map info from agent configurations: `ctmap.InitMapInfo()`

在代理重启过程中，其中一个步骤是通过调用`runDaemon() -> ct.InitMapInfo()`，将用户指定的映射配置保存到包级变量`mapInfo map[mapType]mapAttributes`中。

```
ctmap.InitMapInfo(option.Config.EnableIPv4, option.Config.EnableIPv6, option.Config.EnableNodePort)
```

```
// InitMapInfo builds the information about different CT maps for the
// combination of L3/L4 protocols.
func InitMapInfo(v4, v6, nodeport bool) {
    global4Map, global6Map := nat.GlobalMaps(v4, v6, nodeport)
    global4MapLock := &lock.Mutex{}
    global6MapLock := &lock.Mutex{}

    // SNAT also only works if the CT map is global so all local maps will be nil
    mapInfo = map[mapType]mapAttributes{
       mapTypeIPv4TCPGlobal: {natMap: global4Map, natMapLock: global4MapLock},
       mapTypeIPv6TCPGlobal: {natMap: global6Map, natMapLock: global6MapLock},
       mapTypeIPv4AnyGlobal: {natMap: global4Map, natMapLock: global4MapLock},
       mapTypeIPv6AnyGlobal: {natMap: global6Map, natMapLock: global6MapLock},
    }
}
```

随后，当与CT（连接跟踪）相关的BPF映射被初始化时，它们会从这里的配置存储变量`mapInfo[]`中检索映射配置。

## 3.3 Init map objects: `initMaps()`

在映射配置被解析并保存之后，下一步是根据配置的变化创建、删除或重新创建这些映射。

让我们专注于与CT（连接跟踪）相关的代码：

### ConntrackLocal or non-ConntrackLocal (default)

Cilium 支持将所有连接跟踪（CT）条目存储到全局 CT 表（默认情况下），同时也支持将每个端点的 CT 条目存储到它们各自的 CT 表中（运行时选项 `ConntrackLocal=true`，但目前此选项已损坏）。

尽管名称有些误导性，`func (m *Map) Create()` 实际上是创建/打开/删除/重新创建映射的入口点。它类似于 `OpenOrCreate()`，但在创建或打开映射后会关闭它。我们稍后会跟踪这些方法。

初始化全局 CT 映射
 代理会始终通过调用 `m.Create()` 重新初始化全局 CT 映射

## 3.4 `m.Create() -> m.OpenOrCreate() -> m.openOrCreate() -> Remove() && OpenOrCreateMap()`

Open or create maps:

```
// pkg/bpf/map_linux.go

func (m *Map) Create() (bool, error) {
    isNew := m.OpenOrCreate()
    return isNew, m.Close()
}
```

`m.OpenOrCreate()` is again a wrapper, it calls an internal method `m.openOrCreate()`:

```
// Returns whether the map was deleted and recreated, or an optional error.
func (m *Map) OpenOrCreate() (bool, error) {
    return m.openOrCreate(true)
}
func (m *Map) openOrCreate(pin bool) (bool, error) {
    m.setPathIfUnset()

    if m.NonPersistent {  // If the map represents non-persistent data,
        os.Remove(m.path) // always remove it before opening or creating.
    }

    flags := m.Flags | GetPreAllocateMapFlags(mapType)
    fd, isNew := OpenOrCreateMap(m.path, mapType, m.KeySize, m.ValueSize, m.MaxEntries, flags, m.InnerID, pin)

    registerMap(m.path, m)
    return isNew, nil
}
```

该方法的逻辑如下：

1. 如果映射被标记为非持久化，则删除该映射，稍后会重新创建它。
2. 如果现有映射的属性（如映射类型、键/值大小、容量等）发生变化，则会删除该映射并重新打开，且不会尝试保留其之前的内容。这个属性检查过程在 `OpenOrCreateMap()` 中完成，我们稍后会看到它。

这意味着，当我们使用 `--bpf-ct-global-tcp-max=xxx` 更改映射大小并重启代理时，对应的原始/现有 BPF 映射将始终被删除。

## 3.5 `OpenOrCreateMap() -> objCheck() -> Remove() && recreate -> CreateMap()`

```
// pkg/bpf/bpf_linux.go

func OpenOrCreateMap(path, mapType, keySize, valueSize, maxEntries, flags, innerID, pin bool) (int, bool, error) {
    redo := false
    isNewMap := false

recreate:
    create := true

    // Step 1. ensure map directory exists
    if pin {
        if os.NotExist(path) || redo {
            os.MkdirAll(filepath.Dir(path), 0755)
        } else {
            create = false
        }
    }

    // Step 2. create map if not exist, then return
    if create {
        fd = CreateMap(mapType, keySize, valueSize, maxEntries, flags, innerID, path)
        isNewMap = true

        if pin {
            ObjPin(fd, path)
        }
        return fd, isNewMap, nil
    }

    // Step 3. map already exists, check if there are any map attribute changes,
    // if there is, delete the existing map
    fd = ObjGet(path)
    redo = objCheck(fd, path, mapType, keySize, valueSize, maxEntries, flags)

    // Step 4. recreate the map if there are attribute changes
    if redo == true {
        ObjClose(fd)   // close FD of existing map
        goto recreate
    }
    return fd, isNewMap, err
}
```

逻辑如下：

如果映射不存在：通过调用 `fd = CreateMap()` 创建映射。
 如果映射已存在：调用 `objCheck()` 检查是否存在映射属性更改。如果存在更改，则会：

1. 删除现有映射，
2. 向调用者 `OpenOrCreateMap()` 返回 `hasChanged=true`，随后将创建映射（删除 + 创建 = 重新创建）。

```
// pkg/bpf/bpf_linux.go

func objCheck(fd, path, mapType, keySize, valueSize, maxEntries, flags uint32) bool {
    info := GetMapInfo(os.Getpid(), fd)
    mismatch := false

    if info.MapType != mapType || info.KeySize != keySize ||
        info.ValueSize != valueSize || info.MaxEntries != maxEntries || info.Flags != flags {
        Warn("XX mismatch for BPF map")
        mismatch = true
    }

    if mismatch {
        if info.MapType == MapTypeProgArray {
            return false
        }

        Warning("Removing map to allow for property upgrade (expect map data loss)")

        os.Remove(path) // Kernel still holds map reference count via attached prog.
        return true     // Only exception is prog array, but that is already resolved differently.
    }

    return false
}
```

## 3.6 The final creation: `CreateMap() -> unix.SysCall()`

```
// pkg/bpf/bpf_linux.go

// When mapType is the type HASH_OF_MAPS an innerID is required to point at a
// map fd which has the same type/keySize/valueSize/maxEntries as expected map
// entries. For all other mapTypes innerID is ignored and should be zeroed.
func CreateMap(mapType, keySize, valueSize, maxEntries, flags, innerID, path) (int, error) {
    uba := struct {
        mapType    uint32
        keySize    uint32
        valueSize  uint32
        maxEntries uint32
        mapFlags   uint32
        innerID    uint32
    }{ uint32(mapType), keySize, valueSize, maxEntries, flags, innerID }

    unix.Syscall(unix.SYS_BPF, BPF_MAP_CREATE, uintptr(unsafe.Pointer(&uba)), unsafe.Sizeof(uba))

    runtime.KeepAlive(&uba)
    return int(ret), nil
}
```

# 4 Back to the functionality test

## 4.1 Agent logs on BPF removing

首先，我们可以从第3.5节的代码中看到，当映射属性发生更改时，代理会删除旧的映射并创建一个新的映射，同时记录一条警告日志，因为在此过程中旧的数据会被删除：

## 4.2 Check CT entries during agent restart

We could also check the CT table contents during each step in Section 2.2:

### After connection established

```
$ cilium bpf ct list global 2>&1 | grep 192.168.64.195 | grep TCP
TCP IN 10.5.224.91:40356 -> 192.168.64.195:6379 expires=3295721 RxPackets=14 RxBytes=983 ...
```

CT entry **created**.

### After configuration changed and agent restarted

```
$ cilium bpf ct list global 2>&1 | grep 192.168.64.195 | grep TCP
# nothing found
```

CT entry **disappeared**.

### After we’ve sent some data

```
$ cilium bpf ct list global 2>&1 | grep 192.168.64.195 | grep TCP
TCP IN 10.5.224.91:40356 -> 192.168.64.195:6379 expires=3295750 RxPackets=2 RxBytes=140 RxFlagsSeen=0x02 ...
```

**连接跟踪（CT）条目“重新出现”**，但请注意，所有统计信息（例如接收的数据包数RxPackets、接收的字节数RxBytes）已被重置。原因是，正如代码所示，在重新创建映射时，不会转储现有数据。

# 5 Conclusion and future work

根据我们的测试，当更改连接跟踪（CT）表的大小时，现有的CT条目会被清空，但现有的连接不会中断。

需要进一步深入研究代码以解释原因。后续可能会更新相关内容。