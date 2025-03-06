Ref: https://www.cnxct.com/how-does-cilium-use-ebpf-with-go-and-c/

# 代码结构

bpf目录下有很多eBPF实现的源码，文件列表如下

1. bpf_alignchecker.c C与Go的消息结构体格式校验
2. bpf_host.c 物理层的网卡tc ingress\egress相关过滤器
3. bpf_lxc.c 容器上的网络环境、网络流量管控等
4. bpf_network.c 网络控制相关
5. bpf_overlay.c 叠加网络控制代码
6. bpf_sock.c sock控制相关，包含流量大小控制、TCP状态变化控制
7. bpf_xdp.c XDP层控制相关
8. sockops 目录下有多个文件，用于sockops相关控制，流量重定向等性能优化。
9. cilium-probe-kernel-hz.c probe测试的，忽略

# cilium的eBPF场景应用

Cilium使用上面几个Hook与几个接口功能相结合,创建了以下几个网络对象。

1. 虚拟接口(cilium_host、cilium_net)
2. 可选接口(cilium_vxlan)
3. linux内核加密支持
4. 用户空间代理(Envoy)
5. eBPF Hooks

#### 预过滤器 prefilter

XDP层实现的网络流量过滤过滤器规则。比如，由Cilium agent提供的一组CIDR映射用于查找定位、处理丢弃等。

#### endpoint策略

Cilium endpoint来继承实现。使用映射查找与身份和策略相关的数据包，该层可以很好地扩展到许多端点。根据策略，该层可能会丢弃数据包、转发到本地端点、转发到服务对象或转发到 L7 策略对象以获取进一步的L7规则。这是Cilium数据路径中的主要对象，负责将数据包映射到身份并执行L3和L4策略。

#### Service

TC栈上的HOOK，用于L3/L4层的网络负载均衡功能。

#### L3 加密器

L3层处理IPsec头的流量加密解密等。

#### Socket Layer Enforcement

socket层的两个钩子，即sockops hook和socket send/recv hook。用来监视管理Cilium endpoint关联的所有TCP套接字，包括任何L7代理。

#### L7 策略

L7策略对象将代理流量重定向到Cilium用户空间代理实例。使用Envoy实例作为其用户空间代理。然后，根据配置的L7策略转发流量。

如上组件是Cilium实现的灵活高效的 datapath。下图展示端点到端点的进出口网络流量经过的链路，以及涉及的cilium相关网络对象。

![cilium的Datapath图](https://www.cnxct.com/tools/cilium_bpf_endpoint.svg)

### 总结

综合C的代码，从数据流向来看，分为两类

1. 用户态向内核态发送控制指令、数据
2. 内核态向用户态发送数据

第一部分，cilium调用类bpftool工具来进行eBPF字节码注入。（具体实现的方式，go代码分析时会讲到）； LB部分，会直接向map写入数据内容。(lb.h)
第二部分是内核向用户态发送数据，而数据内容几乎都是其他eBPF的运行日志。尤其是`dbg.h`里定义的`cilium_dbg*` 方法，实现了`skb_event_output()`和`xdp_event_output()`两种函数输出，来代替`trace_printk()`函数，方便用户快速读取日志。两种函数对应的事件输出都是用了`perf buf`类型的map来实现，对应go代码里做了详细的实现，抽象的非常好，后面笔者会重点介绍。

# 源码分析

initMaps函数中初始化了cilium的所有eBPF map，功能包括xdp、ct等网络对象处理。
eBPF maps作用博主rexrock在文章 `https://rexrock.github.io/post/cilium2/`中做个直观的图，见

![img](https://image.cnxct.com/2021/12/post-2408-61b1c9fe40471.png)

### eBPF代码编译

```
err = d.init() //跳转到285行的init函数 
// Remove any old sockops and re-enable with _new_ programs if flag is set sockops.SockmapDisable() 
sockops.SkmsgDisable()
```

对新老map进行删除、替换。

在237行进行datapath的重新初始化加载。

```golang
if err := d.Datapath().Loader().Reinitialize(d.ctx, d, d.mtuConfig.GetDeviceMTU(), d.Datapath(), d.l7Proxy); err != nil {
```

#### datapath初始化ebpf环境

`Reinitialize`函数是抽象的interface的函数

该函数前半部分对启动参数进行整理汇总。

```
prog := filepath.Join(option.Config.BpfDir, "init.sh")
cmd := exec.CommandContext(ctx, prog, args...)
cmd.Env = bpf.Environment()
if _, err := cmd.CombinedOutput(log, true); err != nil {
    return err
}
```

是的，你没看错，调用了外部的shell命令进行ebpf代码编译。对应文件是`bpf/init.sh`，这个shell里会进行编译ebpf文件。

比如：`bpf_compile bpf_alignchecker.c bpf_alignchecker.o obj ""` ，生成eBPF字节码.o文件。后面将用于校验C跟GO的结构体对齐情况。
`bpf_compile`也是封装的`clang`的编译函数，依旧使用llvm\llc编译链接eBPF字节码文件。

### eBPF字节码加载

同样`bpf/init.sh`也会对`bpf/*.c`进行编译，再调用`tc`等命令，对编译生成的eBPF字节码进行加载。

其次，go代码里也有加载的地方，见`pkg/datapath/loader/netlink.go`的`replaceDatapath`函数内91行使用`ip` 或`tc` 命令对字节码文件进行加载，使内核加载新的字节码。完成新老字节码的注入替换。

#### C跟go结构体格式校验

430行，使用go代码，验证C跟G结构体对齐情况。

```
alignchecker.CheckStructAlignments(defaults.AlignCheckerName)
```

在pkg/alignchecker/alignchecker.go里，CheckStructAlignments函数会读取.o的eBPF字节码文件，按照elf格式进行解析，并获取DWARF段信息，查找`.debug_*`段或者`.zdebug_`段信息。
getStructInfosFromDWARF函数会按照elf里段内结构体名字与被检测结构体名字进行对比，验证类型，长度等等。

### ebpf编译加载的其他方式

在`pkg/datapath/loader/base.go`210行左右`reinitializeXDPLocked`函数
调用`compileAndLoadXDPProg`函数进行ebpf字节码编译与加载。

```
// compileAndLoadXDPProg compiles bpf_xdp.c for the given XDP device and loads it.
func compileAndLoadXDPProg(ctx context.Context, xdpDev, xdpMode string, extraCArgs []string) error {
    args, err := xdpCompileArgs(xdpDev, extraCArgs)
    if err != nil {
        return fmt.Errorf("failed to derive XDP compile extra args: %w", err)
    }

    if err := compile(ctx, prog, dirs); err != nil {
        return err
    }
    if err := ctx.Err(); err != nil {
        return err
    }

    objPath := path.Join(dirs.Output, prog.Output)
    return replaceDatapath(ctx, xdpDev, objPath, symbolFromHostNetdevEp, "", true, xdpMode)
}
```

函数中，先进行参数重组，在调用`pkg/datapath/loader/compile.go`的compile函数进行编译。该函数依旧是调用了`clang`进行编译。

### go源码分析总结

1. 编译：直接或间接调用clang/llc命令进行编译链接。
2. 加载：调用外部bpftool\tc\ss\ip等命令加载。
3. MAP管理：调用外部命令或go cilium/ebpf库进行map删除、创建等
4. CORE兼容：会在每个endpoint上编译，没有使用eBPF CORE。
5. 更新：每次重新加载都会编译。

# 内核态与用户态数据交互

## 交互map

| 名字                    | 类型                          | 所属文件      | 数据流向 | 备注                                                      |
| :---------------------- | :---------------------------- | :------------ | :------- | :-------------------------------------------------------- |
| SIGNAL_MAP              | BPF_MAP_TYPE_PERF_EVENT_ARRAY | signal.h      | ？       |                                                           |
| LB4_REVERSE_NAT_SK_MAP  | BPF_MAP_TYPE_LRU_HASH         | bpf_sock.c    | ?        |                                                           |
| LB6_REVERSE_NAT_SK_MAP  | BPF_MAP_TYPE_LRU_HASH         | bpf_sock.c    | ?        |                                                           |
| CIDR4_HMAP_NAME         | BPF_MAP_TYPE_HASH             | bpf_xdp.c     | ?        |                                                           |
| CIDR4_LMAP_NAME         | BPF_MAP_TYPE_LPM_TRIE         | bpf_xdp.c     |          |                                                           |
| CIDR6_HMAP_NAME         | BPF_MAP_TYPE_HASH             | bpf_xdp.c     |          |                                                           |
| CIDR6_LMAP_NAME         | BPF_MAP_TYPE_LPM_TRIE         | bpf_xdp.c     |          |                                                           |
| bytecount_map           | BPF_MAP_TYPE_HASH             | bytecount.h   |          |                                                           |
| cilium_xdp_scratch      | BPF_MAP_TYPE_PERCPU_ARRAY     | xdp.h         |          |                                                           |
| EVENTS_MAP              | BPF_MAP_TYPE_PERF_EVENT_ARRAY | event.h       |          |                                                           |
| IPV4_FRAG_DATAGRAMS_MAP | BPF_MAP_TYPE_LRU_HASH         | ipv4.h        |          |                                                           |
| LB6_REVERSE_NAT_MAP     | BPF_MAP_TYPE_HASH             | lb.h          |          |                                                           |
| LB6_SERVICES_MAP_V2     | BPF_MAP_TYPE_HASH             | lb.h          |          |                                                           |
| ENDPOINTS_MAP           | BPF_MAP_TYPE_HASH             | maps.h        |          |                                                           |
| METRICS_MAP             | BPF_MAP_TYPE_PERCPU_HASH      | maps.h        |          |                                                           |
| POLICY_CALL_MAP         | BPF_MAP_TYPE_PROG_ARRAY       |               |          |                                                           |
| THROTTLE_MAP            | BPF_MAP_TYPE_HASH             |               |          |                                                           |
| EP_POLICY_MAP           | BPF_MAP_TYPE_HASH_OF_MAPS     | maps.h        | ?        | Map to link endpoint id to per endpoint cilium_policy map |
| POLICY_MAP              | BPF_MAP_TYPE_HASH             | maps.h        | ?        | Per-endpoint policy enforcement map                       |
| EVENTS_MAP              | BPF_MAP_TYPE_SOCKHASH         | bpf_sockops.h | ?        |                                                           |

太多了，而且比较偏向cilium的业务功能，偏离本文主题，不写了。后面会按照数据流向分三类，总结说明。

## map作用分类

### 内核态自用

常用与程序内部的临时缓存。比如`__section("cgroup/connect4")`时，TCP socket的状态每次变化，都需要将之前endpoint信息存储起来，下次状态变化时，再读取更改。 举个例子