---
title: (转+译)Cilium Code Walk Through 5 - probe
date: 2025-02-27
update: 2025-02-28
comment: false
tags:
  - Cilium
categories:
  - Cilium
---

Cilium 需要掌握Node之间的拓扑关系，这依赖于每个node进行探测

*<!--more-->*

# Node 之间的健康探测（health probe）机制

![img](https://myblog-1307634347.cos.ap-guangzhou.myqcloud.com/blog/entire-call-stack.png)

# 调用栈：

```
startDaemon -> d.initHealth
|- health.Launch
|- pidfile.Remove(pidfilePath)
|- UpdateController()
|  |- health.LaunchAsEndpoint
|  |- RunInterval: controllerInterval
```

# 1 设计

## 1.1 Full-mesh 健康探测

在 Cilium 的设计中，**每个 node 都可以主动探测（probe）其他 node 的健康状态**， 这样它们就能拿到第一手的全局健康状态信息（global health status of all nodes）。

默认情况下，**任何两个 node 之间都会互相 probe**，因此最终形成一张 full-mesh probe 网络，如下图所示：

![img](https://myblog-1307634347.cos.ap-guangzhou.myqcloud.com/blog/full-mesh.png)

Probe 行为由 cilium-agent 的两个开关控制，默认都是开的，

1. `enable-health-checking`：probe **其他 node**的健康状态。
2. `enable-endpoint-health-checking`：probe **其他 node 上的 `cilium-health-ep`** 的健康状态。稍后会介绍 `cilium-health-ep` 是什么。

## 1.2 四种 probe 类型

从网络层级的角度，probe 分两个维度：

1. 三层（L3）探测：`ping`（ICMP）
2. 七层（L7）探测：`GET` API。

再结合以上两个开关，总共就有**四种 probe**：

1. `enable-health-checking=true`：
   1. ICMP probe (L3)：`ping <NodeIP>`
   2. HTTP probe (L7)：`GET http://<NodeIP>:4240/hello`
2. `enable-endpoint-health-checking=true`：
   1. ICMP probe (L3)：`ping <HealthIP>`
   2. HTTP probe (L7)：`GET http://<HealthIP>:4240/hello`

## 1.3 Probe results

Probe 结果会缓存到 cilium-agent 中，可以通过下面命令查看（`#` 开头的注释是后加的）：

```
(node1) $ cilium-health status
Probe time:   2020-12-29T15:17:02Z
Nodes:
  cluster1/node1 (localhost):
    Host connectivity to 10.5.6.60:        # <-- NodeIP
      ICMP to stack:   OK, RTT=9.557967ms
      HTTP to agent:   OK, RTT=405.072µs
    Endpoint connectivity to 10.6.2.213:   # <-- HealthIP
      ICMP to stack:   OK, RTT=9.951333ms
      HTTP to agent:   OK, RTT=468.645µs
  cluster1/node2:
    ...
  cluster2/node100:
    Host connectivity to 10.6.6.100:        # <-- NodeIP
      ICMP to stack:   OK, RTT=10.164048ms
      HTTP to agent:   OK, RTT=694.196µs
    Endpoint connectivity to 10.22.1.3:     # <-- HealthIP
      ICMP to stack:   OK, RTT=11.282117ms
      HTTP to agent:   OK, RTT=765.092µs
```

如果[启用了 clustermesh](https://arthurchiao.art/blog/cilium-clustermesh/)，那 **cilium-agent 也会对其他集群的 node 进行探测**，所以我们看到上面的输出中有其他集群的 node 信息。

## 1.4 `cilium-health-ep`: cilium-health endpoint

简单来说，cilium-agent 会为每个 Pod 创建一个它所谓的 Endpoint 对象。而在这里， `cilium-health-ep` 是个**特殊的 endpoint**：

它并不是一个 Pod，但可以看到，它有自己独立的

1. Endpoint ID：随机分配，每台节点内唯一。
2. Identity：**reserved identity**，固定值 4，也就是说**每台节点上的 cilium-health identity 都是 4**。
3. IP address：cilium-agent 随机分配。
4. Veth pair：`lxc_health@<peer>`

# 2 实现

![img](https://myblog-1307634347.cos.ap-guangzhou.myqcloud.com/blog/init-highlevel.png)

大致步骤：

1. 调用 `initHealth()` 完成 prober 的初始化工作，**大部分工作都在这里面完成**。
   1. 初始化 prober，**顺序对其他所有 node 执行 probe**。
   2. **创建 `cilium-health-ep`，这一步不依赖上面 probe 的结果**，二者是独立进行的。
2. 注册 cilium-agent `/healthz` API 并开始提供服务。
   - 这个 API 用于**检测 cilium-agent 是否正常**。
   - **`cilium status --brief` 返回的就是这个 API 的结果**。

## 2.2 `initHealth() -> Launch() -> runServer() -> server.Serve()`

`initHealth()` 做的事情：

1. 调用 `health.Launch()`，后者
   1. 初始化 `ch.server`
   2. 初始化 `ch.client`
   3. `go ch.runServer()`，**接下来的大部分逻辑，都在这里面**。
2. 清理之前的 cilium-health pid 文件（`/var/run/cilium/state/health-endpoint.pid`）
3. 创建一个名为 `cilium-health-ep` 的 controller（定时任务），这里面会
   1. 创建 `cilium-health` endpoint，
   2. 定期将该 `cilium-health` endpoint 状态同步到 K8s。

接下来看 `go ch.runServer()`。

## 2.3 `runServer()`

![img](https://myblog-1307634347.cos.ap-guangzhou.myqcloud.com/blog/runServer.png)

逻辑：

1. **等待 cilium-agent 启动成功**（`GET /healthz` 返回成功），然后转步骤 2
2. 删除之前的 `/var/run/cilium/health.sock` 文件。**本地执行 `cilium-health` 命令时会用到这个 socket 文件**。
3. `go ch.server.Serve()`：**创建一个 goroutine，在里面启动 cilium-health API server**，主逻辑在这里面，包括：
   1. 创建 TCP servers
   2. 运行 `runActiveServices()`，这里面会创建 prober 和 unix servers，其中 unix server 在 `Listen()` 时会**创建新的 `health.sock` 文件**。
4. 等待，直到新的 `health.sock` 文件 ready，然后给其设置合适的文件权限
5. 以 `statusProbeInterval` 的间隔，定时向 cilium-agent 发起 `GET /healthz`，并将结果保存

```
// pkg/health/server/server.go

// Serve spins up the following goroutines:
// * TCP API Server: Responders to the health API "/hello" message, one per path
// * Prober: Periodically run pings across the cluster, update server's connectivity status cache.
// * Unix API Server: Handle all health API requests over a unix socket.
func (s *Server) Serve() (err error) {
    for i := range s.tcpServers {
        srv := s.tcpServers[i]
        go func() {
            errors <- srv.Serve()
        }()
    }

    go func() {
        errors <- s.runActiveServices()
    }()

    err = <-errors // Block for the first error, then return.
    return err
}
```

## 2.4 `runActiveServices()`

![img](https://myblog-1307634347.cos.ap-guangzhou.myqcloud.com/blog/runActiveServices.png)

主要步骤：

1. 执行 `FetchStatusResponse()`，这会用一个三层 for 循环对所有 node 顺序进行 probe；
2. 设置 prober `OnIdle()` handler，然后启动 `prober.RunLoop()`，定期更新 node 集 合；
3. 执行 `s.Server.Seve()`，开始接收 Unix、HTTP、HTTPS 请求。

注意其中的第一步，

1. 对所有 node 的 probe 操作是顺序进行的。
2. 每次 probe 如果不通，需要过 `30s` 超时退出。

因此，**如果有大量 node 不通，这里就会花费大量时间**，导致后面的 UNIX server 迟 迟无法启动，具体表现就是宿主机执行 `cilium-health` 命令报以下错误：

```
cilium-health status
Error: Cannot get status: Get "http://%2Fvar%2Frun%2Fcilium%2Fhealth.sock/v1beta/status": dial unix /var/run/cilium/health.sock: connect: no such file or directory
```

因为这个文件是在第三步 `s.Server.Serve() -> Listen()` 里面才创建的。

```
// pkg/health/server/server.go

// Run services that are actively probing other hosts and endpoints over ICMP and HTTP,
// and hosting the health admin API on a local Unix socket.
func (s *Server) runActiveServices() error {
    s.FetchStatusResponse()

    nodesAdded, _, _ := s.getNodes()
    prober := newProber(s, nodesAdded)
    prober.OnIdle = func() {
        // Fetch results and update set of nodes to probe every ProbeInterval
        s.updateCluster(prober.getResults())

        if nodesAdded, nodesRemoved, err := s.getNodes(); err != nil {
            log.WithError(err).Error("unable to get cluster nodes")
        } else {
            prober.setNodes(nodesAdded, nodesRemoved)
        }
    }
    prober.RunLoop()

    return s.Server.Serve()
}
```

最后一行 `s.Server.Serve()` 调用到下面这里：

```
// api/v1/server/server.go

// Serve the api
func (s *Server) Serve() (err error) {
    if !s.hasListeners
        s.Listen() // net.Listen(s.SocketPath) -> create sock file

    if s.handler == nil // set default handler, if none is set
        s.SetHandler(s.api.Serve(nil))

    if s.hasScheme(schemeUnix) { // "Serving cilium at unix://%s", s.SocketPath
        go func(l net.Listener) {
            domainSocket.Serve(l)
        }(s.domainSocketL)
    }

    if s.hasScheme(schemeHTTP) {
        ...
    }
    if s.hasScheme(schemeHTTPS) {
      ...
    }

    return nil
}
```



## 2.5 创建 `cilium-health-ep`

![img](https://myblog-1307634347.cos.ap-guangzhou.myqcloud.com/blog/launch-cilium-health-ep.png)

`cilium-health-ep` 也是一个 Endpoint，因此会经历：

1. 分配 IP
2. 创建 netns
3. 创建 veth pair（`lxc_health`）
4. 创建 Endpoint
5. 分配 Identity：注意 **Cilium 里面都是先创建 Endpoint，再为 Endpoint 分配 Identity**
6. Regenerate BPF

等等过程，代码见 cilium-health/launch/endpoint.go。