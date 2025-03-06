Kubernetes提供了两种方式来将Kubernetes内部的服务暴露到外部

Ingress：用于通过应用层暴露服务

LoadBalancer：用于通过传输层暴露服务

本文探讨了后一种模型的设计思路

# 1 问题描述

假设您在 Kubernetes 集群内部部署了多个 DNS 服务器（Pods），旨在为公司范围内提供 DNS 服务。现在的问题是：您的传统应用程序（例如运行在裸金属或虚拟机中）或其他 Kubernetes 集群中的应用程序，如何访问这些 DNS 服务？如图 1.1 所示

![img](/Users/hanguobiao/Nutstore Files/读书笔记/cilium/L4LB for Kubernetes.assets/exposing-dns-service.png)

- DNS 服务通过 UDP（或 TCP）的 53 端口提供（因此属于第 4 层）。
- DNS Pod 是无状态的，这里的“无状态”意味着所有实例都是相同且活跃的，而不是主备模式或主从模式。

# 2 需求分析

## 2.1 L4LB Model


乍一看，似乎可以使用经典的第 4 层负载均衡器（L4LB）模型来解决这个问题，即：

1. 为 DNS 集群分配一个虚拟 IP（VIP），所有客户端通过 VIP 访问服务。
2. 使用负载均衡算法将来自 VIP 的流量转发到特定的后端。

![img](/Users/hanguobiao/Nutstore Files/读书笔记/cilium/L4LB for Kubernetes.assets/classic-l4lb.png)

## 2.2 特殊考虑

这个方向是对的，但是还缺少一些重要的考虑因素

首先，后端（Kubernetes Pod）是非常动态的，经常会发生变化。各种故障和调度可能会触发Kubernetes终止或者重新调度Pod。

其次，Pod的IP并非固定不变的。想比之下，传统的L4LB更倾向于使用固定IP的后端，它们只是根据健康检查状态来添加或移除现有的后端

第三，后端可能会根据容量计划进行扩展或减缩，这些后端的变化应该及时反映到L4LB上，并且对用户/客户端来说是透明的，无需人工干预（某种形式的服务发现）

这使得L4LB扮演了一个非常独特的角色：

一方面，必须能够从外部访问

另一方面，又属于Kubernetes集群的一部分--它必须监听Kubernetes资源的变化，以便更新其转发规则

### 2.3 技术需求总结

# 3 L4LB解决方案

本文假设底层物理网络采用 Spine-Leaf 架构（本文中物理网络拓扑仅影响 ECMP 的实现）。

## 0 Spine-Leaf 架构

![img](/Users/hanguobiao/Nutstore Files/读书笔记/cilium/L4LB for Kubernetes.assets/l4lb-topo.png)

整体设计如图 3.1 所示：

1. 将若干节点专用于 L4LB（第 4 层负载均衡）节点。
2. 在每个 L4LB 节点上运行一个 BGP 代理，向数据中心网络宣告特定的 CIDR，例如 `10.1.0.0/24`。该 CIDR 中的 IP 将用作 VIP（虚拟 IP），在 Kubernetes 中也被称为 ExternalIP。
3. 在每个 L4LB 节点上运行一个 Cilium 代理，监听 Kubernetes 资源（尤其是带有 ExternalIP 的 Service），并生成 BPF 规则以将数据包转发到后端 Pod。
4. 通过在每个 L4LB 节点的内核中配置一个虚拟设备（dummy device），将 VIP CIDR 和 Cilium 代理连接起来。
5. 在物理网络上启用 ECMP（等价多路径路由）。

从外部访问示例服务时的流量路径如下：

![img](/Users/hanguobiao/Nutstore Files/读书笔记/cilium/L4LB for Kubernetes.assets/l4lb-traffic-path.png)

图中标注的四个步骤如下：

1. **客户端数据包 -> 物理网络（Spine 层）**
2. **Spine 层 -> L4LB 节点，通过 ECMP（等价多路径路由）**
3. **内核路由（粘合层）**
4. **L4LB -> 后端 Pod，通过 Cilium 进行负载均衡**

以下将详细解释这些步骤。我们来看看这种设计如何满足第 2.3 节中列出的四项需求。

### 3.1 BIRD - BGP 代理

L4LB 节点运行 BIRD 作为 BGP 代理。

当 BIRD 向数据中心网络宣告一个 CIDR（例如 `10.1.0.0/24`）时，所有目标 IP 在此 CIDR 范围内的数据包（例如 `10.1.0.2`）都会被路由到该节点。

如果不熟悉 BGP 宣告，可以简单地将其理解为向物理网络广播类似“CIDR `10.1.0.0/24` 位于主机 XXX”的消息。路由器收到此消息后，会将其安装到它们的路由表中。

这解决了第一个需求：持久/不变的（第 4 层）入口点。

### 3.2 Cilium - 网络代理

L4LB 节点上的 `cilium-agent` 会监听 Kubernetes API Server，并为 Kubernetes 的 ExternalIP 服务生成 BPF 规则，将流量从 VIP（由 L4LB 节点持有）转发到后端 Pod。

这解决了第二个和第三个需求：负载均衡以及对后端变化的及时响应。

### 3.3 ECMP - 物理链路高可用

启用 ECMP（等价多路径路由）后，我们可以让多个 L4LB 节点宣告相同的 CIDR，硬件路由器会将这些数据包负载均衡到我们的 L4LB 节点（如图 3.1 和图 3.2 中的发光链路所示）。

此外，还有一种称为双向转发检测（BFD）的 BGP 优化选项，在路由器和 BIRD 之间启用它可以加速整个网络内的路由收敛。

因此，我们解决了第四个需求：高可用性。

### 3.4 内核粘合处理

到目前为止，目标 IP 在 CIDR（VIP）范围内的数据包将到达我们的 L4LB 节点，`cilium-agent` 会为这些 VIP 生成转发规则。

但还有一个部分缺失：内核中没有规则将这些数据包重定向到 `cilium-agent` 的处理范围内。因此，如果没有额外的工作，这些数据包会在内核中被丢弃，而不是通过 Cilium 的 BPF 规则转发到后端，如图 3.3 所示。

![img](/Users/hanguobiao/Nutstore Files/读书笔记/cilium/L4LB for Kubernetes.assets/no-dummy.png)

因此，我们需要一些粘合工作来填补这一空白。我们的解决方案是创建一个虚拟设备（dummy device），该设备持有我们 CIDR 范围内的第一个 IP 地址。

![img](/Users/hanguobiao/Nutstore Files/读书笔记/cilium/L4LB for Kubernetes.assets/add-dummy.png)

# 4 Configurations

System info:

1. Centos: `7.2`
2. Kernel: `4.18+`
3. BIRD: `2.x`
4. Cilium: `1.7+`

Beside, this post assume the Kubernetes cluster uses **direct routing** for Pod networking. (While adjust Cilium configurations will also make this scheme work for non-direct-routing cases, that’s beyond the scope of this post).

## 4.1 Create and configure dummy device

Install:

```
$ modprobe --ignore-install dummy
$ ip link set name cilium-ext0 dev dummy0
```

Configure it to survive host reboot:

```
$ cat ifcfg-cilium-ext0
DEVICE=cilium-ext0
IPADDR=10.1.0.1
NETMASK=255.255.255.0
ONBOOT=yes
TYPE=Ethernet
NM_CONTROLLED=no

$ cat ./modprobe.d/dummy.conf
install dummy /sbin/modprobe --ignore-install dummy; ip link set name cilium-ext0 dev dummy0

$ cat ./modules-load.d/dummy.conf
# Load dummy.ko at boot
dummy

$ cp ifcfg-cilium-ext0          /etc/sysconfig/network-scripts/
$ cp modprobe.d/dummy.conf      /etc/modprobe.d/dummy.conf
$ cp modules-load.d/dummy.conf  /etc/modules-load.d/dummy.conf
```

Enable changes:

```
$ systemctl restart network

$ ifconfig cilium-ext0
cilium-ext0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
              inet 10.1.0.1  netmask 255.255.255.0  broadcast 10.1.0.255
              ...

$ route -n
Kernel IP routing table
Destination     Gateway     Genmask         Flags Metric Ref    Use Iface
...
10.1.0.1        0.0.0.0     255.255.255.0   U     0      0        0 cilium-ext0
```

## 4.2 bird

This involves BGP configurations for the `bird` software, as well as HW routers. Configurations may vary a lot according to the BGP schemes you choose, the latter is beyond the scope of this post. Refer to some get started docs, such as the one we wrote: [Cilium documentation: Using BIRD to run BGP](https://docs.cilium.io/en/stable/gettingstarted/bird/).

For `bird`, add following configurations to `/etc/bird.conf`,

```
protocol static {
        ipv4;                   # Again, IPv4 channel with default options
        ...
        route 10.1.0.0/24 via "cilium-ext0";
}
```

Restart bird and verify changes are applied:

```
$ systemctl restart bird

$ birdc show route
BIRD 2.0.5 ready.
Table master4:
...
10.1.0.0/24         unicast [static1 2020-03-18] * (200)
     dev cilium-ext0
```

## 4.3 cilium-agent

Normal installation according official documents, as long as the agent could listen to kubernetes apiserver.

Two kinds of load balancing mechanisms:

### 4.3.1 NAT: to be specific, SNAT

Configurations:

- `kube-proxy-replacement=probe`
- `node-port-mode=snat` (default)

![img](/Users/hanguobiao/Nutstore Files/读书笔记/cilium/L4LB for Kubernetes.assets/nat-path.png)

Fig. Traffic path in NAT mode

### 4.3.2 DSR: direct server return

Configurations:

- `kube-proxy-replacement=probe`
- `node-port-mode=dsr`

![img](/Users/hanguobiao/Nutstore Files/读书笔记/cilium/L4LB for Kubernetes.assets/dsr-path.png)

Fig. Traffic path in DSR mode

Note that if using DSR mode, **both L4LB and worker nodes** needs to be configured as **DSR**.

## 4.4 ECMP

ECMP needs to be configured on physical routers.

BFD should be configured both on physical routers and `bird`. Refer to [Cilium documentation: Using BIRD to run BGP](https://docs.cilium.io/en/stable/gettingstarted/bird/).

If everything is ok, you should see something like this on your routers:

```
ROUTER# show ip route 10.1.0.0
...
10.1.0.0/24, ubest/mbest: 2/0
    *via 10.4.1.7, [200/0], 13w6d, bgp-65418, internal, tag 65418
    *via 10.4.1.8, [200/0], 12w4d, bgp-65418, internal, tag 65418
```

## 4.5 Verification

For nothing but laziness, I will use my handy nginx service instead of deploying a real DNS service - but the effect is much the same, we will verify our scheme by accessing the nginx from layer 4.

### 4.5.1 On Master Node

On Kubernetes master, create a service with `externalIPs=10.1.0.2`:

```
$ cat cilium-smoke.yaml
apiVersion: v1
kind: Service
metadata:
  name: nginx
  labels:
    app: nginx
spec:
  externalIPs:
  - 10.1.0.2
  ports:
  - port: 80
    name: cilium-smoke
  selector:
    app: nginx
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: cilium-smoke
spec:
  serviceName: "nginx"
  replicas: 1
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - name: nginx
        image: library/nginx-slim:0.8
        ports:
        - containerPort: 80
          name: cilium-smoke

$ kubectl create -f cilium-smoke.yaml
```

Check our service’s information:

```
$ kubectl get svc
$ k get svc
NAME    TYPE           CLUSTER-IP   EXTERNAL-IP   PORT(S)  AGE
...
nginx   LoadBalancer   10.x.x.x     10.1.0.2      80/TCP   2m
```

As can be seen, it is `LoadBalancer` type, and has an external IP `10.1.0.2`.

### 4.5.2 On L4LB Node

Execute following command inside cilium-agent pod:

```
$ cilium service list
...

62   10.1.0.2:53    ExternalIPs    1 => 192.168.1.234:53
                                   2 => 192.168.2.172:53
```

> TODO: more BPF info on L4LB node.
>
> `iproute2` on my current L4LB node is too old, which prohibits my further investigation. You could refer to my previous post [Cilium Network Topology and Traffic Path on AWS](https://arthurchiao.art/blog/cilium-network-topology-on-aws/) if intersted.

### 4.5.3 On test node

On a node which is outside of Kubernetes cluster, test our externalIP service with VIP+Port:

```
$ telnet 10.1.0.2 80
Trying 10.1.0.2...
Connected to 10.1.0.2.
Escape character is '^]'.
```

Successful!

# 5. More Thoughts

## 5.1 Pros & Cons

### 5.1.1 Pros

- Simple, straight forward, ease of understanding
- Ease of management of ExternalIPs: manage CIDR instead of distinct IPs, less BGP announcements
- Ease of security rule managements for BGP filtering

### 5.1.2 Cons

- ECMP hard limits: 16 nodes.

- All traffic goes through L4LB nodes, make them the potential bottleneck (e.g. BW, CPU processing).

- No failover in case of L4LB node downs.

  Currently, if one L4LB node downs, traffic will be rehashed to other L4LB nodes by HW switches via ECMP. However, in the current implementation, all the these traffic will be disruppted as other L4LB nodes could not correctly handle this (no failover). Failover could be achieved with either of：

  1. [Session replication](https://devcentral.f5.com/s/articles/sessions-sessions-everywhere): sync connection/session info among all L4LB nodes, so if one node down, the connection could be handled by other nodes (almost) transparently. LVS supports this features as an experiment.
  2. [Consistent hashing](https://en.wikipedia.org/wiki/Consistent_hashing): another way to achieve failover, and **recent L4LB solutions favor this fashion**, e.g. Facebook Katran, Google Maglev, Github GLB. **Cilium currently (`v1.8.2`) lacks this feature**.

## 5.2 Decoupling of BGP agent and networking agent

It’s important to understand that, in this L4LB scheme, there are no couplings between BGP agent and host network agent, that is,

- You could transparently replace `bird` with another BGP agent, e.g. `quagga` (but you need to concern whether they support the features you would like, e.g. ECMP, BFD).
- You could also transparently replace `cilium-agent` with other networking agents for Kubernetes worker nodes, e.g. `kube-proxy`.

## 5.3 The Hidden CLOS Architecture

![img](/Users/hanguobiao/Nutstore Files/读书笔记/cilium/L4LB for Kubernetes.assets/l4lb-traffic-path-20250228160436261.png)

Fig. 3.2 Traffic path when accessing example service from outside of Kubernetes cluster

If think of each TOR pair and corresponding L4LB nodes as an integral entity, Fig 3.2 could be re-depicted as Fig 5.1:

![img](/Users/hanguobiao/Nutstore Files/读书笔记/cilium/L4LB for Kubernetes.assets/hidden-clos.png)

Fig. 5.1 The Hidden CLOS architecture

which is a [CLOS network](https://en.wikipedia.org/wiki/Clos_network).

Interesting!

## 5.4 Ingress vs LoadBalancer

Ingress provides persistent L7 entrypoints for accessing services inside Kubernetes cluster from outside world. For example,

- App A: `https://<ingress addr>/app-a/`
- App B: `https://<ingress addr>/app-b/`
- App C: `https://<ingress addr>/app-c/`

Have you wondered how to design an Ingress solution?

If your Ingress is deployed inside Kubernetes cluster, then **itself must have a persistent L4 entrypoint**, namely the `<ingress addr>` in the above example.

Combining the L4LB solution in this post and something like Istio Gateway, you will get a workable Ingress.

# 6. Similar Works

## 6.1 MetalLB

[MetalLB](https://metallb.universe.tf/) is similar with this in that it:

1. Announce VIP via BGP
2. Forward/load-balancing to backends with node agent

Difference from the one in this post:

1. BGP agent announces distinct IPs instead of CIDR
2. No dedicated L4LB nodes
3. Forward/load-balancing to backends via kube-proxy (recently supported Cilium)

Problem may faced: more BGP announcements, more routing entries, more difficult for filtering BGP announcements.

## 6.2 Katran

[Katran](https://github.com/facebookincubator/katran) is a general purpose L4LB from Facebook, also based on BGP + BPF.

## 6.3 Kube-proxy + BGP

As mentioned in 5.2, replace Cilium with kube-proxy could also achieve this goal. Differences including:

1. Forwarding rules on L4LB node will be based on iptables or LVS instead of BPF
2. Performance degrades (maybe)

# 7 Summary

This post analyzed the technical requirements of L4LB for Kubernetes clusters, and realized a simple one based on Cilium+BGP+ECMP.