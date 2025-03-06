# Cilium 对IPV6 的支持

纯IPv6网络的K8s集群不仅IPAM更加灵活，集群规模更大，而且可以解锁很多新的网络特性和eBPF特性，能更好满足数据密集型应用的需求

Cilium是作为一个纯IPv6容器网络项目启动的，因此Cilium自带了很多相比IPv4的优势，如扩展更好、地址空间充裕、无需NAT等

由于IPv6的生态还在路上，外部依赖短期内全部支持ipv6不现实，但是通过4/6转换就不影响Cilium先发数据内的集群和应用IPv6化，享受IPv6带来的性能和便利性。

IPv6-only K8s于IPv4对接是通过NAT64/NAT46。基于iptables/netfilter架构无法实现这个功能，可以基于eBPF架构实现（通过 **`bpf_skb_change_proto()`** 实现 4/6 转换。）

# 工作原理

![img](https://arthurchiao.art/assets/img/cilium-tomorrow-networking-data-plane/NAT46-NAT64-support-for-Load-Balancer.png)

- 右边：使用 Cilium 网络的 IPv6-only K8s 集群；
- 左下：集群外的 IPv4 服务；
- 左上：**承担 NAT46/64 功能的 Cilium L4LB 节点**；

思路：

- 通过 Cilium L4LB 节点做 NAT46/64 转换；

  将 IPv4 流量路由到数据中心的边缘节点（边界），经过转换之后再进入 IPv6 网络；反向是类似的。

- 具体工作在 tc BPF 或 XDP 层。

  通过 `bpf_skb_change_proto()` 完成 4/6 转换。

# 工作机制详解

## 集群入向（IPv4 -> IPv6-only）

### 方法一： 有状态NAT46网关

![img](https://arthurchiao.art/assets/img/cilium-tomorrow-networking-data-plane/nat46-gw-1.png)

这种模式下，NAT46 网关是有状态的，工作机制：

- 部署在边界上，是唯一的双栈组件；
- 将 IPv4 `VIP:port` 映射到 IPv6 `VIP:port`（exposed to public natively）；
- 只有 IPv4 流量需要经过 GW 这一跳；
- K8s 集群是干净的 IPv6-only 集群，node/pod IP 都是纯 IPv6；
- 基于 eBPF/XDP，高性能；

下面是通过 Service 实现的 NAT46 规则（也就是“状态”）：

![img](https://arthurchiao.art/assets/img/cilium-tomorrow-networking-data-plane/nat46-gw-2.png)

好处：

1. IPv4 `VIP:port` 到 K8s 集群的 IPv6 `VIP:port` 的映射，与后者完全解耦

2. 从 IPAM 角度考虑，无需特殊的 LoadBalancer Service；任何 public IPv6 prefix 都能按预期工作；

3. NAT46 GW 甚至还能通过 weighted Maglev 负载均衡算法，将请求转发到多个集群上；

   Maglev weights 在 Cilium 1.13 [合并](https://github.com/cilium/cilium/pull/18306)。

缺点：

1. 需要额外的控制平面来对 VIP -> VIP 映射通过 API 进行编程；
2. 客户端源 IP 信息在经过 GW 设备之后就丢失了；
3. GW 是有状态的，记录了 DNAT & SNAT 规则和状态。

### 方法二： 无状态NAT64网关

这种方式是通过 IPv6 协议原生的 IPv4/IPv6 地址映射实现的，因此无需控制平面下发 service 规则来实现 NAT46/64：

![img](https://arthurchiao.art/assets/img/cilium-tomorrow-networking-data-plane/nat46-stateless-gw-1.png)

转发规则：

![img](https://arthurchiao.art/assets/img/cilium-tomorrow-networking-data-plane/nat46-stateless-gw-2.png)

优点：

1. GW 高度可扩展，因为不需要在 GW 节点上保存状态（地址转换信息）；

2. 源地址不丢失，只要原来的地址映射到的是 `64:ff9b::/96` 范围，[RFC6052](https://www.rfc-editor.org/rfc/rfc6052#section-2.1)；

3. loadBalancerSourceRanges can restrict LB service access for external IPv4 clients。

   [K8s documentation on LB source ranges](https://kubernetes.io/docs/concepts/services-networking/_print/#aws-nlb-support)，Cilium 已经支持。

4. GW translation 是透明的，因此无需引入额外的控制平面；

缺点：

1. K8s 集群中的 LB IPAM pool 需要使用 `64:ff9b::/96` 网段；
2. LB 节点需要具体 IPv4 映射知识，能处理好正反转换。

## 集群出向（IPv6-only -> IPv4）

Google 的 [public DNS64](https://developers.google.com/speed/public-dns/docs/dns64) 服务

![img](https://arthurchiao.art/assets/img/cilium-tomorrow-networking-data-plane/ipv6-only-egress.png)

优点：

1. 高度可扩展 GW 作为转换节点，无状态；
2. 集群内 nodes/pods/GW 之间的流量都是纯 IPv6；

缺点：

1. IPAM 管理更复杂，因为 pods/nodes 需要 secondary `64:ff9b::/96` prefix 地址段；

   可以通过有状态 NAT64 GW 解决：Pods use their primary IPv6 address, and GW does NAT to its own IPv4 address.

# Ciliume + BIG TCP

## BIG TCP

设计目标

支持数据中心内单个socket达到100Gbps带宽

使用场景

大数据、AI、机器学习以及其他网络密集型应用

BIG TCP不是适应于大部分场景的通用场景，而是针对数据密集型应用的优化

技术原理

如果以MTU=1538的配置，要达到100Gbps带宽

需要每秒处理815万个包，每个包处理时间不能超过123ms

对于内核协议这个庞然大物来说，这个性能是无法达到的，一次cache miss就会导致性能急剧下降。降低pps会让这个目标变得容易，这就需要增大包长（packet length）