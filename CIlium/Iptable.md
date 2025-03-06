# 网络基础

![网卡内部结构示意图（来源：《网络是怎样连接的》）](https://gitlab.com/jwkljh/img2023/-/raw/main/2303/network-interface-concept-digram.png)

# Netfilter

![img](/Users/hanguobiao/Nutstore Files/读书笔记/untitled markdown.assets/netfilter-arch-mini.png)

Netfilter的作用机制是通过这5个钩子

- Prerouting：只要数据包从设备（如网卡）那里进入到协议栈，就会触发该钩子。当我们需要修改数据包的 “Destination IP” 时，会使用到它，即 Prerouting Hook 主要用于目标网络地址转换（DNAT，Destination NAT）。
- Forward：顾名思义，这里指代转发数据包。前面的 Prerouting Hook 并未经过 IP 路由（Linux 下可以使用 `ip route`或 `route -nv`查看路由表），所以不管数据包是不是发往本机的，全部都照单全收。但经过 IP 路由后，如果发现数据包不是发往本机，则会触发 Forward Hook 进行处理。此时，本机就相当于一个路由器，作为网络数据包的中转站，Forward Hook 的作用就是处理这些被转发的数据包，以此来保护其背后真正的“后端”机器。
- Input：经过 IP 路由后，如果发现数据包是发往本机的，则会触发本钩子。Input Hook 一般用来加工发往本机的数据包，当然也可以做数据过滤，从而保护本机的安全。
- Output：数据包送达到应用层处理后，会把结果送回请求端，在经过 IP 路由之前，会触发该钩子。Output Hook 一般用于加工本地进程输出的数据包，同时也可以限制本机的访问权限，比如发往 `www.example.org`的数据包都丢弃掉。
- Postrouting：数据出协议栈之前，都会触发该钩子，无论这个数据是转发的，还是经过本机进程处理过的。Postrouting Hook 一般用于源网络地址转换（SNAT，Source NAT）。

Netfilter的官方流程如下

![img](https://gitlab.com/jwkljh/img2023/-/raw/main/2303/netfilter-hooks.png)



前面提到，每个钩子处都可以注册回调函数，并且可以注册多个，所以会有优先级的概念，保证执行顺序。把这些回调函数串起来，就构成了一条链，我们将其称为**回调链**（Chained Callbacks）。虽说 Netfilter 框架就是一套简单的事件回调机制，但它却是整个 Linux 网络大厦的基石，包括地址转换、封包处理、地址伪装、基于协议的连接跟踪、数据包过滤、透明代理、带宽限速以及访问控制等，都是在 Netfilter 基础上实现的。

由于要注册回调函数，而且还位于内核层面，这对日常系统运维来说很不友好。iptable是针对于Netfilter的开发框架。 iptables 中内置的行为：

- **ACCEPT**：允许数据包通过，继续执行后续的规则；
- **DROP**：丢弃数据包；
- **RETURN**：跳出当前规则链，继续执行前一个调用链（即调用当前链的链）的后续规则；
- **AUDIT**：对命中规则的数据包创建审计记录，主要用在允许、丢弃和拒绝三种规则的数据包上；
- **LOG**：内核对数据包进行日志记录；
- **DNAT**：修改数据包的目标网络地址；
- **SNAT**：修改数据包的源网络地址；
- **RATEEST**：流量速率估算器；
- **REDIRECT**：在本机上做端口映射，比如将 80 端口映射到 8080，访问 80 端口的数据包将会重定向到 8080 端口对应的监听服务；
- **REJECT**：功能与 **DROP** 类似，只不过它会通过 ICMP 协议给发送端返回错误信息，比如 `Destination network unreachable`，`Destination host unreachable`等，默认返回 `Destination port unreachable`；
- **TOS**：设置 IP 头部的 TOS 字段，即 Type of Service；
- **MASQUERADE**：地址伪装，可以理解为动态的 SNAT。通过它可以将源地址绑定到某个网卡上，因为这个网卡的 IP 可能是动态变化的，此时用 SNAT 就不好实现；



Netfilter 中内置了 5 张表，与前面的 5 条链相互组合，便有了“**5 表 5 链**”的叫法，这 5 张表分别是：

- raw 表：配置该表主要用于去除数据包上的连接追踪机制。默认情况下，连接会被跟踪，所以配置该表后，可以加速数据包穿越防火墙，提高性能。

  > This table is used mainly for configuring exemptions from [connection tracking](https://en.wikipedia.org/wiki/Netfilter#Connection_tracking) in combination with the NOTRACK target.
  > One of the important features built on top of the Netfilter framework is connection tracking.Connection tracking allows the kernel to keep track of all logical network connections or sessions, and thereby relate all of the packets which may make up that connection. NAT relies on this information to translate all related packets in the same way, and iptables can use this information to act as a stateful firewall.

- mangle 表：修改数据包内容，常用于数据包报文头的修改，比如服务类型（Type of Service, ToS），生存周期（Time to Live, TTL），Mark 标记等。

  > This table is used for specialized packet alteration.

- nat 表：用于修改数据包的源地址或目标地址，可以将其理解为一个 IP 分享器，但要更强大。

- filter 表：数据包过滤，控制到达某条链上的数据包是放行（ACCEPT），还是拒绝（REJECT），或是丢弃（DROP）等。前面提到 iptables 命令的使用规则：`iptables [-t table] ...`，如果省略 `-t table`，则默认操作的就是 filter 表。

- security 表：安全增强，一般用于 SELinux 中，其他情况并不常用。

一个链上可以关联的表可以有多个，所以这 5 张表在一个链上执行的时候得有个顺序：`raw --> mangle --> nat --> filter --> security`，即先去连接追踪，再改数据包，然后做源或目标地址转换，最后是过滤和安全。表与链的对应关系如下表所示：

![img](https://gitlab.com/jwkljh/img2023/-/raw/main/2303/netfilter-packet-flow.png)

5 条链源自 5 个钩子，而它们与 5 张规则表的关系是固定的。表不可新增，但可以在某张表中新增自定义链，并且自定义链只能通过默认的 5 条链 jump（比如 iptables 中的 `-j, --jump target`参数）过去，对应的规则才能被执行。

了解 Netfilter 框架对网络通信的干预逻辑之后，我们知道了这个框架内部的复杂程度。前面也提到，如果直接操控 Netfilter 框架的各个钩子是不太现实的，所以就有了 Xtables 系列工具。假设把 Netfilter 框架当作服务端，那么 Xtables 系列工具就是客户端，这是一个典型的 C/S 架构，如同 Linux 下各类终端命令一般。



# IPVS

IPVS基于传输层实现负载均衡能力，IPVS服务所运行的集群，扮演这负载均衡器的角色。拦截网络流量，并利用相关算法将流量路由到后端某台真实服务器

pvs 是 Netfilter 框架上的一个模块，可用来构建高可用、高性能的服务器集群。

![img](https://gitlab.com/jwkljh/img2023/-/raw/main/2306/ipvs-on-netfilter.png)

ipvs 只实现了 Netfilter 框架中的三个钩子，分别是：Input，Forward 和 Output，也就是加工发往本机的数据包，转发数据包以及加工从本机进程处理后的数据包。

从源码层面来看，与三个钩子相对应的函数主要有：`ip_vs_remote_request`, `ip_vs_reply` `ip_vs_forward_icmp`, `ip_vs_local_request`, `ip_vs_local_reply`。

那么这些函数干了啥呢？其实，上面的注释已经给出一部分信息。

nput Hook：`ip_vs_remote_request`, `ip_vs_reply`

1）`ip_vs_remote_request` 对应的核心函数为 `ip_vs_in`，用于处理外部客户端进入 ipvs 系统的报文，如果没有可用连接，则创建；

2） `ip_vs_reply` 对应的核心函数为 `ip_vs_out`，用于处理系统回复给外部客户端的报文，比如修改源 IP 或目标 IP 地址等。

```
/*
 *	It is hooked at the NF_INET_FORWARD and NF_INET_LOCAL_IN chain, used only for VS/NAT.
 *	Check if packet is reply for established ip_vs_conn.
 */
static unsigned int ip_vs_reply4(void *priv, struct sk_buff *skb,
	     const struct nf_hook_state *state) {
	return ip_vs_out(net_ipvs(state->net), state->hook, skb, AF_INET);
}
```

Forward Hook: `ip_vs_forward_icmp`, `ip_vs_reply`

1） `ip_vs_forward_icmp` 的核心函数为 `ip_vs_in_icmp`，用于处理外部客户端进入 ipvs 系统的 ICMP 报文，并将其转发到后端真实的服务器上。

```
/*
 *			It is hooked at the NF_INET_FORWARD chain, in order to catch ICMP
 *      related packets destined for 0.0.0.0/0.
 *      When fwmark-based virtual service is used, such as transparent
 *      cache cluster, TCP packets can be marked and routed to ip_vs_in,
 *      but ICMP destined for 0.0.0.0/0 cannnot be easily marked and
 *      sent to ip_vs_in_icmp. So, catch them at the NF_INET_FORWARD chain
 *      and send them to ip_vs_in_icmp.
 */
static unsigned int
ip_vs_forward_icmp(void *priv, struct sk_buff *skb,
		   const struct nf_hook_state *state)
{
	int r;
	struct netns_ipvs *ipvs = net_ipvs(state->net);

	if (ip_hdr(skb)->protocol != IPPROTO_ICMP)
		return NF_ACCEPT;

	/* ipvs enabled in this netns ? */
	if (unlikely(sysctl_backup_only(ipvs) || !ipvs->enable))
		return NF_ACCEPT;

	return ip_vs_in_icmp(ipvs, skb, &r, state->hook);
}
```

- 2） `ip_vs_reply` 在上面已经介绍过，对于后端真实服务器返回的数据报文，ipvs 系统需要将其源 IP 地址修改为 ipvs 系统所在机器的虚拟 IP（即 SNAT）。

- Output Hook: `ip_vs_local_request`, `ip_vs_local_reply`

  1）`ip_vs_local_request` 对应的核心函数是前面介绍的 `ip_vs_in`，主要处理由本机应用服务发给 ipvs 系统的报文，调度并发送信息等；

  2）`ip_vs_local_reply` 对应的核心函数也是前面介绍的 `ip_vs_out`，只不过这里处理的是 ipvs 本机回复的消息，一般用于 NAT/Masq 转发模式，以及 NAT 地址的修改等。

  > **MASQUERADE**：地址伪装，可以理解为动态的 SNAT。通过它可以将源地址绑定到某个网卡上，因为这个网卡的 IP 可能是动态变化的，此时用 SNAT 就不好实现。
  >
  > **AI 回复**：MASQUERADE 转发模式用于网络地址转换（NAT）的设置，允许私有网络中的计算机通过共享的公共 IP 地址访问互联网。MASQUERADE 是一种特殊的 NAT 转发模式，它动态地修改数据包的源 IP 地址，使其伪装成 NAT 网关的 IP 地址，从而实现网络连接的转发。

简单来说，当一个请求到 ipvs 系统后，会被内核拦截，在 ipvs 系统处理后（即上面提到的钩子），再发往后端真实的服务器，后端服务器回复的消息也 **可能** 会走 ipvs，经过转换后，再转发给原请求客户端。