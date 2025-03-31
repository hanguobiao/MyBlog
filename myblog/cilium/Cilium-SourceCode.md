---
title: Cilium BPF程序分析
date: 2025-03-30
update: 2025-03-30
comment: false
tags:
  - Cilium
  - BPF
categories:
  - Cilium
  - BPF
---

这里对Cilium中的BPF程序做一下分析，代码基于Cilium v1.16版本。主要分析跨节点情况下数据包在Cilium中的DataPath

*<!--more-->*

# 配置

Cilium的配置存储在ConfigMap,

Cilium策略存储在CRD当中，包括NetworkPolicies

# IPAM

CNI负责为POD分配IP地址，

Cilium支持多种IPAM模式：

- 在KubeBlocks-host scope模式中，会为整个集群分配一个很大的前缀范围，Kubernetes为每个节点划分出该前缀的一个子网。之后，Cilium从每个子网获取并分配IP
- 在Cluster scope模式下，Cilium为每个节点分配CIDR，如果IP用完，还可以为集群添加更多前缀。在前两种模式下，同一节点上的Pod将从同一范围接受IP地址。
- multi-pool scope支持根据用户定义的工作负载属性，从多个不同的IPAM池当中分配PodCIDR。同一节点上的POd可以接受来自不同范围的IP地址。此外，podCIDR可以在被需要的时候动态添加到节点上



# DNS

DNS不属于CNI的职责范畴，Kubernetes集群自带一个内置的DNS服务器（通常是coreDNS），会根据namespace和集群名称自动分配名称

例如Pod的IP地址是10.244.1.234，那么它就会获得10- 244-1-234.default.pod.cluster.local这样的名称。

默认情况下，pod会使用clisterFirst的DNS策略。使用这个策略，任何不符合集群DNS后缀的DNS请求都会被转发到上游的DNS服务器。Kubernetes中可以为每个Pod单独配置DNS策略 



# Pod之间是如何通讯的

## Overlay

![image-20250328121146998](https://myblog-1307634347.cos.ap-guangzhou.myqcloud.com/blog/image-20250328121146998.png)

优点

- 不依赖底层网络--连接节点的网络不需要知道POD CIDR。只要节点能通信，POD就能通信
- 克服IP地址不足的挑战--不依赖底层网络，有更多的IP地址可供Pod使用
- 自动配置和简单性--加入集群的新节点将自动加入overlay网络

缺点

Overlay意味着要添加包头，每1500字节的数据包需要50字节开销





# 源码

## bpf_host.c

### from_container

#### cil_from_container

1. 初始化操作清理元数据，重置*Qdisc队列映射*
2. 协议类型检测
3. 处理IPv4和IPv6流量，以IPv4为例
   1. 设置EDT限速
   2. 尾调用CILIUM_CALL_IPV4_FROM_LXC

```
/* Attachment/entry point is ingress for veth.
 * It corresponds to packets leaving the container.
 */
__section_entry
int cil_from_container(struct __ctx_buff *ctx)
{
	__u16 proto;
	__u32 sec_label = SECLABEL;
	__s8 ext_err = 0;
	int ret;

	bpf_clear_meta(ctx);
	reset_queue_mapping(ctx);

	if (!validate_ethertype(ctx, &proto)) {
		ret = DROP_UNSUPPORTED_L2;
		goto out;
	}

	switch (proto) {
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		edt_set_aggregate(ctx, LXC_ID);
		ret = tail_call_internal(ctx, CILIUM_CALL_IPV4_FROM_LXC, &ext_err);
		sec_label = SECLABEL_IPV4;
		break;
#endif /* ENABLE_IPV4 */

}
```

调用栈

```
cil_from_container 
|- bpf_clear_meta
|- reset_queue_mapping
|- #ifdef —> ENABLE_IPV4 
|  |- tail_handle_ipv4 -> __tail_handle_ipv4 -> tail_ipv4_ct_egress -> tail_handle_ipv4_cont -> handle_ipv4_from_lxc
|  |  |- 
```



#### handle_ipv4_from_lxc

之后通过尾调用CILIUM_CALL_IPV4_FROM_LXC， 这里是容器发出流量的核心处理流程

```
__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV4_FROM_LXC)
int tail_handle_ipv4(struct __ctx_buff *ctx)
{
    __s8 ext_err = 0;
    int ret = __tail_handle_ipv4(ctx, &ext_err);

    if (IS_ERR(ret))
       return send_drop_notify_error_ext(ctx, SECLABEL_IPV4, ret, ext_err,
                     CTX_ACT_DROP, METRIC_EGRESS);
    return ret;
}
```

处理流程

1. 获取identity身份

```
info = lookup_ip4_remote_endpoint(ip4->daddr, cluster_id);
		if (info && info->sec_identity) {
			*dst_sec_identity = info->sec_identity;
			tunnel_endpoint = info->tunnel_endpoint;
			encrypt_key = get_min_encrypt_key(info->key);
			skip_tunnel = info->flag_skip_tunnel;
		} else {
			*dst_sec_identity = WORLD_IPV4_ID;
		}
```

2. 判断是否符合策略

```
	verdict = policy_can_egress4(ctx, &POLICY_MAP, tuple, l4_off, SECLABEL_IPV4,
				     *dst_sec_identity, &policy_match_type, &audited,
				     ext_err, &proxy_port);

```

3. 根据CT的状态进行下一步行为

Case CT_NEW: 

1. 填充CT条目
1. 查找集群范围的CT映射表
1. 创建双向CT条目

case CT_REPLY：基础主连接属性

case CT_REPLY：policy_mark_skip(ctx);

case CT_ESTABLISHED：

根据proxy_redirect判断是否重建



```
	switch (ct_status) {
	case CT_NEW:
ct_recreate4:

		ct_map = get_cluster_ct_map4(tuple, cluster_id);
		if (!ct_map)
			return DROP_CT_NO_MAP_FOUND;

		ct_related_map = get_cluster_ct_any_map4(cluster_id);
		if (!ct_related_map)
			return DROP_CT_NO_MAP_FOUND;

		/* We could avoid creating related entries for legacy ClusterIP
		 * handling here, but turns out that verifier cannot handle it.
		 */
		ct_state_new.proxy_redirect = proxy_port > 0;
		ct_state_new.from_l7lb = from_l7lb;

		ret = ct_create4(ct_map, ct_related_map, tuple, ctx,
				 CT_EGRESS, &ct_state_new, ext_err);
		if (IS_ERR(ret))
			return ret;
		break;

	case CT_ESTABLISHED:
		ct_state_new.proxy_redirect = proxy_port > 0;
		if (unlikely(ct_state->proxy_redirect != ct_state_new.proxy_redirect))
			goto ct_recreate4;
		break;

	case CT_RELATED:
	case CT_REPLY:
		policy_mark_skip(ctx);
```

4. 获取到后端的IP

```
		/* 查找IPv4地址，在以下情况会返回匹配结果：
		 * 目标IP地址属于由Cilium管理的本地端点
		 * 目标IP地址是主机本身的关联IP地址
		 * 目标IP地址属于端点自身 */
		ep = __lookup_ip4_endpoint(daddr);
```

5. 交给vxLAN的隧道，这里使用 tunnel endpoint 作为隧道对端。最终转发给 `ENCAP_IFINDEX`（这个值是接口的索引值，由 cilium-agent 启动时获取的），就是cilium_vxlan`。

```
		ret = encap_and_redirect_lxc(ctx, tunnel_endpoint, ip4->saddr,
					     ip4->daddr, encrypt_key, &key,
					     SECLABEL_IPV4, *dst_sec_identity, &trace);
```

调用链

```
encap_and_redirect_lxc -> __encap_and_redirect_lxc -> encap_and_redirect_with_nodeid
```



## cilium_vxlan

cilium_vxlan的BPF程序位于bpf_overlay.c，这里的BPF程序就是被attach到vxLAN隧道的端口

这里默认会直接返回int ret = TC_ACT_OK;

但是会额外处理等内容

1. **带宽管理**：精确流量调度(QoS)
2. **身份标记**：安全身份传递
3. **NAT处理**：NodePort服务转发
4. **隧道管理**：封装信息维护

```
/* Attached to the egress of cilium_vxlan/cilium_geneve to execute on packets
 * leaving the node via the tunnel.
 */
__section_entry
int cil_to_overlay(struct __ctx_buff *ctx)
{
		int ret = TC_ACT_OK;
}
```



接着就是数据包进入内核协议栈

## to_host_from_lxc

如果数据包需要出主机，发往另外的主机，那么会触发`eth0` 接口，这里的逻辑在bpf_host.c当中

类似的这里基本上也就是返回 `CTX_ACT_OK` 交给内核网络栈继续处理

```
static __always_inline int
/* Handles packet from a local endpoint entering the host namespace. Applies
 * ingress host policies.
 */
to_host_from_lxc(struct __ctx_buff *ctx __maybe_unused)
{
    int ret = CTX_ACT_OK;
    ...
}
```



## from_host_to_lxc

数据包进入主机后也会触发挂载在eth0当中的BPF程序

```
from_host_to_lxc -> ipv4_host_policy_egress -> __ipv4_host_policy_egress
```

__ipv4_host_policy_egress会判断HOST级别的identity和policies



## cil_from_overlay

之后数据包会进入到cilium_vxlan，触发cli_from_overlay

```
-> tail_handle_ipv4 -> handle_ipv4
|- lookup_ip4_remote_endpoint 
|- lookup_ip4_endpoint
|- return ipv4_local_deliver
|  |- l3_local_delivery
|  |  |- tail_call_policy(ctx, ep->lxc_id)
```

处理流程，检查Endpoint是否在当前Node当中，获取到Endpoint的信息

最终通过ipv4_local_delivery，通过Endpoint中的lxcID尾调用BPF，也就是cil_to_container



## cil_to_container

如果目标地址就在本机的话，就会被这里捕获并处理

处理流程：

1. 初始化

```
bpf_clear_meta(ctx);

magic = inherit_identity_from_host(ctx, &identity);
```

2. 主机防火墙策略执行

```
	/* 如果数据包来自主机命名空间（hostns）并且启用了每端点路由，
   * 那么在处理其他逻辑之前，首先跳转至 bpf_host 以执行出口主机策略。
   * 主机策略执行完毕后，我们会跳回 bpf_lxc。每当调用 inherit_identity_from_host 时，
   * 数据包标记（packet mark）会被清除。因此，当跳转回来时，
   * 数据包标记已被清除，身份标识也不再匹配 HOST_ID。 */
	if (identity == HOST_ID) {
		ctx_store_meta(ctx, CB_FROM_HOST, 1);
		ctx_store_meta(ctx, CB_DST_ENDPOINT_ID, LXC_ID);

		ret = tail_call_policy(ctx, HOST_EP_ID);
		return send_drop_notify(ctx, identity, sec_label, LXC_ID,
					DROP_HOST_NOT_READY, CTX_ACT_DROP,
					METRIC_INGRESS);
	}
```

3. 协议分发

```
	if (identity_is_world_ipv4(identity)) {
		struct endpoint_info *ep;
		void *data, *data_end;
		struct iphdr *ip4;

		if (!revalidate_data(ctx, &data, &data_end, &ip4)) {
			ret = DROP_INVALID;
			goto out;
		}

		ep = __lookup_ip4_endpoint(ip4->saddr);
		if (ep)
			identity = ep->sec_id;
	}
# endif /* ENABLE_HIGH_SCALE_IPCACHE */
		ctx_store_meta(ctx, CB_SRC_LABEL, identity);
		ret = tail_call_internal(ctx, CILIUM_CALL_IPV4_CT_INGRESS, &ext_err);
		break;
```

通过尾调用进一步处理CILIUM_CALL_IPV4_CT_INGRESS 调用tail_ipv4_to_endpoint进行进一步处理

```
ret = tail_call_internal(ctx, CILIUM_CALL_IPV4_CT_INGRESS, &ext_err);
```



### tail_ipv4_to_endpoint

这里涉及到identity的处理

1. 获取identity

```
__u32 src_sec_identity = ctx_load_and_clear_meta(ctx, CB_SRC_LABEL);
```

2. 查询Endpoint并处理SNAT的情况

```
		info = lookup_ip4_remote_endpoint(ip4->saddr, 0);
		if (info != NULL) {
			__u32 sec_identity = info->sec_identity;

			if (sec_identity) {
        /* 当对进入 Cilium 的流量启用 SNAT 时，
         * 来自外部世界的所有流量都会将主机 IP 作为源地址。
         * 实际仅当 "src_sec_identity"（传入本函数的参数）
         * 将源标识为主机时，流量才真正来自主机。
         * 因此若 ipcache 将源标记为 HOST_ID，
         * 我们可以忽略其报告。 */
				if (sec_identity != HOST_ID)
					src_sec_identity = sec_identity;
			}
		}
```

| 原始源IP   | SNAT后源IP | 身份判定逻辑                  |
| ---------- | ---------- | ----------------------------- |
| 外部真实IP | 主机IP     | 按IPCACHE中外部IP映射的身份   |
| 主机进程IP | 主机IP     | 保留src_sec_identity的HOST_ID |

3. Policies处理

```
	ret = ipv4_policy(ctx, ip4, THIS_INTERFACE_IFINDEX, src_sec_identity,
			  NULL, &ext_err, &proxy_port, false);
	switch (ret) {
	case POLICY_ACT_PROXY_REDIRECT:
		if (!revalidate_data(ctx, &data, &data_end, &ip4)) {
			ret = DROP_INVALID;
			goto out;
		}

		ret = ctx_redirect_to_proxy_hairpin_ipv4(ctx, ip4, proxy_port);
		ctx->mark = ctx_load_meta(ctx, CB_PROXY_MAGIC);
		proxy_redirect = true;
		break;
```



### handle_policy

这里处理networkplicy的逻辑

1. 验证协议

```
	if (!validate_ethertype(ctx, &proto)) {
		ret = DROP_UNSUPPORTED_L2;
		goto out;
	}
```

2. 尾调用tail_ipv4_policy

```
case bpf_htons(ETH_P_IP):
    ret = invoke_tailcall_if(__and(is_defined(ENABLE_IPV4), is_defined(ENABLE_IPV6)),
              CILIUM_CALL_IPV4_CT_INGRESS_POLICY_ONLY,
              tail_ipv4_ct_ingress_policy_only, &ext_err);
    sec_label = SECLABEL_IPV4;
    break;
```



### tail_ipv4_policy

执行networkplicy

1. 处理tunnel模式

   隧道封装流量直接入栈时因MAC地址不匹配被内核过滤，这里需要标记为发送主机类型

2. 执行策略

```
	ret = ipv4_policy(ctx, ip4, THIS_INTERFACE_IFINDEX, src_label, &tuple,
			  &ext_err, &proxy_port, from_tunnel);
	switch (ret) {
	case POLICY_ACT_PROXY_REDIRECT:
		ret = ctx_redirect_to_proxy4(ctx, &tuple, proxy_port, from_host);
		proxy_redirect = true;
		break;
	case CTX_ACT_OK:
```

3. case CTX_ACT_OK时，端点直连转发，这时包会发送到虚拟以太接口，lxc，进入到veth并到达容器的eth0接口

```
		if (ifindex)
			ret = redirect_ep(ctx, THIS_INTERFACE_IFINDEX, from_host,
					  from_tunnel);
```





# CNI 

```
func main() {
    c := cmd.NewCmd()
    skel.PluginMain(c.Add,
       c.Check,
       c.Del,
       cniVersion.PluginSupports("0.1.0", "0.2.0", "0.3.0", "0.3.1", "0.4.0", "1.0.0"),
       "Cilium CNI plugin "+version.Version)
}
```

##  ADD

1. 创建Veth，并将一段移到容器ns

并且 host 侧网卡命名一般是: lxc + sha256(containerID))，如 lxc123abc；container 侧网卡命名一般是：tmp + maxLen(endpointID, 5)，如 tmp123, 并且设置：

```
veth, peer, tmpIfName, err := connector.SetupVeth(cniID, int(conf.DeviceMTU),
    int(conf.GROMaxSize), int(conf.GSOMaxSize),
    int(conf.GROIPV4MaxSize), int(conf.GSOIPV4MaxSize), ep, sysctl)
    
    
err = connector.SetupVethRemoteNs(ns, tmpIfName, epConf.IfName())
```

2. 配置容器侧路由将容器内的流量劫持到Cilium网卡

```
docker inspect 9a0874d84b93 | grep -i pid # 9a0874d84b93 为 container id
nsenter -t 15707 -n route -n
#Kernel IP routing table
#Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
#0.0.0.0         100.216.152.93   0.0.0.0         UG    0      0        0 eth0
#100.216.152.93   0.0.0.0         255.255.255.255 UH    0      0        0 eth0
```

3. Cilium IPAM 分配 pod ip

```
ipam, err = c.IPAMAllocate("", podName, true)
```

4. 下发 eBPF 程序

针对每一个 pod 创建对应的 CiliumEndpoint 对象，在这一步会下发 tc eBPF 程序到 pod 网卡上:





# VxLAN

当不同节点的Pod进行通信时，会利用Cilium_VxLan，对数据包进行封装

这是由于层物理网络常无法直接路由 Pod 的虚拟 IP。VXLAN 通过创建逻辑覆盖网络(Layer 2 over Layer 3)实现：

- **封装能力**：将原始 Pod 的 Ethernet 帧封装在 UDP 包中，头部附加 VXLAN 标识
- **透明转发**：底网仅需处理外层 UDP 包的三层路由，无需感知内部虚拟网络结构

![img](https://myblog-1307634347.cos.ap-guangzhou.myqcloud.com/blog/image-19-1024x578.png)

在cilium_vxlan虚拟网络接口上抓包，如下所示。从抓包分析可以看出，Linux内核将Pod1发出的原始数据包发送到cilium_vxlan进行隧道相关的封包、解包处理，然后再将其送往主机的物理网卡eth0。

![img](https://myblog-1307634347.cos.ap-guangzhou.myqcloud.com/blog/image-20-1024x232.png)

图7 cilium_vxlan抓包

在物理网卡eth0抓包可以发现，Pod1出发的数据包经过cilium_vxlan的封装处理之后，其源目的地址已经变成物理主机node-161和node-162，这是经典的overlay封装。同时，还可以发现，cilium_vxlan除了对数据包进行了隧道封装之外，还将原始数据包进行了TLS加密处理，保障了数据包在主机外的物理网络中的安全性。

![img](https://myblog-1307634347.cos.ap-guangzhou.myqcloud.com/blog/image-21.png)

图8 node-161 eth0抓包
