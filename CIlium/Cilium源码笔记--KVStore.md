# What's Inside Cilium's KVStore (and What's Not)

Cilium 需要数据存储来在代理之间传播状态。它支持以下数据存储：

### Kubernetes CRDs（默认）

存储任何数据并传播状态的默认选择是使用 Kubernetes 自定义资源定义（CRDs）。Kubernetes 提供 CRDs，供集群组件通过 Kubernetes 资源来表示配置和状态。

### 键值存储

通过 Cilium 默认配置中设置的 Kubernetes CRDs，可以满足所有状态存储和传播的需求。可选地，可以使用键值存储作为优化手段，以提高集群的可扩展性，因为直接使用键值存储可以更高效地处理变更通知和存储需求。



Ref：https://arthurchiao.art/blog/whats-inside-cilium-etcd/

在一个由 Cilium 驱动的大规模 Kubernetes 集群中，存在一个中央存储库（kvstore），所有 Cilium agent 都会连接到它。虽然 Cilium 支持多种类型的 kvstore，但最常用的是 etcd。

那么你可能会好奇：这个 kvstore 中究竟存储了哪些内容？在这篇文章中，我们将深入探讨这一问题。

# 1 Preparation

Software version:

1. Kubernetes: `1.17+`
2. Cilium: `1.8.2`
3. Etcd (cilium kvstore): `3.2.24`

# 2 What’s inside cilium-etcd

些导出的键值主要分为三类：

- Pod 身份信息
- Pod IP 地址
- Kubernetes 节点信息

## 2.1 Identity

```
$ etcdctl get cilium/state/identities/v1/id/12928
k8s:app=istio-ingressgateway;
k8s:chart=gateways;
k8s:heritage=Tiller;
k8s:io.cilium.k8s.policy.cluster=default;
k8s:io.cilium.k8s.policy.serviceaccount=ai-ingressgateway-service-account;
k8s:io.kubernetes.pod.namespace=istio-system;
k8s:istio=ai-ingressgateway;
k8s:release=istio;
```

Cilium 从 Kubernetes 中提取了部分（并非全部，例如 pod-template 被忽略）标签，并为其添加 `k8s:` 前缀，然后存储到 cilium-etcd 中。

- `app=istio-ingressgateway`
- `chart=gateways`
- `heritage=Tiller`
- `istio=ai-ingressgateway`
- `release=istio`

此外，它还会添加自己的标签：

- `k8s:io.cilium.k8s.policy.cluster=default`
- `k8s:io.cilium.k8s.policy.serviceaccount=ai-ingressgateway-service-account`
- `k8s:io.kubernetes.pod.namespace=istio-system`

## 2.2 Labels -> Identity

## 2.3 Pod IP Address

在 `k describe pod` 的输出中，我们获取了一些额外信息：

Pod IP: 10.6.6.43
 节点: k8s-node1
 PodCIDR: 10.6.6.0/24

```
$ etcdctl get cilium/state/ip/v1/default/10.6.6.43
{
  "IP":"10.6.6.43",
  "Mask":null,
  "HostIP":"10.5.1.132",
  "ID":12928,
  "Key":0,
  "Metadata":"cilium-global:default:k8s-node1:432",
  "K8sNamespace":"istio-system",
  "K8sPodName":"ai-ingressgateway-6bdbdbf7dc-jz85c"
}
```

## 2.4 Kubernetes Node

```
$ etcdctl get cilium/state/nodes/v1/default/k8s-node1
{
  "Name":"k8s-node1",
  "Cluster":"default",
  "IPAddresses":[{"Type":"InternalIP", "IP":"10.5.1.132"},
                 {"Type":"CiliumInternalIP", "IP":"10.6.6.71"}],
  "IPv4AllocCIDR":{"IP":"10.6.6.0", "Mask":"////AA=="},
  "IPv6AllocCIDR":null,
  "IPv4HealthIP":"10.6.6.79",
  "IPv6HealthIP":"",
  "ClusterID":0,
  "Source":"local",
  "EncryptionKey":0
},
```

### 2.4.1 IPv4AllocCIDR

```
(k8s master) $ kubectl describe node k8s-node1 | grep PodCIDR
PodCIDR:                      10.6.6.0/24
PodCIDRs:                     10.6.6.0/24
```

### 2.4.2 CiliumInternalIP

```
(k8s-node1) $ ifconfig cilium_host
cilium_host: flags=4291<UP,BROADCAST,RUNNING,NOARP,MULTICAST>  mtu 1500
        inet 10.6.6.71  netmask 255.255.255.255  broadcast 0.0.0.0
        ...
```

### 2.4.3 IPv4HealthIP

```
(k8s-node1) $ cilium endpoint list | awk 'NR == 1 || /reserved:health/'
ENDPOINT   POLICY (ingress)   POLICY (egress)   IDENTITY   LABELS (source:key[=value])   IPv4          STATUS
3030       Disabled           Disabled          4          reserved:health               10.6.6.79    ready
```

# 3 What’s NOT inside cilium-etcd

## 3.1 Cilium network policy (CNP)

Cilium network policy (CNP) stores in k8s apiserver.

```
(k8s master) $ kubelet get cnp
NAME        AGE
cnp-test    10d
```

Cilium agents listen to apiserver, and cache them locally:

```
(node) $ cilium policy get
[
  {
    "endpointSelector": {
      "matchLabels": {
        "any:cnp": "test",
        "k8s:io.kubernetes.pod.namespace": "default"
      }
    },
    "ingress": [
      {
        "fromEndpoints": [
          {
            "matchLabels": {
              "any:io.kubernetes.pod.namespace": "default",
              "any:cnp": "apitest"
            }
          }
        ],
```

在代理重启或节点重启时，Cilium 代理会从 API Server 中重新创建这些策略。

## 3.2 Endpoint

Cilium 的端点是一个节点本地的概念，也就是说，EndpointID 仅在创建它的节点内有意义，且不同节点之间的 EndpointID 可能存在重叠。

```
(node1) $ cilium endpoint list
ENDPOINT   IDENTITY   LABELS (source:key[=value])                    IPv4       STATUS
2489       42222      k8s:app=redis                                  10.2.2.2   ready
                      k8s:io.kubernetes.pod.namespace=default
(node2) $ cilium endpoint list
ENDPOINT   IDENTITY   LABELS (source:key[=value])                    IPv4       STATUS
2489       43333      k8s:app=mongo                                  10.2.3.3   ready
                      k8s:io.kubernetes.pod.namespace=default
```

## 3.3 CiliumEndpoint (CEP)

对于每个端点，cilium-agent 会在 Kubernetes 中创建一个相应的 CiliumEndpoint CRD

```
(master) $ k describe cep web1-0
Name:         web1-0
Namespace:    default
Labels:       <none>
Annotations:  <none>
API Version:  cilium.io/v2
Kind:         CiliumEndpoint
Metadata:
  Creation Timestamp:  2020-09-16T10:25:56Z
  Generation:          1
  Resource Version:    2164268066
  Self Link:           /apis/cilium.io/v2/namespaces/default/ciliumendpoints/web1-0
  UID:                 9881196e-359a-4bd2-bcb8-a357e17a9441
Status:
  Encryption:
  External - Identifiers:
    Container - Id:  34722eeca1019e273c158f2ef94bfd80c36d45f8afd48d8f547c12989ae69348
    k8s-namespace:   default
    k8s-pod-name:    web1-0
    Pod - Name:      default/web1-0
  Id:                3139
  Identity:
    Id:  8419
    Labels:
      k8s:io.kubernetes.pod.namespace=default
      k8s:statefulset.kubernetes.io/pod-name=web1-0
  Named - Ports:
    Name:      web
    Port:      80
    Protocol:  TCP
  Networking:
    Addressing:
      ipv4:  10.6.2.2
    Node:    10.5.6.60
  State:     ready
Events:      <none>
```

对于每个端点，都会有一个专用的控制器，用于将本地端点的状态同步到 Kubernetes 的 CEP（CiliumEndpoint）资源中。

# 4. Summary

cilium-etcd 内部存储的内容（键 -> 值）：

1. `IdentityID` -> `IdentityLabels` (PodLabels)
2. `IdentityLabels` + `/` + `NodeIP` -> `IdentityID`
3. `PodIP` -> `PodIPDetails` (e.g. identity, host, etc)
4. `NodeName` -> `NodeDetails`
5. `ClusterMeshNodeName` -> `ClusterMeshNodeDetails`

cilium-etcd 中未存储的内容：

1. CiliumNetworkPolicy (CNP)：存储在 Kubernetes 中
2.  Endpoint（节点本地）：存储在节点本地文件中
3.  CiliumEndpoint (CEP)：存储在 Kubernetes 中