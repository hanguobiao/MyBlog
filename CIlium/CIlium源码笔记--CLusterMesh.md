# Cilium: What the Agents Do When ClusterMesh Enabled

Ref:https://arthurchiao.art/blog/cilium-clustermesh/

Cilium 提供了 clustermesh 功能，用于实现跨不同 Kubernetes 集群的全局服务负载均衡和网络策略执行



![img](https://arthurchiao.art/assets/img/cilium-clustermesh/clustermesh.png)

# 1 Introduction

## 1.1 Cilium-powered k8s cluster

![img](https://arthurchiao.art/assets/img/cilium-clustermesh/cilium-powered-k8s-cluster.png)

**apiserver**：位于master 节点上的 k8s API 服务器。
 诸如 `kubectl create/apply/delete/get/describe xxx` 等命令会向 apiserver 发送请求。

**cilium-agent**：运行在每个工作节点上的守护进程/代理。

- 监听 k8s apiserver 中的资源变化
- 监听 cilium-etcd 中的网络策略变化
- IP 分配（非 ENI 模式）
- Pod 网络设置
- 网络策略执行

**cilium-etcd**：用于存储信息的键值存储（仓库），包括：

- 节点信息
- 身份信息
- L3/L4/L7 网络策略

## 1.2 Multi-cluster scenarios (why multi-cluster?)

为了应对实际挑战，例如灾难恢复、业务管理以及基础设施的易维护性，您可能已经将业务应用程序部署到了多个集群中。

在这种情况下，确定具体实例（Pod）应放置在哪个集群时，存在不同的粒度：

**按服务划分**：例如，将服务 svc1 的所有 Pod 放置在 cluster1 中，而将服务 svc2 的所有 Pod 放置在 cluster2 中。
 **按 Pod 划分**：将一个服务的 Pod 分成两组，例如前半部分调度到 cluster1，后半部分调度到 cluster2。

这将导致在访问其他集群中的服务时，产生不同的模型/模式。

## 1.3 Cross-cluster accessing models

![img](https://arthurchiao.art/assets/img/cilium-clustermesh/multi-cluster-access-patterns.png)

如果 cluster1 中的客户端希望访问其他集群中的服务 svc，可能的模型包括：

**k8s Ingress：通过 L7**

- 由 k8s 描述的一种模型，但需要由网络插件/供应商实现。
- 通过 L7 代理（如 istio-gateway）暴露服务。
- istio-gateway 作为 API 网关，可以从其他集群访问。

**k8s LoadBalancer 或 externalIPs：通过 L4**

- 由 k8s 描述的一种模型，但需要由网络插件/供应商实现（更多信息见 [5]）。
- 通过 externalIPs 暴露服务。
- externalIPs 通常由云供应商提供，可以从其他集群访问，并将流量负载均衡到服务的正确后端。

**其他供应商特定的解决方案，例如 Cilium 的 clustermesh：在某种程度上通过 L3**

- 这不是 k8s 模型，而是 Cilium 提供的特定实现。
- 启用跨集群的 k8s 服务，服务的 Pod 可以分散到不同集群中。
- 客户端 Pod 可以访问任何集群中的服务，无论服务的后端运行在哪个集群。
- 同时支持跨集群的网络策略。

## 1.4 Where clustermesh is needed

如果您将同一服务的 Pod 分散到不同的集群中（如第 1.2 节中的第二种情况），并且希望对这些服务进行服务发现/负载均衡或实施网络策略，那么您可能需要 **clustermesh**。

# 2 Test environment

![img](https://arthurchiao.art/assets/img/cilium-clustermesh/separate-clusters.png)

如图 2-1 所示，我们在本文中使用两个 k8s 集群作为测试环境。这两个集群具备以下特性：

- 使用直接路由 [2,4] 实现跨主机网络通信。
- 两个集群的节点 IP 不重叠。
- 两个集群的 PodCIDR 不重叠。
- 没有防火墙规则阻止两个集群之间的通信。

这满足了 [1] 中详细描述的 clustermesh 的先决条件。

# 3 ClusterMesh setup

## 3.1 Configuration changes

在上述两个运行中的集群基础上，为 cilium agents 添加以下额外配置：

- **cluster-name**：在所有集群中唯一的字符串
- **cluster-id**：在所有集群中唯一的整数，范围为 0~255
- **clustermesh-config**：包含其他集群所有 cilium-etcd 配置文件的目录（注意，每个集群的配置文件名称必须与其集群名称相同）

这些配置的设计理念是：

1. 确保每个集群具有唯一的标识符（集群名称和 ID）。
2. 使一个集群中的 cilium agents 能够监听其他集群中的网络策略变化。

满足上述条件后，每个集群将能够获取所有集群中服务和网络策略的全局视图。

![img](https://arthurchiao.art/assets/img/cilium-clustermesh/clustermesh.png)

重新绘制图 2-1 如下，通过并排对比可以更清晰地看到变化（实际上是新增内容）：

![img](https://arthurchiao.art/assets/img/cilium-clustermesh/separate-clusters.png)

### 3.1.1 Configure cluster1

```
# previous
$ cilium-agent --config-dir=/tmp/cilium/config-map

# now
$ cilium-agent --config-dir=/tmp/cilium/config-map \
    --cluster-id=101 --cluster-name=cluster1 --clustermesh-config=/var/lib/cilium/clustermesh
```

`/var/lib/cilium/clustermesh` 是从主机路径 `mount/var/lib/cilium/clustermesh/` 挂载的。

```
(cluster1 node1) $ ls mount/var/lib/cilium/clustermesh/
cluster2
cluster2-etcd-client-ca.crt
cluster2-etcd-client.crt
cluster2-etcd-client.key

(cluster1 node1) $ cat mount/var/lib/cilium/clustermesh/cluster2
endpoints:
  - https://10.2.2.2:2379

ca-file:   '/var/lib/cilium/clustermesh/cluster2-etcd-client-ca.crt'
key-file:  '/var/lib/cilium/clustermesh/cluster2-etcd-client.key'
cert-file: '/var/lib/cilium/clustermesh/cluster2-etcd-client.crt'
```

### 3.1.2 Configure cluster2

```
$ cilium-agent --config-dir=/tmp/cilium/config-map \
    --cluster-id=102 --cluster-name=cluster2 --clustermesh-config=/var/lib/cilium/clustermesh
```

```
(cluster2 node1) $ ls mount/var/lib/cilium/clustermesh/
cluster1
cluster1-etcd-client-ca.crt
cluster1-etcd-client.crt
cluster1-etcd-client.key

(cluster2 node1) $ cat mount/var/lib/cilium/clustermesh/cluster1
endpoints:
  - https://10.1.1.1:2379

ca-file:   '/var/lib/cilium/clustermesh/cluster1-etcd-client-ca.crt'
key-file:  '/var/lib/cilium/clustermesh/cluster1-etcd-client.key'
cert-file: '/var/lib/cilium/clustermesh/cluster1-etcd-client.crt'
```

## 3.2 Verify clustermesh syncing

Check cluster status:

```
(cluster1 node1) $ cilium status --verbose
KVStore:                Ok   etcd: ...
Kubernetes:             Ok   1.17+ (v1.17.6-3) [linux/amd64]
...
ClusterMesh:   1/1 clusters ready, 0 global-services
   cluster2: ready, 23 nodes, 2618 identities, 0 services, 0 failures (last: never)
   └  etcd: 1/1 connected, ...
```

List all nodes of all clusters in the mesh:

```
(cluster1 node1) $ cilium node list
Name               IPv4 Address   Endpoint CIDR    IPv6 Address   Endpoint CIDR
cluster1/node1     10.xx.xx.xx   10.xx.xx.xx/24
cluster1/node2     10.xx.xx.xx   10.xx.xx.xx/24
...
cluster2/node1     10.xx.xx.xx   10.xx.xx.xx/24
cluster2/node2     10.xx.xx.xx   10.xx.xx.xx/24
...
```

# 4 Network policy test

创建了一个简单的服务器-客户端系统来测试集群网格（clustermesh）的网络策略实施：

- **protected-db**：服务器端，监听端口 6379
  仅允许来自员工 Pod 的访问，无论这些员工 Pod 位于哪个集群。
- **employee**：客户端，应被允许访问 protected-db。
- **所有其他 Pod**：不允许访问 protected-db。
  我们将创建一个名为 stranger 的 Pod 作为此类代表。

![img](https://arthurchiao.art/assets/img/cilium-clustermesh/policy-enabled.png)

## 4.1 Create server and clients

Server yaml `protected-db.yaml`:

```
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: protected-db
  annotations:
    io.cilium/global-service: "true"
spec:
  replicas: 1
  selector:
    matchLabels:
      app: protected-db
  serviceName: ""
  template:
    metadata:
      labels:
        app: protected-db
    spec:
      # affinity:
      #   nodeAffinity:
      #     requiredDuringSchedulingIgnoredDuringExecution:
      #       nodeSelectorTerms:
      #       - matchExpressions:
      #         - key: kubernetes.io/hostname
      #           operator: In
      #           values:
      #           - node1
      containers:
      - image: redis:6.0.5-alpine
        name: protected-db
```

与普通（非集群网格）服务相比，特殊之处在于 metadata 部分中的 `io.cilium/global-service: "true"` 注解。该注解告知 Cilium 代理，这是一个跨不同集群的后端 Pod 服务：

### 4.1.2 Create client in cluster1

### 4.1.3 Create client in cluster2

## 4.2 Connectivity test

```
# access protected-db from cluster1-employee:
(cluster1 master) $ k exec employee-0 redis-cli -- -h 10.3.3.3 -p 6379 ping
PONG

# access protected-db from cluster1-stranger:
(cluster1 master) $ k exec stranger-0 redis-cli -- -h 10.3.3.3 -p 6379 ping
PONG

# access protected-db from cluster2-employee:
(cluster2 master) $ k exec employee-0 -n istio-space redis-cli -- -h 10.3.3.3 -p 6379 ping
PONG
```

![img](https://arthurchiao.art/assets/img/cilium-clustermesh/no-policy.png)

## 4.3 Apply global network policy

我们将在 `protected-db` 的入口路径上应用 L4 策略。

`l4-policy.yaml`:

```
apiVersion: "cilium.io/v2"
kind: CiliumNetworkPolicy
metadata:
  name: "clustermesh-ingress-l4-policy"
  description: "demo: allow only employee to access protected-db"
spec:
  endpointSelector:
    matchLabels:
      app: protected-db
      io.cilium.k8s.policy.cluster: cluster1
  ingress:
  - toPorts:
    - ports:
      - port: "6379"
        protocol: TCP
    fromEndpoints:
      - matchLabels:
          app: employee
          io.cilium.k8s.policy.cluster: cluster2
          k8s:io.kubernetes.pod.namespace: istio-space
      - matchLabels:
          app: employee
          # io.cilium.k8s.policy.cluster: cluster1
          k8s:io.kubernetes.pod.namespace: default
```

请注意，对于同一集群内的客户端，**不能**添加 `io.cilium.k8s.policy.cluster: cluster1`

## 4.4 Test and observe

```
# access protected-db from cluster1-employee:
(cluster1 master) $ k exec employee-0 redis-cli -- -h 10.3.3.3 -p 6379 ping
PONG

# access protected-db from cluster1-stranger:
(cluster1 master) $ k exec stranger-0 redis-cli -- -h 10.3.3.3 -p 6379 ping
^C

# access protected-db from cluster2-employee:
(cluster2 master) $ k exec employee-0 -n istio-space redis-cli -- -h 10.3.3.3 -p 6379 ping
PONG
```

![img](https://arthurchiao.art/assets/img/cilium-clustermesh/policy-enabled.png)

在运行 `protected-db` 的节点的 `cilium-agent` 上进行抓包时，我们可以看到来自未知来源的 SYN 数据包被 `cilium-agent` 丢弃：

# 5 Conclusion

在这篇文章中，我们展示了如何通过为 `cilium-agent` 添加几个（具体来说是 4 个）额外参数来设置 Cilium 集群网格（clustermesh）。虽然这些步骤是基于我们的部署方式，但很容易适应其他部署方式，例如通过 DaemonSet 和 ConfigMap 进行部署。

如果你希望将更多集群加入网格，只需按照文章中的方法，将新集群的 `cilium-etcd` 配置文件及相应的证书添加到 `/var/lib/cilium/clustermesh` 目录中，它们将形成一个点对点的集群网格。