# 中心化部署

![image-20250226131743566](/Users/hanguobiao/Nutstore Files/读书笔记/Kubeblocks笔记/多K8s部署.assets/image-20250226131743566.png)

中心化方案会增加一个额外的中心K8s来存储KB的CR，以及运行KB Operator。为了保证该中心K8s的跨AZ容灾能力，此K8s通常会采用3AZ的部署形式。

在此方案中，KB定义的CRD及CR仅存放在中心K8s里。KB Operator仅在中心K8s里运行，不在任一Worker K8s里运行。KB Operator会通过多个worker K8s的API去拖取与检测Pod、Service、Configmap、Secret、PVC等K8s原生对象的更新，修改这些对象也转发到对应的K8s API中。

**从某种意义上来讲，方案一（去中心化的方案）很像是把中心K8s部署到这三个worker K8s集群的Pod里。**



# Overview

从 0.9.0 版本开始，kb 支持管理多个 k8s 集群，为用户在实例容灾、k8s 集群管理等方面提供新的选项。

KB 多 k8s 集群形态下，整个系统的逻辑结构如下图：

![image-20250226131416905](/Users/hanguobiao/Nutstore Files/读书笔记/Kubeblocks笔记/多K8s部署.assets/image-20250226131416905.png)

如图中所示，为了支持多 k8s 管理，引入一组新的概念：

- control plane k8s - 一个独立的 k8s 集群，kb operator 运行在该集群当中，kb 定义的相关对象大都存放在这个集群（比如 definition、cluster、backup、ops 等）。用户对多集群实例的管理，通过跟这个集群的 API 进行交互来完成。
- data plane k8s - 用于运行最终 workload 的 k8s 集群，数量可以是一到多个。这些集群当中会 hosting 实例相关的计算、存储、网络等资源，如 pod、pvc、service、sa、cm、secret、jobs 等，而 kb operator 目前（0.9.0）不会运行在当中。

实际物理部署上：control plane k8s 可以选择部署在单个 az，简单灵活；可以选择部署在多个不同 az，提供更高的可用性保证；可以复用某个 data plane k8s 集群，更低成本方式运行。

# 环境准备

这个阶段主要是 setup 几个 k8s 集群，以及准备部署 kb 所需的一些配置信息。

1. 准备 1 + n 个 k8s 集群，其中 1 设定为 control plane，n 设定为 data plane，确保这些 data plane k8s 集群的 API server 在 control plane 集群中可以联通（包含两个层面：一是网络连通，二是访问配置）。
2. 准备 operator 访问 data plane k8s 所需的配置信息，以 secret 形式放置在 control plane 集群当中，部署 kb operator 时需要传入。其中，secret key 要求为 “kubeconfig”，value 为标准 kubeconfig 内容格式。示例：

```YAML
apiVersion: v1
kind: Secret
metadata:
  namespace: kb-system
  name: <your-secret-name> 
type: kubernetes.kubeconfig
stringData:
  kubeconfig: |
    apiVersion: v1
    clusters:
      ...
    contexts:
      ...
    kind: Config
    users:
      ...
```

这里假设准备有三个 data plane k8s 集群，context 分别命名为：k8s-1、k8s-2、k8s-3。

# 部署

## Operator

Operator 运行在 control plane k8s，因此下述操作仅需要在 control plane 进行即可。

1. 通过 kbcli 部署 operator

```Bash
# multiCluster.kubeConfig - 指定存放 data plane k8s kubeconfig 信息的 secret
# multiCluster.contexts - 指定 data plane k8s contexts
kbcli kubeblocks install --version=0.9.0 --set multiCluster.kubeConfig=<secret-name> --set multiCluster.contexts=<contexts>
```

1. 检查、等待 operator 部署完成

```Bash
kbcli kubeblocks status
```

## RBAC

实例 workload 在 data plane k8s 运行时，需要特定的 RBAC 资源进行管理动作，因此需要预先在各 data plane 集群单独安装 kb 所需的 RBAC 资源。

```Bash
# 1. 从 control plane dump 所需的 clusterrole 资源：kubeblocks-cluster-pod-role
kubectl get clusterrole kubeblocks-cluster-pod-role -o yaml > /tmp/kubeblocks-cluster-pod-role.yaml

# 2. 编辑文件内容，去除不必要的 meta 信息（比如 UID、resource version），保留其他内容

# 3. Apply 文件内容到其他 data plane 集群
kubectl apply -f /tmp/kubeblocks-cluster-pod-role.yaml --context=k8s-1
kubectl apply -f /tmp/kubeblocks-cluster-pod-role.yaml --context=k8s-2
kubectl apply -f /tmp/kubeblocks-cluster-pod-role.yaml --context=k8s-3
```

## 网络

KB 基于 k8s service 抽象来提供内外部的服务访问。对于 service 的抽象，集群内的访问 k8s 一般会有默认的实现，对于来自集群外的流量通常需要用户自己提供方案。而在多 k8s 形态下，无论是实例间的复制流量、还是客户端的访问流量，基本都属于“集群外流量”。因此为了让跨集群实例能够正常工作，网络部分一般需要进行一些额外的处理。

这里会以一组可选的方案为例，用来完整描述整个流程。实际使用中，用户可以根据自身集群和网络环境，选择适合的方案进行部署。

### 东西向流量

#### 云上方案

云厂商提供的 k8s 服务，一般都提供了内/外网 load balancer service 可供使用，这样可以直接基于 LB service 来构建副本之间的互访，简单易用。

#### 自建方案

东西向互访的自建方案以 cilium clustermesh 为例来进行说明，cilium 本身的部署选择 overlay 模式，各 data plane 集群配置如下：

| cluster | context | name  | id   | CIDR        |
| ------- | ------- | ----- | ---- | ----------- |
| 1       | k8s-1   | k8s-1 | 1    | 10.1.0.0/16 |
| 2       | k8s-2   | k8s-2 | 2    | 10.2.0.0/16 |
| 3       | k8s-3   | k8s-3 | 3    | 10.3.0.0/16 |

注：这里的 CIDR 是 cilium overlay 网络的地址，具体设置时要跟主机网络地址段区分开。

下述操作步骤相关命令，可以在各个集群分别执行（不用带 --context 参数），也可以在有三个 context 信息的环境里统一执行（分别指定 --context 参数）。

1. 安装 cilium，指定 cluster id/name 和 cluster pool pod CIDR。官方文档：[Specify the Cluster Name and ID](https://docs.cilium.io/en/stable/network/clustermesh/clustermesh/#specify-the-cluster-name-and-id)。

```Bash
cilium install --set cluster.name=k8s-1 --set cluster.id=1 --set ipam.operator.clusterPoolIPv4PodCIDRList=10.1.0.0/16 —context k8s-1
cilium install --set cluster.name=k8s-2 --set cluster.id=2 --set ipam.operator.clusterPoolIPv4PodCIDRList=10.2.0.0/16 —context k8s-2
cilium install --set cluster.name=k8s-3 --set cluster.id=3 --set ipam.operator.clusterPoolIPv4PodCIDRList=10.3.0.0/16 —context k8s-3
```

1. 开启 cilium clustermesh，并等待 ready。这里以 NodePort 方式提供对 clustermesh control plane 的访问，其他可选方式及具体信息请参考官方文档：[Enable Cluster Mesh](https://docs.cilium.io/en/stable/network/clustermesh/clustermesh/#enable-cluster-mesh)。

```Bash
cilium clustermesh enable --service-type NodePort —context k8s-1
cilium clustermesh enable --service-type NodePort —context k8s-2
cilium clustermesh enable --service-type NodePort —context k8s-3
cilium clustermesh status —wait —context k8s-1
cilium clustermesh status —wait —context k8s-2
cilium clustermesh status —wait —context k8s-3
```

1. 打通各集群，并等待 ready。官方文档：[Connect Clusters](https://docs.cilium.io/en/stable/network/clustermesh/clustermesh/#connect-clusters)。

```Bash
cilium clustermesh connect --context k8s-1 --destination-context k8s-2
cilium clustermesh connect --context k8s-1 --destination-context k8s-3
cilium clustermesh connect --context k8s-2 --destination-context k8s-3
cilium clustermesh status —wait —context k8s-1
cilium clustermesh status —wait —context k8s-2
cilium clustermesh status —wait —context k8s-3
```

1. 【可选】可以通过 cilium dbg 工具检查跨集群的 tunnel 情况。官方文档：[cilium dbg](https://docs.cilium.io/en/stable/cmdref/cilium-dbg/)。

```Bash
cilium-dbg bpf tunnel list
```

1. 【可选】集群连通性测试。官方文档：[Test Pod Connectivity Between Clusters](https://docs.cilium.io/en/stable/network/clustermesh/clustermesh/#test-pod-connectivity-between-clusters)。

### 南北向流量

南北向为客户端提供服务，需要每个data plane k8s的Pod都有对外的连接地址，这个地址的实现可以是NodePort、LoadBalancer或者其他方案，我们以NodePort和LoadBalancer为例介绍。

如果客户端不具备读写路由能力，那在Pod地址之上，我们还需要提供读写分离地址，实现上可以用七层的Proxy，四层的SDN VIP，或者纯粹的DNS，为了简化问题，我们先假设客户端具备读写路由能力，可以直接配置所有Pod连接地址。

#### NodePort

NodePort方案非常简单，为每个data plane k8s集群的Pod创建NodePort Service，客户端用主机网络IP和NodePort即可连接。

#### LoadBalancer

以MetalLB提供LoadBalancer Service为例，首先要准备data plane k8s的LB网段，该网段需要跟客户端路由可达，并且不同k8s集群要错开：

| cluster | context | name  | id   | CIDR        |
| ------- | ------- | ----- | ---- | ----------- |
| 1       | k8s-1   | k8s-1 | 1    | 10.4.0.0/16 |
| 2       | k8s-2   | k8s-2 | 2    | 10.5.0.0/16 |
| 3       | k8s-3   | k8s-3 | 3    | 10.6.0.0/16 |

然后在所有data plane k8s部署MetalLB

```Bash
helm repo add metallb https://metallb.github.io/metallb
helm install metallb metallb/metallb
```

等待相关Pod ready

```Bash
kubectl wait --namespace metallb-system --for=condition=ready pod --selector=app=metallb --timeout=90s
```

在三个k8s集群apply以下yaml，请注意替换spec.addresses为对应k8s集群的LB网段

```YAML
apiVersion: metallb.io/v1beta1
kind: IPAddressPool
metadata:
  name: example
  namespace: metallb-system
spec:
  addresses:
  - x.x.x.x/x
---
apiVersion: metallb.io/v1beta1
kind: L2Advertisement
metadata:
  name: empty
  namespace: metallb-system
```

为每个data plane k8s集群的Pod创建LoadBalancer Service，拿到所有VIP，即可供客户端连接。

# 验证

多集群实例的运行，各个副本之间的访问地址不能直接简单使用原 domain 内的地址（比如 pod FQDN），需要显式的创建并配置使用跨集群的服务地址来进行通信，因此需要对 Addon 作一定适配工作。

这里以社区版 etcd 为例来进行演示，相关适配的结果可以参考 etcd addon：https://github.com/apecloud/kubeblocks-addons/blob/release-0.9/addons/etcd/templates/componentdefinition.yaml。

## 实例创建

因为不同的网络要求的配置会有不同，这里分别以云上和自建两种方式为例说明如果创建一个三副本的跨集群 etcd 实例。

### 云上方案

这里以阿里云为例，其他厂商的配置可以参考官方文档。

```YAML
apiVersion: apps.kubeblocks.io/v1alpha1
kind: Cluster
metadata:
  namespace: default
  generateName: etcd
  annotations:
    # optional：可以用该 annotation 显式指定当前实例要求分布的集群
    apps.kubeblocks.io/multi-cluster-placement: "k8s-1,k8s-2,k8s-3"
spec:
  terminationPolicy: WipeOut
  componentSpecs:
    - componentDef: etcd-0.9.0
      name: etcd
      replicas: 3
      resources:
        limits:
          cpu: 100m
          memory: 100M
        requests:
          cpu: 100m
          memory: 100M
      volumeClaimTemplates:
        - name: data
          spec:
            accessModes:
              - ReadWriteOnce
            resources:
              requests:
                storage: 20Gi # 云上 provisioning 要求的最小 size？
      services:
        - name: peer
          serviceType: LoadBalancer
          annotations:
            # 如果运行在基于 LoadBalancer service 提供的互访方案上，这个 annotation key 是必须
            apps.kubeblocks.io/multi-cluster-service-placement: unique
            # ACK LoadBalancer service 要求的 annotation key
            service.beta.kubernetes.io/alibaba-cloud-loadbalancer-address-type: intranet
          podService: true
```

阿里云 & 火山引擎跨云部署示例。

```YAML
apiVersion: apps.kubeblocks.io/v1alpha1
kind: Cluster
metadata:
  namespace: default
  generateName: etcd
  annotations:
    # optional：可以用该 annotation 显式指定当前实例要求分布的集群
    apps.kubeblocks.io/multi-cluster-placement: "k8s-1,k8s-2,k8s-3"
spec:
  terminationPolicy: WipeOut
  componentSpecs:
    - componentDef: etcd-0.9.0
      name: etcd
      replicas: 3
      resources:
        limits:
          cpu: 100m
          memory: 100M
        requests:
          cpu: 100m
          memory: 100M
      volumeClaimTemplates:
        - name: data
          spec:
            accessModes:
              - ReadWriteOnce
            resources:
              requests:
                storage: 20Gi # 云上 provisioning 要求的最小 size？
      services:
        - name: peer
          serviceType: LoadBalancer
          annotations:
            # 如果运行在基于 LoadBalancer service 提供的互访方案上，这个 annotation key 是必须
            apps.kubeblocks.io/multi-cluster-service-placement: unique
            # ACK LoadBalancer service 要求的 annotation key。因为要跨云访问，因此需要配置为公网类型
            service.beta.kubernetes.io/alibaba-cloud-loadbalancer-address-type: internet
            # VKE LoadBalancer service 要求的 annotation keys。因为要跨云访问，因此需要配置为公网类型
            service.beta.kubernetes.io/volcengine-loadbalancer-subnet-id: <subnet-id>
            service.beta.kubernetes.io/volcengine-loadbalancer-address-type: "PUBLIC"
          podService: true
```

### 自建方案

```Bash
apiVersion: apps.kubeblocks.io/v1alpha1
kind: Cluster
metadata:
  namespace: default
  generateName: etcd
  annotations:
    # optional：可以用该 annotation 显式指定当前实例要求分布的集群
    apps.kubeblocks.io/multi-cluster-placement: "k8s-1,k8s-2,k8s-3"
spec:
  terminationPolicy: WipeOut
  componentSpecs:
    - componentDef: etcd-0.9.0
      name: etcd
      replicas: 3
      resources:
        limits:
          cpu: 100m
          memory: 100M
        requests:
          cpu: 100m
          memory: 100M
      volumeClaimTemplates:
        - name: data
          spec:
            accessModes:
              - ReadWriteOnce
            resources:
              requests:
                storage: 1Gi
      services:
        - name: peer
          serviceType: ClusterIP
          annotations:
            service.cilium.io/global: "true" # cilium clustermesh global service
          podService: true
```

## 故障切换

- 副本故障

```Bash
# 1. down 掉主副本

# 2. 验证实例角色和流量切换
```

- 集群故障

当某个 k8s 集群发生故障不可用时，实例自身会通过自己的 HA 机制完成数据平面的服务切换，客户端的流量切换依赖所选择的南北向流量方案（TODO：待补充）。

控制平面上，因为 KB 无法独立判断某个 k8s 集群是否可用，因此需要用户介入来提供信息，明确标记某个集群不可用。在此期间（集群发生不可用，到用户告知 KB 该信息），新增和存量实例的管理和状态展示可能受影响（取决于具体的故障类型）。

当从 KB 标记故障集群之后，存量实例的状态会正常更新，新增实例如果不涉及故障集群的可以正常操作。Ps：这里不涉及故障副本的恢复。

```Bash
# 1. 创建三副本实例，等待实例运行正常

# 2. down 掉主副本所在 k8s 集群，假设为 k8s-0

# 3. 观察引擎自身，角色会自动完成更新切换

# 4. 观察实例在 KB 的状态，一直停留在故障前正常运行的状态，重启 KB 也不会有效果

# 5. 从 KB 标记故障集群不可用
$ kubectl edit deploy kubeblocks -n kb-system
## 给 manager 添加启动参数
--multi-cluster-contexts-disabled=k8s-0

# 6. 等待 KB 启动，观察存量实例状态更新

# 7. 新建实例，显式指定副本不包含故障集群，实例可以成功创建并正常运行
```

## 集群管理

- 查看集群

```Bash
# 1. 查看 data plane 集群列表和状态
```

- 关闭/打开集群

```Bash
# 1. 关闭某个 data plane 集群的分配

# 2. 验证上面实例运行正常

# 3. 验证新建实例不会分配到该集群

# 4. 重新打开集群的分配

# 5. 验证新建实例可以重新分配到该集群
```

- 添加/删除集群

```Bash
# 1. 添加一个新的 data plane 集群

# 2. 创建新实例，验证可以分配副本到新加集群

# 3. 清理该集群上的实例副本

# 4. 删除该集群，检查 data plane 集群列表和状态
```

# Reference

1. Cilium clustermesh：https://[docs.cilium.io/en/stable/network/clustermesh/clustermesh/](http://docs.cilium.io/en/stable/network/clustermesh/clustermesh/)
2. Cilium IPAM：https://[docs.cilium.io/en/stable/network/concepts/ipam/cluster-pool/](http://docs.cilium.io/en/stable/network/concepts/ipam/cluster-pool/)
3. Cilium dbg：https://[docs.cilium.io/en/stable/cmdref/cilium-dbg/](http://docs.cilium.io/en/stable/cmdref/cilium-dbg/)