

# 1 K8s 的核心是其 API 框架而非容器

## 1.1 容器是基础

时间回到 2013 年。当一条简单的 `docker run postgre` 命令就能运行起 postgre 这样 复杂的传统服务时，开发者在震惊之余犹如受到天启；以 docker 为代表的实用容器技术的 横空出世，也预示着一扇通往敏捷基础设施的大门即将打开。此后，一切都在往好的方向迅速发展：

- 越来越多的开发者开始采用**容器作为一种标准构建和运行方式**，
- 业界也意识到，很容易将这种封装方式引入计算集群，通过 Kubernetes 或 Mesos 这样的编排器来调度计算任务 —— 自此，**容器便成为这些调度器最重要的 workload 类型**。

但本文将要说明，容器并非 Kubernetes 最重要、最有价值的地方，Kubernetes 也并非 仅仅是一个更广泛意义上的 workload 调度器 —— 高效地调度不同类型的 workload 只是 Kubernetes 提供的一种重要价值，但并不是它成功的原因。

## 1.2 API 才是核心

K8s 的成功和价值在于，提供了一种标准的编程接口（API），可以用来编写和使用 **软件定义的基础设施服务**（本文所说的“基础设施”，**范围要大于 IAAS**）：

- Specification + Implementation 构成一个完整的 API 框架 —— 用于设计、实现和使用**各种类型和规模的基础设施服务**；
- 这些 API 都基于相同的核心结构和语义：**typed resources watched and reconciled by controllers** （资源按类型划分，控制器监听相应类型的资源，并将其实际 status 校准到 spec 里期望的状态）。

### 1.2.1 K8s 之前：各自造轮子，封装厂商 API 差异

K8s 之前，基础设施基本上是各种不同 API、格式和语义的“云”服务组成的大杂烩：

1. 云厂商只提供了计算实例、块存储、虚拟网络和对象存储等基础构建模块，开发者需要像拼图一样将它们拼出一个相对完整的基础设施方案；
2. 对于其他云厂商，重复过程 1，因为各家的 API、结构和语义并不相同，甚至差异很大。

虽然 Terraform 等工具的出现，提供了一种跨厂商的通用格式，但原始的结构和语义仍然 是五花八门的，—— 针对 AWS 编写的 Terraform descriptor 是无法用到 Azure 的。

### 1.2.2 K8s 面世：标准化、跨厂商的 API、结构和语义

现在再来看 Kubernetes 从一开始就提供的东西：描述各种资源需求的标准 API。例如，

- 描述 pod、container 等**计算需求** 的 API；
- 描述 service、ingress 等**虚拟网络功能** 的 API；
- 描述 volumes 之类的**持久存储** 的 API；
- 甚至还包括 service account 之类的**服务身份** 的 API 等等。

这些 API 是跨公有云/私有云和各家云厂商的，各云厂商会将 Kubernetes 结构和语义 对接到它们各自的原生 API。 因此我们可以说，Kubernetes 提供了一种**管理软件定义基础设施（也就是云）的标准接口**。 或者说，Kubernetes 是一个针对云服务（cloud services）的标准 API 框架。

### 1.2.3 K8s API 扩展：CRD

提供一套跨厂商的标准结构和语义来声明核心基础设施（pod/service/volume/serviceaccount/…）， 是 Kubernetes 成功的基础。在此基础上，它又通过 CRD（Custom Resource Definition）， 将这个结构**扩展到任何/所有基础设施资源**。

- CRD 在 1.7 引入，允许云厂商和开发者自己的服务复用 K8s 的 spec/impl 编程框架。

  有了 CRD，用户不仅能声明 Kubernetes API 预定义的计算、存储、网络服务， 还能声明数据库、task runner、消息总线、数字证书 … 任何云厂商能想到的东西！

- [Operator Framework](https://operatorframework.io/) 以及 [SIG API Machinery](https://github.com/kubernetes/community/tree/master/sig-api-machinery) 等项目的出现，提供了方便地创建和管理这些 CRD 的工具，最小化用户工作量，最大程度实现标准化。

例如，Crossplane 之类的项目，将厂商资源 RDS 数据库、SQS queue 资源映射到 Kubernetes API，就像核心 K8s controller 一样用自己的 controller 来管理网卡、磁盘等自定义资源。 Google、RedHat 等 Kubernetes 发行商也在它们的基础 Kubernetes 发行版中包含越来越多的自定义资源类型。

## 1.3 小结

我们说 Kubernetes 的核心是其 API 框架，但**并不是说这套 API 框架就是完美的**。 事实上，后一点并不是（非常）重要，因为 Kubernetes 模型已经成为一个事实标准： 开发者理解它、大量工具主动与它对接、主流厂商也都已经原生支持它。用户认可度、互操作性 经常比其他方面更能决定一个产品能否成功。

随着 Kubernetes 资源模型越来越广泛的传播，现在已经能够 用一组 Kubernetes 资源来描述一整个**软件定义计算环境**。 就像用 `docker run` 可以启动单个程序一样，用 `kubectl apply -f` 就能部署和运行一个分布式应用， 而无需关心是在私有云还是公有云以及具体哪家云厂商上，Kubernetes 的 API 框架已经屏蔽了这些细节。

因此，Kubernetes 并不是关于容器的，而是关于 API。

# 2 直观类比：K8s 是个数据库，CRD 是一张表，API 是 SQL

在本节中，我们将创建一个名为 `fruit` 的 CRD，它有 `name/sweet/weight` 三个字段， 完整 CRD 如下，

```
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: fruits.example.org        # CRD 名字
spec:
  conversion:
    strategy: None
  group: example.org              # REST API: /apis/<group>/<version>
  names:
    kind: Fruit
    listKind: FruitList
    plural: fruits
    singular: fruit
  scope: Namespaced               # Fruit 资源是区分 namespace 的
  versions:
  - name: v1                      # REST API: /apis/<group>/<version>
    schema:
      openAPIV3Schema:
        properties:
          spec:
            properties:
              comment:            # 字段 1，表示备注
                type: string
              sweet:              # 字段 2，表示甜否
                type: boolean
              weight:             # 字段 3，表示重量
                type: integer
            type: object
        type: object
    served: true                  # 启用这个版本的 API（v1）
    storage: true
    additionalPrinterColumns:     # 可选项，配置了这些 printer columns 之后，
    - jsonPath: .spec.sweet       # 命令行 k get <crd> <cr> 时，能够打印出下面这些字段，
      name: sweet                 # 否则，k8s 默认只打印 CRD 的 NAME 和 AGE
      type: boolean
    - jsonPath: .spec.weight
      name: weight
      type: integer
    - jsonPath: .spec.comment
      name: comment
      type: string
```

后面会解释每个 section 都是什么意思。在此之前，先来做几个（直观而粗糙的）类比。

## 3.1 K8s 是个数据库

像其他数据库技术一样，它有自己的持久存储引擎（etcd），以及构建在存储引擎之上的 一套 API 和语义。这些语义允许用户创建、读取、更新和删除（CURD）数据库中的数据。 下面是一些**概念对应关系**：

| 关系型数据库 | Kubernetes (as a database) | 说明                                                    |
| :----------- | :------------------------- | :------------------------------------------------------ |
| `DATABASE`   | cluster                    | 一套 K8s 集群就是一个 database 【注 1】                 |
| `TABLE`      | `Kind`                     | 每种资源类型对应一个表；分为内置类型和扩展类型 【注 2】 |
| `COLUMN`     | property                   | 表里面的列，可以是 string、boolean 等类型               |
| rows         | resources                  | 表中的一个具体 record                                   |

另外，Kubernetes API 还有**两大特色**：

1. 极其可扩展：声明 CRD 就会自动创建 API；
2. 支持事件驱动。

## 3.2 CRD 是一张表

CRD 和内置的 Pod、Service、NetworkPolicy 一样，不过是数据库的一张表。 例如，前面给出的 `fruit` CRD，有 `name/sweet/weight` 列，以及 “apple”, “banana” 等 entry，

![img](https://arthurchiao.art/assets/img/k8s-is-about-apis/table-vs-crd.png)

用户发现了 k8s 的强大，希望将越来越多的东西（数据）放到 k8s 里面来管理。数据类 型显然多种多样的，不可能全部内置到 k8s 里。因此，一种方式就是允许用户创建自己的 “表”，设置自己的“列” —— 这正是 CRD 的由来。

### 3.2.1 定义表结构（CRD spec）

CRD（及 CR）描述格式可以是 YAML 或 JSON。CRD 的内容可以简单分为三部分：

1. **常规 k8s metadata**：每种 K8s 资源都需要声明的字段，包括 `apiVersion`、`kind`、`metadata.name` 等。

   ```
    apiVersion: apiextensions.k8s.io/v1
    kind: CustomResourceDefinition
    metadata:
      name: fruits.example.org        # CRD 名字
   ```

2. **Table-level 信息**：例如表的名字，最好用小写，方便以后命令行操作；

   ```
    spec:
      conversion:
        strategy: None
      group: example.org              # REST API: /apis/<group>/<version>
      names:
        kind: Fruit
        listKind: FruitList
        plural: fruits
        singular: fruit
      scope: Namespaced               # Fruit 资源是区分 namespace 的
   ```

3. **Column-level 信息**：列名及类型等等，遵循 OpenAPISpecification v3 规范。

   ```
      versions:
      - name: v1                      # REST API: /apis/<group>/<version>
        schema:
          openAPIV3Schema:
            properties:
              spec:
                properties:
                  comment:            # 字段 1，表示备注
                    type: string
                  sweet:              # 字段 2，表示甜否
                    type: boolean
                  weight:             # 字段 3，表示重量
                    type: integer
                type: object
            type: object
        served: true                  # 启用这个版本的 API（v1）
        storage: true
        additionalPrinterColumns:     # 可选项，配置了这些 printer columns 之后，
        - jsonPath: .spec.sweet       # 命令行 k get <crd> <cr> 时，能够打印出下面这些字段，
          name: sweet                 # 否则，k8s 默认只打印 CRD 的 NAME 和 AGE
          type: boolean
        - jsonPath: .spec.weight
          name: weight
          type: integer
        - jsonPath: .spec.comment
          name: comment
          type: string
   ```

## 3.3 API 是 SQL

上一节我们是通过 `kubectl` 命令行来执行 CR 的增删查改，它其实只是一个外壳，内部 调用的是 **Kubernetes 为这个 CRD 自动生成的 API** —— 所以 又回到了本文第一节论述的内容：**K8s 的核心是其 API 框架**。

只要在执行 `kubectl` 命令时**指定一个足够大的 loglevel**，就能看到 背后的具体 API 请求。例如，

```
$ kubectl create -v 10 -f apple-cr.yaml
  ...
  Request Body: {"apiVersion":"example.org/v1","kind":"Fruit",\"spec\":{\"comment\":\"little bit rotten\",\"sweet\":false,\"weight\":100}}\n"},"name":"apple","namespace":"default"},"spec":{"comment":"little bit rotten","sweet":false,"weight":100}}
  curl -k -v -XPOST 'https://127.0.0.1:6443/apis/example.org/v1/namespaces/default/fruits?fieldManager=kubectl-client-side-apply'
  POST https://127.0.0.1:6443/apis/example.org/v1/namespaces/default/fruits?fieldManager=kubectl-client-side-apply 201 Created in 25 milliseconds
  ...
```