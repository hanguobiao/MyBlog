# Kubeblocks 源码笔记--启动流程

# 部署方式

Kubeblocks以Deployment的形式部署，本质上是一系列CRD Controller的集合。另外还有dataprotection的Deployment用于数据保护。(dataprotection会在后面详细介绍，前期只需要关注Kubeblocks)

## 启动参数

Kubeblocks Deployment中需要关注的只有主容器，镜像中的启动命令为`ENTRYPOINT ["/manager"]`在加上

定义的参数args就是完整的启动命令

```
- args:                                                                                                                          
  - --health-probe-bind-address=:8081                                                                                            
  - --metrics-bind-address=:8080                                                                                                 
  - --leader-elect                                                                                                               
  - --zap-devel=false                                                                                                            
  - --zap-time-encoding=iso8601                                                                                                  
  - --zap-encoder=console                                                                                                        
  - --apps=true                                                                                                                  
  - --workloads=true                                                                                                             
  - --operations=true                                                                                                            
  - --extensions=true                                                                                                            
  - --experimental=false                                                                                                         
  - --trace=false                                                                                                                
  - --user-agent=kubeblocks  
```

接下来看一下代码的实现逻辑

# 代码结构

项目基于KubeBuilder框架开发，核心是根据数据库实践抽象出的CRD，即APIs。以及对应这一套抽象出的API的实现，即Controllers。Kubeblocks本质上是多个Controller的合集，

项目结构中关键为apis、cmd、config、controllers、deploy、pkg

## apis && config

apis中是所有CRD的定义，也是是KubeBuilder的GO结构体，通过KubeBuilder生成最终的CRD放在config文件夹的crd中，可以通过make generate && make manifests 生成所有需要的内容。

## cmd

cmd是可执行文件的入口，可以看出Kubeblocks有哪些组件

dataprotection：是备份相关的内容，还有保护数据的作用？部署形式为部署Kubeblocks时，同时部署一个dataprotection的Deployment

helmhook：

kbagent: 合并自之前版本的configmanger和lorry，兼顾配置管理，和命令通道的作用

manager：就是Kubeblocks的主程序

reloader: 暂时不详



### Controller

<img src="/Users/hanguobiao/Library/Application Support/typora-user-images/image-20241015120709915.png" alt="image-20241015120709915" style="zoom:50%;" />

api的具体实现逻辑，包含调谐本身CRD的Controller和处理交互逻辑的Transformer。

可以与上面的api对应，其中的workloads是对于底层Statefulset的扩展

# 启动流程

## 调用栈

```
main   // cmd/manager/main.go
|- viper.ReadInConfig()
|- viper.WatchConfig()
|- mgr := ctrl.NewManager
|- multicluster.Setup
|- InitHostPortManager
|- if viper.GetBool(appsFlagKey.viperName())
|  |- (&appscontrollers.ClusterDefinitionReconciler{}).SetupWithManager(mgr)
|- ......（初始化所有CRD Controller）
|- (&appsv1.ClusterDefinition{}).SetupWebhookWithManager(mgr)
|- ......（初始化所有Webhook）
|-  multiClusterMgr.Bind(mgr)
|- mgr.Start(ctrl.SetupSignalHandler())
```

可以看到启动流程包括

- 基于Viper的配置管理
- 跨K8s集群的
- 所有CRD Manager的启动
- Webhook的启动

同时根据启动时viper参数可以将CRD划分为下面的几类（实际上目前并没有排列组合的用法，往往是全部启动）

## CRD类型

### apps

是Kubeblocks最核心的CRD，可以理解为是对数据库架构和组件的抽象

ClusterDefinition：对于数据库topology结构的抽象， 即数据库有哪些组件，也可以定义组件的初始化顺序（非必须）

ShardingDefinition：针对有Sharding 架构的数据的Sharding定义

ComponentDefinition：核心CRD，针对

ComponentVersion

SidecarDefinition

Cluster

Component

ServiceDescriptor

Event

### workloads

InstanceSet

### operations

OpsDefinition
OpsRequest

### extensions

Addon

### experimental

NodeCountScaler

### trace

ReconciliationTrace

### parameters

ConfigConstraint
Configuration
Reconfigure
ParametersDefinition
ParameterDrivenConfigRender

## MultiCluster（alpha）

Kubeblocks支持多K8s集群混布，即将同一个数据库集群的POD打散部署到不同的K8s集群当中。这一机制是依赖于CIlium的ClusterMesh机制来实现跨K8s集群的Service路由

ClusterMesh可以参考：

Kubeblocks在启动时创建了多K8s的Context，保存了访问各个K8s的Client以及Controller-runtiem的Cache

```
func Setup(scheme *runtime.Scheme, cfg *rest.Config, cli client.Client, kubeConfig, contexts, disabledContexts string) (Manager, error) {
		mcc, err := newClientNCache(scheme, kubeConfig, contexts, disabledContexts)
		for k, c := range mcc {
      if isSameContextWithControl(cfg, c) {
        cc := mcc[k]
        if isUnavailableClient(cc.client) {
          return nil, fmt.Errorf("control cluster %s is disabled", cc.context)
        }
        // reset the cache and use default cli of control cluster
        cc.cache = nil
        cc.client = cli
        mcc[k] = cc
      }
    }

    clients := func() map[string]client.Client {
      m := make(map[string]client.Client)
      for _, c := range mcc {
        m[c.context] = c.client
      }
      return m
    }
    caches := func() map[string]cache.Cache {
      m := make(map[string]cache.Cache)
      for _, c := range mcc {
        m[c.context] = c.cache
      }
      return m
    }
    setupScheme(scheme)
    return &manager{
      cli:    NewClient(cli, clients()),
      caches: caches(),
    }, nil
}
```

之后调用的multiClusterMgr.Bind(mgr)会将创建的多K8s集群的Cache与Manager绑定

```
func (m *manager) Bind(mgr ctrl.Manager) error {
    for k, c := range m.caches {
       if c != nil {
          if err := mgr.Add(m.caches[k]); err != nil {
             return fmt.Errorf("failed to bind cache to Manager: %s", err.Error())
          }
       }
    }
    return nil
}
```

# 

## ControllerManager启动

这里的SetupWithManager函数就是KubeBuilder框架定义的方法

最后启动mgr，就完成了初始化

```
mgr.Start(ctrl.SetupSignalHandler())
```



# API设计

上面介绍Kubeblocks有哪些API，这里对API之间的关系做简要介绍，方面后面介绍具体的代码实现



# 代码解析

# cluster

### 调用栈

```
ClusterReconciler.Reconcile
|- planBuilder := newClusterPlanBuilder()
|- planBuilder.Init()
|- plan := planBuilder.AddTransformer(&clusterDeletionTransformer{}...).Build()
|- plan.Execute()
```

Cluster指代了具体需要创建的数据库集群，所以当创建CLuster的CR时，KubeBlocks会实际生成具体的数据库Workload。

由于创建数据库以及调谐过程中涉及的Kubernetes资源和CRD繁多，这些资源又存在着依赖关系。Kubeblocks通过dag的方式来处理这种依赖关系，而plan就是对DAG的包装。

之后的Component的Reconcile流程也是使用的类似的方式

这部分代码的核心在Cluster_Controller.go中：

```
planBuilder := newClusterPlanBuilder(reqCtx, r.Client)
if err := planBuilder.Init(); err != nil {
  return intctrlutil.CheckedRequeueWithError(err, reqCtx.Log, "")
}

......

// Build stage
// what you should do in most cases is writing your transformer.
//
// here are the how-to tips:
// 1. one transformer for one scenario
// 2. try not to modify the current transformers, make a new one
// 3. transformers are independent with each-other, with some exceptions.
//    Which means transformers' order is not important in most cases.
//    If you don't know where to put your transformer, append it to the end and that would be ok.
// 4. don't use client.Client for object write, use client.ReadonlyClient for object read.
//    If you do need to create/update/delete object, make your intent operation a lifecycleVertex and put it into the DAG.
//
// TODO: transformers are vertices, theirs' dependencies are edges, make plan Build stage a DAG.
plan, errBuild := planBuilder.
  AddTransformer(
    // handle cluster halt first
    &clusterHaltTransformer{},
    // handle cluster deletion
    &clusterDeletionTransformer{},
    // check is recovering from halted cluster
    &clusterHaltRecoveryTransformer{},
    // update finalizer and cd&cv labels
    &clusterAssureMetaTransformer{},
    // validate cd & cv's existence and availability
    &clusterLoadRefResourcesTransformer{},
    // handle cluster shared account
    &clusterSharedAccountTransformer{},
    // normalize the cluster and component API
    &ClusterAPINormalizationTransformer{},
    // placement replicas across data-plane k8s clusters
    &clusterPlacementTransformer{multiClusterMgr: r.MultiClusterMgr},
    // handle cluster services
    &clusterServiceTransformer{},
    // handle the restore for cluster
    &clusterRestoreTransformer{},
    // create all cluster components objects
    &clusterComponentTransformer{},
    // update cluster components' status
    &clusterComponentStatusTransformer{},
    // create default cluster connection credential secret object
    &clusterConnCredentialTransformer{},
    // build backuppolicy and backupschedule from backupPolicyTemplate
    &clusterBackupPolicyTransformer{},
    // add our finalizer to all objects
    &clusterOwnershipTransformer{},
    // make all workload objects depending on credential secret
    &secretTransformer{},
    // update cluster status
    &clusterStatusTransformer{},
    // always safe to put your transformer below
  ).
  Build()
	
// Execute stage
// errBuild not nil means build stage partial success or validation error
// execute the plan first, delay error handling
if errExec := plan.Execute(); errExec != nil {
  return requeueError(errExec)
}
```

### planbuilder

首先初始化planBuilder，将Transformer步骤加入到planBuilder中，最后会执行plan来开始完整的调谐过程。

planbuilder的接口如下所示

```go
// PlanBuilder builds a Plan by applying a group of Transformer to an empty DAG.
type PlanBuilder interface {
	// Init loads the primary object to be reconciled, and does meta initialization
	Init() error

	// AddTransformer adds transformers to the builder in sequence order.
	// And the transformers will be executed in the add order.
	AddTransformer(transformer ...Transformer) PlanBuilder

	// AddParallelTransformer adds transformers to the builder.
	// And the transformers will be executed in parallel.
	AddParallelTransformer(transformer ...Transformer) PlanBuilder

	// Build runs all the transformers added by AddTransformer and/or AddParallelTransformer.
	Build() (Plan, error)
}

```

其中的Transformer将CRD以及Kubernetes资源之间的交互逻辑放到Transformer中，这样CRD的Controller可以更加专注地处理状态等自身的调谐，解耦了CRD自身状态的调谐和实现逻辑。

抽象出的接口具体由clusterPlanBuilder执行

```go
// clusterPlanBuilder a graph.PlanBuilder implementation for Cluster reconciliation
type clusterPlanBuilder struct {
	req          ctrl.Request
	cli          client.Client
	transCtx     *clusterTransformContext
	transformers graph.TransformerChain
}
```

其中Transformers存储着所有的Transformer，也就是init后通过调用AddTransformer添加的Transformer。

transCtx存储着所有需要传递的信息，具体有

```
// clusterTransformContext a graph.TransformContext implementation for Cluster reconciliation
type clusterTransformContext struct {
	context.Context
	Client client.Reader
	record.EventRecorder
	logr.Logger
	Cluster       *appsv1.Cluster
	OrigCluster   *appsv1.Cluster
	ClusterDef    *appsv1.ClusterDefinition
	ComponentDefs map[string]*appsv1.ComponentDefinition
	// ComponentSpecs includes all cluster component specs generated from ComponentSpecs and ShardingSpecs
	ComponentSpecs []*appsv1.ClusterComponentSpec
	// ShardingComponentSpecs includes all sharding component specs generated from ShardingSpecs
	ShardingComponentSpecs map[string][]*appsv1.ClusterComponentSpec
	// Annotations to be added to components, mapping with ComponentSpecs.
	Annotations map[string]map[string]string
}

```

可以分为两部分，一部分是共用的组件包括日志、event还有k8s client；另一部分是从当前cluster中抽取出来的Component信息。每个planbuilder负责当前cluster的调谐过程。

### DAG

Build函数以流式编程的方式紧跟在AddTransformer后面。核心的DAG就是在这里初始化，并生成最终的plan。

首先看dag的结构，由顶点和边组成。顶点可以是任意对象一般是各种资源对象。Edge标明了顶点之间的关系，本质上也是Vertex（interface{}）

```go
type DAG struct {
	vertices map[Vertex]Vertex
	edges    map[Edge]Edge
}

type Vertex interface{}

type Edge interface {
	From() Vertex
	To() Vertex
}

type realEdge struct {
	F, T Vertex
}

```

首先是针对DAG结构的操作

```go
// AddVertex puts 'v' into 'd'
func (d *DAG) AddVertex(v Vertex) bool {
	if v == nil {
		return false
	}
	d.vertices[v] = v
	return true
}

// RemoveVertex deletes 'v' from 'd'
// the in&out edges are also deleted
func (d *DAG) RemoveVertex(v Vertex) bool {
	if v == nil {
		return true
	}
	for k := range d.edges {
		if k.From() == v || k.To() == v {
			delete(d.edges, k)
		}
	}
	delete(d.vertices, v)
	return true
}

// AddEdge puts edge 'e' into 'd'
func (d *DAG) AddEdge(e Edge) bool {
	if e.From() == nil || e.To() == nil {
		return false
	}
	for k := range d.edges {
		if k.From() == e.From() && k.To() == e.To() {
			return true
		}
	}
	d.edges[e] = e
	return true
}

// RemoveEdge deletes edge 'e'
func (d *DAG) RemoveEdge(e Edge) bool {
	for k := range d.edges {
		if k.From() == e.From() && k.To() == e.To() {
			delete(d.edges, k)
		}
	}
	return true
}


// Connect vertex 'from' to 'to' by a new edge if not exist
func (d *DAG) Connect(from, to Vertex) bool {
	if from == nil || to == nil {
		return false
	}
	for k := range d.edges {
		if k.From() == from && k.To() == to {
			return true
		}
	}
	edge := RealEdge(from, to)
	d.edges[edge] = edge
	return true
}

// AddConnect add 'to' to the DAG 'd' and connect 'from' to 'to'
func (d *DAG) AddConnect(from, to Vertex) bool {
	if !d.AddVertex(to) {
		return false
	}
	return d.Connect(from, to)
}


// AddConnectRoot add 'v' to the DAG 'd' and connect root to 'v'
func (d *DAG) AddConnectRoot(v Vertex) bool {
	root := d.Root()
	if root == nil {
		return false
	}
	return d.AddConnect(root, v)
}
```

以上是针对dag结构上的操作，这里还提供了针对dag的遍历操作

```go
// WalkTopoOrder walks the DAG 'd' in topology order
func (d *DAG) WalkTopoOrder(walkFunc WalkFunc, less func(v1, v2 Vertex) bool) error {
	if err := d.validate(); err != nil {
		return err
	}
	orders := d.topologicalOrder(false, less)
	for _, v := range orders {
		if err := walkFunc(v); err != nil {
			return err
		}
	}
	return nil
}

// WalkReverseTopoOrder walks the DAG 'd' in reverse topology order
func (d *DAG) WalkReverseTopoOrder(walkFunc WalkFunc, less func(v1, v2 Vertex) bool) error {
	if err := d.validate(); err != nil {
		return err
	}
	orders := d.topologicalOrder(true, less)
	for _, v := range orders {
		if err := walkFunc(v); err != nil {
			return err
		}
	}
	return nil
}

// WalkBFS walks the DAG 'd' in breadth-first order
func (d *DAG) WalkBFS(walkFunc WalkFunc) error {
	return d.bfs(walkFunc, nil)
}

```

具体的dfs操作就是通过队列实现的，以及校验dag正确性的

```go
func (d *DAG) bfs(walkFunc WalkFunc, less func(v1, v2 Vertex) bool) error {
    if err := d.validate(); err != nil {
       return err
    }
    queue := make([]Vertex, 0)
    walked := make(map[Vertex]bool, len(d.Vertices()))

    root := d.Root()
    queue = append(queue, root)
    for len(queue) > 0 {
       var walkErr error
       for _, vertex := range queue {
          if err := walkFunc(vertex); err != nil {
             walkErr = err
          }
       }
       if walkErr != nil {
          return walkErr
       }

       nextStep := make([]Vertex, 0)
       for _, vertex := range queue {
          adjs := d.outAdj(vertex)
          if less != nil {
             sort.SliceStable(adjs, func(i, j int) bool {
                return less(adjs[i], adjs[j])
             })
          }
          for _, adj := range adjs {
             if !walked[adj] {
                nextStep = append(nextStep, adj)
                walked[adj] = true
             }
          }
       }
       queue = nextStep
    }

    return nil
}

// validate 'd' has single Root and has no cycles
func (d *DAG) validate() error {
	// single Root validation
	root := d.Root()
	if root == nil {
		return errors.New("no single Root found")
	}

	// self-cycle validation
	for e := range d.edges {
		if e.From() == e.To() {
			return fmt.Errorf("self-cycle found: %v", e.From())
		}
	}

	// cycle validation
	// use a DFS func to find cycles
	walked := make(map[Vertex]bool)
	marked := make(map[Vertex]bool)
	var walk func(v Vertex) error
	walk = func(v Vertex) error {
		if walked[v] {
			return nil
		}
		if marked[v] {
			return errors.New("cycle found")
		}

		marked[v] = true
		adjacent := d.outAdj(v)
		for _, vertex := range adjacent {
			if err := walk(vertex); err != nil {
				return err
			}
		}
		marked[v] = false
		walked[v] = true
		return nil
	}
	for v := range d.vertices {
		if err := walk(v); err != nil {
			return err
		}
	}
	return nil
}
```

还有获取某一Vertex关联的Vertex的函数

```
// outAdj returns all adjacent vertices that v points to
func (d *DAG) outAdj(v Vertex) []Vertex {
	vertices := make([]Vertex, 0)
	for e := range d.edges {
		if e.From() == v {
			vertices = append(vertices, e.To())
		}
	}
	return vertices
}

// inAdj returns all adjacent vertices that point to v
func (d *DAG) inAdj(v Vertex) []Vertex {
	vertices := make([]Vertex, 0)
	for e := range d.edges {
		if e.To() == v {
			vertices = append(vertices, e.From())
		}
	}
	return vertices
}
```



# DAG执行

## build

build中会生成上面的DAG结构并通过Transformer对DAG进行处理，生成最终需要呈现的资源的DAG结构，具体的Transformer之后再进行介绍，transformers.ApplyTo这里利用之前添加的所有Transformer对dag进行处理。

```go
err = c.transformers.ApplyTo(c.transCtx, dag)
```

Build函数会返回clusterPlan的对象，这就是本次Cluster需要执行的计划，之后会执行`plan.Execute();`对最终生成的DAG进行处理。

```go
// construct execution plan
plan := &clusterPlan{
    dag:      dag,
    walkFunc: c.defaultWalkFuncWithLogging,
    cli:      c.cli,
    transCtx: c.transCtx,
}
```

其中的walkFunc处理逻辑目前只有一种

```go
func (c *clusterPlanBuilder) defaultWalkFunc(vertex graph.Vertex) error {
    node, ok := vertex.(*model.ObjectVertex)
    if !ok {
       return fmt.Errorf("wrong vertex type %v", vertex)
    }
    if node.Action == nil {
       return fmt.Errorf("node action can't be nil")
    }

    // cluster object has more business to do, handle them here
    if _, ok = node.Obj.(*appsv1.Cluster); ok {
       if err := c.reconcileCluster(node); err != nil {
          return err
       }
    }
    return c.reconcileObject(node)
}
```

根据node被反射出来的类型进行不同的处理（而不再是之前将不同操作类型的对象统一在一起，一起操作）

```go
func (c *clusterPlanBuilder) reconcileCluster(node *model.ObjectVertex) error {
	cluster := node.Obj.(*appsv1.Cluster).DeepCopy()
	origCluster := node.OriObj.(*appsv1.Cluster)
	switch *node.Action {
	// cluster.meta and cluster.spec might change
	case model.STATUS:
		if !reflect.DeepEqual(cluster.ObjectMeta, origCluster.ObjectMeta) || !reflect.DeepEqual(cluster.Spec, origCluster.Spec) {
			patch := client.MergeFrom(origCluster.DeepCopy())
			if err := c.cli.Patch(c.transCtx.Context, cluster, patch); err != nil {
				return err
			}
		}
	case model.CREATE, model.UPDATE:
		return fmt.Errorf("cluster can't be created or updated: %s", cluster.Name)
	}
	return nil
}

func (c *clusterPlanBuilder) reconcileObject(node *model.ObjectVertex) error {
	ctx := c.transCtx.Context
	switch *node.Action {
	case model.CREATE:
		return c.reconcileCreateObject(ctx, node)
	case model.UPDATE:
		return c.reconcileUpdateObject(ctx, node)
	case model.PATCH:
		return c.reconcilePatchObject(ctx, node)
	case model.DELETE:
		return c.reconcileDeleteObject(ctx, node)
	case model.STATUS:
		return c.reconcileStatusObject(ctx, node)
	case model.NOOP:
		return c.reconcileNoopObject(ctx, node)
	}
	return nil
}
```

以Create为例，实际上就是通过Cli执行相应的操作

```
func (c *clusterPlanBuilder) reconcileCreateObject(ctx context.Context, node *model.ObjectVertex) error {
    err := c.cli.Create(ctx, node.Obj, appsutil.ClientOption(node))
    if err != nil && !apierrors.IsAlreadyExists(err) {
       return err
    }
    return nil
}
```

而最后的execate就是执行dag.WalkReverseTopoOrder，通过clusterPlan绑定的walkFunc来遍历经过DAG排序后的节点

```
func (p *clusterPlan) Execute() error {
	err := p.dag.WalkReverseTopoOrder(p.walkFunc, nil)
	if err != nil {
		if hErr := p.handlePlanExecutionError(err); hErr != nil {
			return hErr
		}
	}
	return err
}
```

