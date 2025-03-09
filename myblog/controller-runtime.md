---
title: controller-runtime源码机制
date: 2025-01-23
update: 2025-03-02
comment: false
tags:
  - kubernetes
categories:
  - kubernetes
---

Kubebuilder是一个开发Operator的脚手架，提供代码库封装底层的K8s client-go

实现上基于社区的Controller-Runtime框架，这里就详细探究一下Controller-Runtime的代码实现

# Informer

之前Client-Go部分留了一个悬念，什么是Informer，这个概念在Client-Go中并不明显，而Controller-Runtime中对Informer做出了明确抽象。





# 核心概念

## Controller

用于封装Reconciler的控制器，采用event的方式触发Reconcile

## Reconciler

实际的业务处理方式，将特定资源调谐到期望的模式

## manager

用于管理多个Controller

## Informer

相当于K8s资源的本地缓存，



# 代码

首先看一下KubeBuilder生成的main函数入口

1. 创建一个Manager用于管理所有的Controller
2. 将Manger的Client传给Controller，并且调用SetupWithManager将Controller初始化
3. 启动Manager



```
	mgr, err := ctrl.NewManager(intctrlutil.GetKubeRestConfig(userAgent), ctrl.Options{
		Scheme: scheme,
		Metrics: server.Options{
			BindAddress:   metricsAddr,
			ExtraHandlers: metrics.RuntimeMetric(),
		},
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID: enableLeaderElectionID + ".XXX.io",
		LeaderElectionReleaseOnCancel: true,

		WebhookServer: webhook.NewServer(webhook.Options{
			Port:    9443,
			CertDir: viper.GetString("cert_dir"),
		}),
		Client: client.Options{
			Cache: &client.CacheOptions{
				DisableFor: intctrlutil.GetUncachedObjects(),
			},
		},
	})

if err = (&appscontrollers.XXXReconciler{
    Client:   mgr.GetClient(),
    Scheme:   mgr.GetScheme(),
    Recorder: mgr.GetEventRecorderFor("XXX-controller"),
}).SetupWithManager(mgr); err != nil {
    setupLog.Error(err, "unable to create controller", "controller", "XXX")
    os.Exit(1)
}

if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
}
```

## 初始化

```go
// New returns a new Manager for creating Controllers.
// Note that if ContentType in the given config is not set, "application/vnd.kubernetes.protobuf"
// will be used for all built-in resources of Kubernetes, and "application/json" is for other types
// including all CRD resources.
func New(config *rest.Config, options Options) (Manager, error) {

		cluster, err := cluster.New(config, func(clusterOptions *cluster.Options) {
      clusterOptions.Scheme = options.Scheme
      clusterOptions.MapperProvider = options.MapperProvider
      clusterOptions.Logger = options.Logger
      clusterOptions.NewCache = options.NewCache
      clusterOptions.NewClient = options.NewClient
      clusterOptions.Cache = options.Cache
      clusterOptions.Client = options.Client
      clusterOptions.EventBroadcaster = options.EventBroadcaster //nolint:staticcheck
    })
  
  	return &controllerManager{
      stopProcedureEngaged:          ptr.To(int64(0)),
      cluster:                       cluster,
      runnables:                     runnables,
      errChan:                       errChan,
      recorderProvider:              recorderProvider,
      resourceLock:                  resourceLock,
      metricsServer:                 metricsServer,
      controllerConfig:              options.Controller,
      logger:                        options.Logger,
      elected:                       make(chan struct{}),
      webhookServer:                 options.WebhookServer,
      leaderElectionID:              options.LeaderElectionID,
      leaseDuration:                 *options.LeaseDuration,
      renewDeadline:                 *options.RenewDeadline,
      retryPeriod:                   *options.RetryPeriod,
      healthProbeListener:           healthProbeListener,
      readinessEndpointName:         options.ReadinessEndpointName,
      livenessEndpointName:          options.LivenessEndpointName,
      pprofListener:                 pprofListener,
      gracefulShutdownTimeout:       *options.GracefulShutdownTimeout,
      internalProceduresStop:        make(chan struct{}),
      leaderElectionStopped:         make(chan struct{}),
      leaderElectionReleaseOnCancel: options.LeaderElectionReleaseOnCancel,
    }, nil

}
```

重要内容的初始化在cluster.New(）

### cluster.New(）

这里主要初始化了Client和Cache

```
cache, err := options.NewCache(config, cacheOpts)

clientWriter, err := options.NewClient(config, clientOpts)

clientReader, err := client.New(config, client.Options{
		HTTPClient: options.HTTPClient,
		Scheme:     options.Scheme,
		Mapper:     mapper,
})

recorderProvider, err := options.newRecorderProvider(config, options.HTTPClient, options.Scheme, options.Logger.WithName("events"), options.makeBroadcaster)
```

Cache的接口中包含了Informer，Cache正是基于Informer机制与K8s机制保持同步，

```
// Cache knows how to load Kubernetes objects, fetch informers to request
// to receive events for Kubernetes objects (at a low-level),
// and add indices to fields on the objects stored in the cache.
type Cache interface {
    // Reader acts as a client to objects stored in the cache.
    client.Reader

    // Informers loads informers and adds field indices.
    Informers
}
```

Client的接口定义：

```
// Client knows how to perform CRUD operations on Kubernetes objects.
type Client interface {
    Reader
    Writer
    StatusClient
    SubResourceClientConstructor

    // Scheme returns the scheme this client is using.
    Scheme() *runtime.Scheme
    // RESTMapper returns the rest this client is using.
    RESTMapper() meta.RESTMapper
    // GroupVersionKindFor returns the GroupVersionKind for the given object.
    GroupVersionKindFor(obj runtime.Object) (schema.GroupVersionKind, error)
    // IsObjectNamespaced returns true if the GroupVersionKind of the object is namespaced.
    IsObjectNamespaced(obj runtime.Object) (bool, error)
}
```

## SetupWithManager

SetupWithManager用于将具体的Controller注册到Manager当中

NewControllerManagedBy创建了一个Builder对象

```go
func (r *XXXReconciler) SetupWithManager(mgr ctrl.Manager) error {
    return intctrlutil.NewControllerManagedBy(mgr).
       For(&appsv1.XXX{}).
  		 Own().
  		 Watches().
       Complete(r)
}

func NewControllerManagedBy(mgr manager.Manager) *builder.Builder {
	b := ctrl.NewControllerManagedBy(mgr).
		WithEventFilter(predicate.NewPredicateFuncs(namespacePredicateFilter))
	return b
}


```

builder的定义：

```
type Builder = TypedBuilder[reconcile.Request]

// TypedBuilder builds a Controller. The request is the request type
// that is passed to the workqueue and then to the Reconciler.
// The workqueue de-duplicates identical requests.
type TypedBuilder[request comparable] struct {
	forInput         ForInput
	ownsInput        []OwnsInput
	rawSources       []source.TypedSource[request]
	watchesInput     []WatchesInput[request]
	mgr              manager.Manager
	globalPredicates []predicate.Predicate
	ctrl             controller.TypedController[request]
	ctrlOptions      controller.TypedOptions[request]
	name             string
	newController    func(name string, mgr manager.Manager, options controller.TypedOptions[request]) (controller.TypedController[request], error)
}
```

builder可以通过调用for、own、watches来决定自身关心哪些资源

forInput:指定Controller的主要管理资源（例如 `Deployment`、`Pod` 等），控制器会直接监听该类型资源的事件，并触发Reconcile

ownsInput：指定控制器创建的并拥有所有权的子资源类型（例如 `Deployment` 控制器拥有 `ReplicaSet`）。当子资源变化时，**自动触发关联父资源的调和**。

watchesInput：监听与主资源**逻辑相关但无明确所有权关系**的资源（例如 `ConfigMap`、`Secret` 等）。需要手动定义事件到调和请求的映射逻辑。

### Complete

#### 调用栈

```
Complete-> Build
|- doController
|  |- ctrlOptions.MaxConcurrentReconciles = concurrency
|  |- ctrlOptions.CacheSyncTimeout = globalOpts.CacheSyncTimeout
|  |- controller.NewTyped[request]
|  |  |- NewTypedUnmanaged
|  |  |- mgr.Add(c)
|  |- blder.newController
|  |  |- NewTyped[request] -> NewTypedUnmanaged
|  |  |  |- workqueue.DefaultTypedControllerRateLimiter[request]()
|  |  |  |- NewTypedRateLimitingQueueWithConfig
|  |  |- mgr.Add() -> cm.add(r) -> cm.runnables.Add(r)
|  |  |  |- r.startQueue = append(r.startQueue, readyRunnable)
|  |  |  |- r.ch <- readyRunnable
|- doWatch
|  |- blder.ctrl.Watch(src) // wathch forInput
|  |- for src in rawSources -> blder.ctrl.Watch(src) //watch ownsInput
|  |- for w in watchesInput -> blder.ctrl.Watch
|  |  |- src.Start -> is.Informer.AddEventHandler —> HandlerFuncs()
|  |  |  |- OnAdd
|  |  |  |- OnUpdate
|  |  |  |- OnDelete
```

创建controller的实现逻辑

```
// Build builds the Application Controller and returns the Controller it created.
func (blder *TypedBuilder[request]) Build(r reconcile.TypedReconciler[request]) (controller.TypedController[request], error) {

    // Set the ControllerManagedBy
    if err := blder.doController(r); err != nil {
       return nil, err
    }

    // Set the Watch
    if err := blder.doWatch(); err != nil {
       return nil, err
    }

    return blder.ctrl, nil
}
```

### newController

关键是newController，会调用NewTyped -> NewTypedUnmanaged这里会创建实际的Controller并添加到Manager当中。

```
	if blder.newController == nil {
		blder.newController = controller.NewTyped[request]
	}

	// Build the controller and return.
	blder.ctrl, err = blder.newController(controllerName, blder.mgr, ctrlOptions)
```

这里的Controller如果没有指定Queue存储的话，默认使用RateLimitingQueue

RateLimiter默认会采用ItemExponentialFailureRateLimiter，也就是失败次数越多，限制会指数级增长

```
if options.RateLimiter == nil {
    if ptr.Deref(options.UsePriorityQueue, false) {
       options.RateLimiter = workqueue.NewTypedItemExponentialFailureRateLimiter[request](5*time.Millisecond, 1000*time.Second)
    } else {
       options.RateLimiter = workqueue.DefaultTypedControllerRateLimiter[request]()
    }
}

if options.NewQueue == nil {
    options.NewQueue = func(controllerName string, rateLimiter workqueue.TypedRateLimiter[request]) workqueue.TypedRateLimitingInterface[request] {
       if ptr.Deref(options.UsePriorityQueue, false) {
          return priorityqueue.New(controllerName, func(o *priorityqueue.Opts[request]) {
             o.Log = options.Logger.WithValues("controller", controllerName)
             o.RateLimiter = rateLimiter
          })
       }
       return workqueue.NewTypedRateLimitingQueueWithConfig(rateLimiter, workqueue.TypedRateLimitingQueueConfig[request]{
          Name: controllerName,
       })
    }
}
```

### Watch

Watch机制就是通过Informer来实现的

```go
func (is *Informer) Start(ctx context.Context, queue workqueue.TypedRateLimitingInterface[reconcile.Request]) error {
    _, err := is.Informer.AddEventHandler(internal.NewEventHandler(ctx, queue, is.Handler, is.Predicates).HandlerFuncs())
    if err != nil {
       return err
    }
    return nil
}
```

很明显，Controller-Runtime是通过Informer来实现监控资源变化的功能并注册了Handler函数

以Add函数为例，把Request添加到了RateLimitingQueue当中

```go
// OnAdd creates CreateEvent and calls Create on EventHandler.
func (e *EventHandler[object, request]) OnAdd(obj interface{}) {
    c := event.TypedCreateEvent[object]{}

    // Pull Object out of the object
    if o, ok := obj.(object); ok {
       c.Object = o
    } else {
       log.Error(nil, "OnAdd missing Object",
          "object", obj, "type", fmt.Sprintf("%T", obj))
       return
    }

    for _, p := range e.predicates {
       if !p.Create(c) {
          return
       }
    }

    // Invoke create handler
    ctx, cancel := context.WithCancel(e.ctx)
    defer cancel()
    e.handler.Create(ctx, c, e.queue)
}

// Create implements EventHandler.
func (e *TypedEnqueueRequestForObject[T]) Create(ctx context.Context, evt event.TypedCreateEvent[T], q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
	if isNil(evt.Object) {
		enqueueLog.Error(nil, "CreateEvent received with no metadata", "event", evt)
		return
	}
	q.Add(reconcile.Request{NamespacedName: types.NamespacedName{
		Name:      evt.Object.GetName(),
		Namespace: evt.Object.GetNamespace(),
	}})
}
```

## Manager.start()

到此为止，就完成了大部分初始化的逻辑

### 调用栈

```
cm.add(cm.cluster) //将Cluster添加到runable，关键是Informer cache
cm.runnables.HTTPServers.Add(cm.metricsServer, nil) //添加Metrics
cm.addHealthProbeServer() //探针
cm.addPprofServer() //prof性能指标
cm.runnables.HTTPServers.Start(logCtx)
cm.runnables.Webhooks.Start(cm.internalCtx) // 如果有webHook就启动
cm.runnables.Caches.Start(cm.internalCtx)  // 启动Informer cache
cm.runnables.Others.Start(cm.internalCtx)  // 包括自定义Controller
|- r.startOnce.Do -> go r.reconcile()
if leaderElector != nil -> go leaderElector.Run(ctx) // 实例选主
else -> go cm.startLeaderElectionRunnables()
```

这里就将所有需要的组件全部启动了，包括关键的Informer和所有的Controller



## Reconciler的调用

所有注册到Manager的Controller都通过cm.runnables.Others.Start启动了

那么Controller中的Reconciler是如何被调用的呢？这里就来探究一下Reconcile是如何被触发的

### 调用栈

```
runnableGroup.start
|- r.startOnce.Do -> go r.reconcile()
|  |- for runnable in r.ch 
|  |  |- // check r.stopped
|  |  |- go func(rn *readyRunnable) -> rn.Check(检查外部依赖并通知) && rn.Start
|  |  |  |- c.NewQueue 
|  |  |  |- for watch in c.startWatches
|  |  |  |  |- go watch.Start(ctx, c.Queue)
|  |  |  |  |  |- is.Informer.AddEventHandler
|  |  |  |  |  |  |- e.OnAdd，e.OnUpdate，e.OnDelete
|  |  |  |- wg.Add(c.MaxConcurrentReconciles)
|  |  |  |- for i in c.MaxConcurrentReconciles -> go for c.processNextWorkItem(ctx){}

for processNextWorkItem
|- obj, shutdown := c.Queue.Get()
|- c.reconcileHandler(ctx, obj)
|* |- result, err := c.Reconcile(ctx, req) -> c.Do.Reconcile(ctx, req)
|  |- switch 
|  |  case err != nil -> c.Queue.AddRateLimited(req) // 限速重试
|  |  case result.RequeueAfter -> c.Queue.Forget(req);c.Queue.AddAfter(req, result.RequeueAfter) // 清除重试计数 (Forget) + 延时入队 (AddAfter)
|  |  default -> c.Queue.Forget(req)

```

c.Do.Reconcile就是通过SetupWithManager注册的Reconciler，从这里就进入了用户的自定义逻辑

那么Reconciler的每一次调谐是如何触发的呢？这就要回到c.startWatches了

1. 在初始化的时候，c.startWatches添加了所有for、own、watches的object

2. 在start这里会依次调用watch.start这里会启动Informer并注册Handler函数，
3. 之后就是Informer监听到事件，以Add为例，当监听到Add事件时，经过predicates的处理，之后会调用e.handler.Create，这里是之前讲过的watch逻辑，在Queue中add一个request
4. processNextWorkItem会不断重复，其中会通过c.Queue.Get()取出事件进而触发调谐

```
func (e *EventHandler[object, request]) OnAdd(obj interface{}) {
		......
    e.handler.Create(ctx, c, e.queue)
}

func (e *TypedEnqueueRequestForObject[T]) Create(ctx context.Context, evt event.TypedCreateEvent[T], q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
		......
    q.Add(reconcile.Request{NamespacedName: types.NamespacedName{
      Name:      evt.Object.GetName(),
      Namespace: evt.Object.GetNamespace(),
    }})
}
```
