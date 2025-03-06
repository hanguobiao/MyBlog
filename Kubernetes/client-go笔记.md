# Client-go笔记

# Informer机制

Client-go中最重要的组件爱你就是informer。通过HTTP API可以查询集群中所有的资源对象并watch其变化，但是大量的HTTP调用会对API Server造成较大负荷，网络调用可能存在较大的延迟。Informer可以用于监视API Server中的资源并将它们的当前状态缓存到本地，可以

- 减少 API 服务器的负载：通过在本地缓存资源信息，Informer 减少了需要向 API 服务器发出的请求数量。这可以防止由于 API 服务器过载而影响整个集群的性能。
- 提高应用程序性能：使用缓存的数据，客户端应用程序可以快速访问资源信息，而无需等待 API 服务器响应。这可以提高应用程序性能并减少延迟。
- 简化代码：Informer 提供了一种更简单、更流畅的方式来监视 Kubernetes 中的资源更改。客户端应用程序可以使用现有的 Informer 库来处理这些任务，而无需编写复杂的代码来管理与 API 服务器的连接并处理更新。
- 更高的可靠性：由于 Informer 在本地缓存数据，因此即使 API 服务器不可用或存在问题，它们也可以继续工作。这可以确保客户端应用程序即使在底层 Kubernetes 基础结构出现问题时也能保持功能。

# Informer架构

![img](https://infracreate.feishu.cn/space/api/box/stream/download/asynccode/?code=NDVlZDU3ZTRlZDY4Y2ZjYzNhNTdkNjVkZjIxOTQyMGVfRjZpOEg0a0xLT2syZzBuS2Y4eDJJMktxcTZyV1FCbG5fVG9rZW46VmVFY2JMWWx2b2g5czh4WHJBWWN5aEkwbmFoXzE3MjcwMDA4MDM6MTcyNzAwNDQwM19WNA)

上半部分是Client-go的实现，下面是自己的Custom Controller实现。实现Custom Controller时，一般在Informer中配置回调函数Callbacks来实现Informer和Custom Controller上下两部分的通讯。

![img](https://infracreate.feishu.cn/space/api/box/stream/download/asynccode/?code=OGIwOTkzZWQ3MGU1NzgxMWIwYmFiOGU4MzA0YjdjNDJfZGMxN3hUTHE2dG0zREpGOU9IZk1NZmVxdXVqeTdBaEdfVG9rZW46WFlvcmI5b2N5b3dUVFN4OXd0MmNzMDgzbjlmXzE3MjcwMDA4MDM6MTcyNzAwNDQwM19WNA)

# 源码分析

```Go
// create the pod watcher
podListWatcher := cache.NewListWatchFromClient(clientset.CoreV1().RESTClient(), "pods", v1.NamespaceDefault, fields.Everything())

// create the workqueue
queue := workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())

// 创建 indexer 和 informer
indexer, informer := cache.NewIndexerInformer(podListWatcher, &v1.Pod{}, 0, cache.ResourceEventHandlerFuncs{}

controller := NewController(queue, indexer, informer)

stop := make(chan struct{})
defer close(stop)
go controller.Run(1, stop)
```

官方案例中创建的是一个Pod的ListWatch，接着创建了一个带有限速功能的Workqueuue，之后调用cache.NewIndexInformer来创建indexer和Informer

## Controller.run()

```Go
go c.informer.Run(stopCh)
if !cache.WaitForCacheSync(stopCh, c.informer.HasSynced) {
    runtime.HandleError(fmt.Errorf("Timed out waiting for caches to sync"))
    return        }

// 业务逻辑回调 c.runWorker
for i := 0; i < threadiness; i++ {
        go wait.Until(c.runWorker, time.Second, stopCh)
}
```

`go c.informer.Run()` 用来启用 informer 服务

```Go
r := NewReflectorWithOptions(
    c.config.ListerWatcher,
    c.config.ObjectType,
    c.config.Queue,
    ReflectorOptions{
       ResyncPeriod:    c.config.FullResyncPeriod,
       MinWatchTimeout: c.config.MinWatchTimeout,
       TypeDescription: c.config.ObjectDescription,
       Clock:           c.clock,
    },
)
wg.StartWithChannel(stopCh, r.Run)
```

首先会创建一个Reflector对象， 并注入ListerWatcher和 Delta Fifo，之后会启动Reflector

```Go
func (r *Reflector) Run(stopCh <-chan struct{}) {
    wait.BackoffUntil(func() {
       if err := r.ListAndWatch(stopCh); err != nil {
          r.watchErrorHandler(r, err)
       }
    }, r.backoffManager, true, stopCh)
}
```

ListAndWatch会首先获取到所有的items，并且获得资源在调用时的Version，之后会利用这个Version来Watch该资源

```Go
if useWatchList {
    w, err = r.watchList(stopCh)
    if w == nil && err == nil {
       // stopCh was closed
       return nil
    }
    if err != nil {
       klog.Warningf("The watchlist request ended with an error, falling back to the standard LIST/WATCH semantics because making progress is better than deadlocking, err = %v", err)
       fallbackToList = true
       // ensure that we won't accidentally pass some garbage down the watch.
       w = nil
    }
}

if fallbackToList {
    err = r.list(stopCh)
    if err != nil {
       return err
    }
}

klog.V(2).Infof("Caches populated for %v from %s", r.typeDescription, r.name)
return r.watchWithResync(w, stopCh)
```

当前版本会根据参数决定是否调用WatchList，通过stream的方式从API Server获取数据。streaming的优势是使用较少的资源来获取资源，如果没有开启WatchList或者stream的方式失败则采用list的方式获取资源。

### stream方式

### list方式

```Go
 // 1. 向 apiserver 发送请求
// 如果支持 listerWatcher，则尝试以 chunks 的方式获取资源列表; 否则第一个列表就返回完整的响应
go func() {
    pager := pager.New(pager.SimplePageFunc(func(opts metav1.ListOptions) (runtime.Object, error) {
        return r.listerWatcher.List(opts)
    }))
    ......
    list, paginatedResult, err = pager.ListWithAlloc(context.Background(), options)
}

// 2. 读取响应 以 channel通道的方式获取上面 goroutine 的响应结果
select {
case <-stopCh:
    return nil
case r := <-panicCh:
    panic(r)
case <-listCh:
}

// 3.1 从响应结果列表里获取版本号信息
listMetaInterface, err := meta.ListAccessor(list)
resourceVersion = listMetaInterface.GetResourceVersion()
items, err := meta.ExtractListWithAlloc(list)

// 3.2 根据上次获取的版本号同步最新记录, 更新 Store(Delta FIIO queue) 为最新内容
if err := r.syncWith(items, resourceVersion); err != nil {
    return fmt.Errorf("unable to sync list result: %v", err)
}

// 3.3 更新最新版本号
r.setLastSyncResourceVersion(resourceVersion)
```

当获取资源列表后，对于以后更新的资源，则需要根据 `上次的版本号` 来监控以后变更的资源，这样就可以只监控后续变更的资源即可，大大减少数据的传输。

从信息传输的可靠性来讲，Informer和api-server之间出现异常，Informer会重新建立watcher链接，通过携带上个版本的sourceVerison再次更新所有的增量变化。

而info和custom之间，通过workqeueu来进行事件通知。Informer的协程将FIFO中的事件取出并更新到本地后，会将事件同步回调至custom Controller，加入到workqeueu队列。但是Informer在处理回调事件时，并不关注回调结果。也就是custom Controller侧的消费出现异常导致数据同步失败，Informer是不知情的

resync的作用是保障custom数据与本地缓存的一致性，以维持整体的可靠性，它会定时将本地缓存中所有的资源对象生成事件重新推送到FIFO中，重新触发controller的回调。

![img](https://infracreate.feishu.cn/space/api/box/stream/download/asynccode/?code=MmU1YTlhNDI4NmI1MzgyNGZhZTkyZDNjMDQzOGQxMWJfMUxZQjFmS1BkYUduNENVZE9OVVVSdjJuY2REc2M4TGFfVG9rZW46SkJGTWJWVXJCb3l1M0Z4ZEFuOWNIUUhvbm1nXzE3MjcwMDA4MDM6MTcyNzAwNDQwM19WNA)

```Go
// watchWithResync runs watch with startResync in the background.
func (r *Reflector) watchWithResync(w watch.Interface, stopCh <-chan struct{}) error {
    resyncerrc := make(chan error, 1)
    cancelCh := make(chan struct{})
    defer close(cancelCh)
    go r.startResync(stopCh, cancelCh, resyncerrc)
    return r.watch(w, stopCh, resyncerrc)
}
```

下面是watch的实现

```Go
for {
    if w == nil {
        w, err = r.listerWatcher.Watch(options)
    }
    err = handleWatch(start, w, r.store, r.expectedType, r.expectedGVK, r.name, r.typeDescription, r.setLastSyncResourceVersion,
    r.clock, resyncerrc, stopCh)
    w.Stop()
    w = nil
    retry.After(err)
}
```

watch的具体实现

```Go
func handleAnyWatch（......) {
loop:
    for {
        case event, ok := <-w.ResultChan():
            if !ok {
                break loop
            }
            if event.Type == watch.Error {
                return watchListBookmarkReceived, apierrors.FromObject(event.Object)
            }
            if expectedType != nil {
                if e, a := expectedType, reflect.TypeOf(event.Object); e != a {
                   utilruntime.HandleError(fmt.Errorf("%s: expected type %v, but watch event object had type %v", name, e, a))
                   continue
                }
            }
            if expectedGVK != nil {
                if e, a := *expectedGVK, event.Object.GetObjectKind().GroupVersionKind(); e != a {
                   utilruntime.HandleError(fmt.Errorf("%s: expected gvk %v, but watch event object had gvk %v", name, e, a))
                   continue
                }
            }
            meta, err := meta.Accessor(event.Object)
            if err != nil {
                utilruntime.HandleError(fmt.Errorf("%s: unable to understand watch event %#v", name, event))
                continue
            }
            resourceVersion := meta.GetResourceVersion()
            
            // 更新Delta FIFO Queue
            switch event.Type {
            case watch.Added:
                err := store.Add(event.Object)
                if err != nil {
                   utilruntime.HandleError(fmt.Errorf("%s: unable to add watch event object (%#v) to store: %v", name, event.Object, err))
                }
            case watch.Modified:
                err := store.Update(event.Object)
                if err != nil {
                   utilruntime.HandleError(fmt.Errorf("%s: unable to update watch event object (%#v) to store: %v", name, event.Object, err))
                }
            case watch.Deleted:
                // TODO: Will any consumers need access to the "last known
                // state", which is passed in event.Object? If so, may need
                // to change this.
                err := store.Delete(event.Object)
                if err != nil {
                   utilruntime.HandleError(fmt.Errorf("%s: unable to delete watch event object (%#v) from store: %v", name, event.Object, err))
                }
            case watch.Bookmark:
                // A `Bookmark` means watch has synced here, just update the resourceVersion
                if meta.GetAnnotations()[metav1.InitialEventsAnnotationKey] == "true" {
                   watchListBookmarkReceived = true
                }
            default:
                utilruntime.HandleError(fmt.Errorf("%s: unable to understand watch event %#v", name, event))
            }
            setLastSyncResourceVersion(resourceVersion)
            if rvu, ok := store.(ResourceVersionUpdater); ok {
                rvu.UpdateResourceVersion(resourceVersion)
            }
            eventCount++
            if exitOnWatchListBookmarkReceived && watchListBookmarkReceived {
                watchDuration := clock.Since(start)
                klog.V(4).Infof("exiting %v Watch because received the bookmark that marks the end of initial events stream, total %v items received in %v", name, eventCount, watchDuration)
                return watchListBookmarkReceived, nil
            }
            initialEventsEndBookmarkWarningTicker.observeLastEventTimeStamp(clock.Now())
                }
            }
```

`go wait.Until(c.runWorker, time.Second, stopCh)` 用来实现自定义控制器的逻辑

# sharedInformer

如果在一个应用中有多处相互独立的业务逻辑都需要监控同一种资源对象，用户会编写多个 `Informer` 来进行处理。这会导致应用中发起对 K8s `API Server` 同一资源的多次 `ListAndWatch` 调用，并且每一个 `Informer` 中都有一份单独的本地缓存，增加了内存占用

K8s 在 `client go` 中基于 `Informer` 之上再次做了一层封装，提供了 `SharedInformer` 机制。采用 `SharedInformer` 后，客户端对同一种资源对象只会有一个对 `API Server` 的 `ListAndWatch` 调用，多个 `Informer` 也会共用同一份缓存，减少了对 `API Server` 的请求，提高了性能。