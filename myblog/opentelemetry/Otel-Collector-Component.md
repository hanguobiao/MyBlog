---
title: OpenTelemetry Collector Component源码
date: 2025-03-20
update: 2025-03-21
comment: false
tags:
  - OpenTelemetry
categories:
  - OpenTelemetry
---

这里对一些关键的组件进行分析

*<!--more-->*

# Receiver-Creator

作为一个可观测数据采集器，我们当然不希望，他只能使用固定的Receiver来采集数据

这是就可以使用Receiver-Creator来动态生成需要的Receiver

首先看一下Receiver的启动流程

## Start

调用栈

```
start
|- rc.observerHandler = &observerHandler
|  |  |- newReceiverRunner
|- for watchObserver in rc.cfg.WatchObservers
|  |- for cid, ext in rcHost.GetExtensions()
|  |  |- obs, ok := ext.(observer.Observable)
|  |  |- observers[watchObserver] = obs
|- for observable in observers
|  |- observable.ListAndWatch(rc.observerHandler)
```

可以看到Receiver-Creator的关键就是从所有的Extension中找出所有的Extension，并启动ListAndWatch机制，receiverCreator将observerHandler注册到了ListWatch函数当中

可以看到Observable的接口中关键就是ListAndWatch

```
// Observable is an interface that provides notification of endpoint changes.
type Observable interface {
    // ListAndWatch provides initial state sync as well as change notification.
    // notify. OnAdd will be called one or more times if there are endpoints discovered.
    // (It would not be called if there are no endpoints present.) The endpoint synchronization
    // happens asynchronously to this call.
    ListAndWatch(notify Notify)

    // Unsubscribe stops the previously registered Notify from receiving callback invocations.
    Unsubscribe(notify Notify)
}
```

## ListAndWatch

Receiver-Creator的实际作用就是针对定义的每个Endpoint生成合适的receiver

EndpointsWatcher就是observable的实现

```
// EndpointsWatcher provides a generic mechanism to run EndpointsLister.ListEndpoints every
// RefreshInterval and report any new or removed endpoints to Notify instances registered
// via ListAndWatch. Any observer that lists endpoints can make use of EndpointsWatcher
// to poll for endpoints by embedding this struct and using NewEndpointsWatcher().
type EndpointsWatcher struct {
    EndpointsLister EndpointsLister
    RefreshInterval time.Duration

    // subscribed Notify instances ~sync.Map(map[NotifyID]Notify)
    toNotify sync.Map
    // map of NotifyID to known endpoints for that Notify (subscriptions can occur at different times in service startup).
    // ~sync.Map(map[NotifyID]map[EndpointID]Endpoint)
    existingEndpoints sync.Map
    stop              chan struct{}
    once              *sync.Once
    logger            *zap.Logger
}
```

接着看一下ListAndWatch的处理逻辑，这里就是定时触发notifyOfLatestEndpoints，

```
// ListAndWatch runs EndpointsLister.ListEndpoints() on a regular interval and keeps track of the results
// for alerting all subscribed Notify's of the based on the differences from the previous call.
func (ew *EndpointsWatcher) ListAndWatch(notify observer.Notify) {
    ew.once.Do(func() {
       go func() {
          ticker := time.NewTicker(ew.RefreshInterval)
          defer ticker.Stop()

          for {
             select {
             case <-ew.stop:
                return
             case <-ticker.C:
                var toNotify []observer.NotifyID
                ew.toNotify.Range(func(notifyID, _ any) bool {
                   toNotify = append(toNotify, notifyID.(observer.NotifyID))
                   return true
                })
                ew.notifyOfLatestEndpoints(toNotify...)
             }
          }
       }()
    })

    ew.toNotify.Store(notify.ID(), notify)
    ew.notifyOfLatestEndpoints(notify.ID())
}
```

notifyOfLatestEndpoints又会调用Observer的ListEndpoints方法获取到全量的Endpoints，之后和自身存储的Endpoints做一个diff，来触发Handler中的OnAdd、OnRemove、OnChange

```
func (ew *EndpointsWatcher) updateAndNotifyOfEndpoints(notify observer.Notify, endpoints []observer.Endpoint, done *sync.WaitGroup) {
	defer done.Done()
	removedEndpoints, addedEndpoints, changedEndpoints := ew.updateEndpoints(notify, endpoints)
	if len(removedEndpoints) > 0 {
		ew.logEndpointEvent("removed endpoints", notify, removedEndpoints)
		notify.OnRemove(removedEndpoints)
	}

	if len(addedEndpoints) > 0 {
		ew.logEndpointEvent("added endpoints", notify, addedEndpoints)
		notify.OnAdd(addedEndpoints)
	}

	if len(changedEndpoints) > 0 {
		ew.logEndpointEvent("changed endpoints", notify, changedEndpoints)
		notify.OnChange(changedEndpoints)
	}
}
```

这是就可以跳转到observerHandler，来处理上面被通知到的事件，还是以Onadd为例，可以看到这里会获取注册到ReceiverCreator中的Receiver模版，根据rules匹配成功，并启动

```
for _, template := range obs.config.receiverTemplates {
			if matches, err := template.rule.eval(env); err != nil {
				obs.params.TelemetrySettings.Logger.Error("failed matching rule", zap.String("rule", template.Rule), zap.Error(err))
				continue
			} else if !matches {
				continue
			}
			obs.startReceiver(template, env, e)
}
```

值得一提的是这里的Receiver是一个封装好的enhancingConsumer

```
// enhancingConsumer adds additional resource attributes from the given endpoint environment before passing the
// telemetry to its next consumers. The added attributes vary based on the type of the endpoint.
type enhancingConsumer struct {
    logs    consumer.Logs
    metrics consumer.Metrics
    traces  consumer.Traces
    attrs   map[string]string
}
```

以日志采集为例，会调用创建好的logReceiver的ConsumeLogs方法，这样就进入Pipeline具体的采集当中了

```
func (ec *enhancingConsumer) ConsumeLogs(ctx context.Context, ld plog.Logs) error {
    if ec.logs == nil {
       return errors.New("no log consumer available")
    }
    rl := ld.ResourceLogs()
    for i := 0; i < rl.Len(); i++ {
       ec.putAttrs(rl.At(i).Resource().Attributes())
    }

    return ec.logs.ConsumeLogs(ctx, ld)
}
```

## Observer

我们以opentelemetry-collector-contrib中的k8sobserver来了解一下Observer是如何生效的

### start

```
start -> k.once.Do
|- podInformer := cache.NewSharedInformer
|- podInformer.AddEventHandler
|- go podInformer.Run(k.stop)

|- serviceInformer := cache.NewSharedInformer
|- serviceInformer.AddEventHandler
|- go serviceInformer.Run(k.stop)

|- nodeInformer := cache.NewSharedInformer
|- go nodeInformer.Run(k.stop)
|- nodeInformer.AddEventHandler(k.handler)
```

这里是典型的SharedInformer机制，通过注册Handler在所监控资源发生add、update、delete事件时执行对应的回调函数

那么关键就是Handler的处理逻辑是什么样的,handler 的定义如下，其中使用了sync.Map来存储Endpoint，可以理解为是一组可观测数据的采集点，receiverCreator会针对每个Endpoint来生成对应类型的Receiver，这样就完成了调用

```
// handler handles k8s cache informer callbacks.
type handler struct {
    // idNamespace should be some unique token to distinguish multiple handler instances.
    idNamespace string
    // endpoints is a map[observer.EndpointID]observer.Endpoint all existing endpoints at any given moment
    endpoints *sync.Map

    logger *zap.Logger
}
```

以onAdd函数为例看一下具体是如何处理的，逻辑就是将Informer下发的Add事件中的资源转换为Endpoint并存储到sync.Map当中

```
// OnAdd is called in response to a new pod or node being detected.
func (h *handler) OnAdd(objectInterface any, _ bool) {
    var endpoints []observer.Endpoint

    switch object := objectInterface.(type) {
    case *v1.Pod:
       endpoints = convertPodToEndpoints(h.idNamespace, object)
    case *v1.Service:
       endpoints = convertServiceToEndpoints(h.idNamespace, object)
    case *networkingv1.Ingress:
       endpoints = convertIngressToEndpoints(h.idNamespace, object)
    case *v1.Node:
       endpoints = append(endpoints, convertNodeToEndpoint(h.idNamespace, object))
    default: // unsupported
       return
    }

    for _, endpoint := range endpoints {
       h.endpoints.Store(endpoint.ID, endpoint)
    }
}
```

还有一个接口ListEndpoints，这个就是和ReceiverCreator联动的关键

```
func (h *handler) ListEndpoints() []observer.Endpoint {
    var endpoints []observer.Endpoint
    h.endpoints.Range(func(endpointID, endpoint any) bool {
       if e, ok := endpoint.(observer.Endpoint); ok {
          endpoints = append(endpoints, e)
       } else {
          h.logger.Info("failed listing endpoint", zap.Any("endpointID", endpointID), zap.Any("endpoint", endpoint))
       }
       return true
    })
    return endpoints
}
```