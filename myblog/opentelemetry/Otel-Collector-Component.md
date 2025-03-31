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





# Batch

OTel-collector作为一个监控采集器，理所应当的会对监控数据进行削峰填谷的操作，来确保数据采集的稳定。

batch就是一个常用的processor，用于收集一定数量的可观测数据，之后一起发送到Pipeline后面的流程

## Start

```

```

通过goroutines来确保batch启动

```

func (bp *batchProcessor[T]) Start(ctx context.Context, _ component.Host) error {
	return bp.batcher.start(ctx)
}

func (sb *singleShardBatcher[T]) start(context.Context) error {
	sb.single.start()
	return nil
}

func (b *shard[T]) start() {
	b.processor.goroutines.Add(1)
	go b.startLoop()
}
```

可以看到batch是通过b.newItem这个chan来获取到新的待处理对象，Loop的处理逻辑：

1. 如果processor被关闭，仍然会处理完所有newItem中的对象
2. newItem中有新对象到达，就调用processItem，如果itemCount >= sendBatchSize 就发送所有Items
3. timerCh触发了超时那么就会发送所有Items，并resetTimer

```
func (b *shard[T]) startLoop() {
    defer b.processor.goroutines.Done()

    // timerCh ensures we only block when there is a
    // timer, since <- from a nil channel is blocking.
    var timerCh <-chan time.Time
    if b.processor.timeout != 0 && b.processor.sendBatchSize != 0 {
       b.timer = time.NewTimer(b.processor.timeout)
       timerCh = b.timer.C
    }
    for {
       select {
       case <-b.processor.shutdownC:
       DONE:
          for {
             select {
             case item := <-b.newItem:
                b.processItem(item)
             default:
                break DONE
             }
          }
          // This is the close of the channel
          if b.batch.itemCount() > 0 {
             // TODO: Set a timeout on sendTraces or
             // make it cancellable using the context that Shutdown gets as a parameter
             b.sendItems(triggerTimeout)
          }
          return
       case item := <-b.newItem:
          b.processItem(item)
       case <-timerCh:
          if b.batch.itemCount() > 0 {
             b.sendItems(triggerTimeout)
          }
          b.resetTimer()
       }
    }
}
```

而消费函数consume就是将数据放入newItem当中

```
func (sb *singleShardBatcher[T]) consume(_ context.Context, data T) error {
    sb.single.newItem <- data
    return nil
}
```



## sendItems

当batch容量满或者触发了定时器的超时都会将当前队列中的数据进行发送，其中的b.batch.export实际上是调用了nextConsumer.ConsumeXXX，将数据传输到下一个消费者

并且会通过batchProcessorTelemetry记录

```
func (b *shard[T]) sendItems(trigger trigger) {
    sent, req := b.batch.split(b.processor.sendBatchMaxSize)

    err := b.batch.export(b.exportCtx, req)
    if err != nil {
       b.processor.logger.Warn("Sender failed", zap.Error(err))
       return
    }
    var bytes int
    bpt := b.processor.telemetry

    // Check if the instrument is enabled to calculate the size of the batch in bytes.
    // See https://pkg.go.dev/go.opentelemetry.io/otel/sdk/metric/internal/x#readme-instrument-enabled
    batchSendSizeBytes := bpt.telemetryBuilder.ProcessorBatchBatchSendSizeBytes
    instr, ok := batchSendSizeBytes.(interface{ Enabled(context.Context) bool })
    if !ok || instr.Enabled(bpt.exportCtx) {
       bytes = b.batch.sizeBytes(req)
    }

    bpt.record(trigger, int64(sent), int64(bytes))
}

func (bl *batchLogs) export(ctx context.Context, ld plog.Logs) error {
	return bl.nextConsumer.ConsumeLogs(ctx, ld)
}

```



# memorylimiter

batch通常会搭配memorylimiter来限制内存的使用，并在Pipeline中一般位于batch前面。作用是限制内存使用，避免OOM，这在使用Batch的场景下尤为重要

从Start中可以看出MemoryLimiter会在定时器触发后调用CheckMemLimits检查内存占用

```
func (ml *MemoryLimiter) Start(_ context.Context, _ component.Host) error {
    ml.refCounterLock.Lock()
    defer ml.refCounterLock.Unlock()

    ml.refCounter++
    if ml.refCounter == 1 {
       ml.closed = make(chan struct{})
       ml.waitGroup.Add(1)
       go func() {
          defer ml.waitGroup.Done()

          for {
             select {
             case <-ml.ticker.C:
             case <-ml.closed:
                return
             }
             ml.CheckMemLimits()
          }
       }()
    }
    return nil
}
```



这里有个go语言运行时的调用，用于获取当前go程序所占用的Mem，比较有趣

其中的systemstack的大概逻辑就是如果是普通 goroutine 栈中调用，则需要切换到 g0 栈执行函数，执行完成之后再切换回去。

> g0 是每个 M 系统线程创建的第一个 goroutine，使用的是系统栈，并不是 runtime 维护的用户栈。g0 的主要职责为 goroutine 管理调度、goroutine 的创建、GC 扫描、栈扩容、defer 函数的初始化等。也就是说每当执行这些操作的时候，runtime 都会切换到 g0 栈上执行。

### stopTheWorld

1. 执行stopTheWorld
   1. 获取worldsema全局锁
   2. 标记当前的gp.m.preemptoff，禁止Machine被抢占
   3. 切换到系统栈执行关键逻辑
      1. 将状态迁移到**`_Gwaiting`**
      2. **调用内部实现`stopTheWorldWithSema`**
      3. 恢复**Goroutine**状态
   4. 返回上下文，用于恢复

### readmemstats_m

1. 确认处于WorldStoppe

2. systemstack(flushallmcaches)：遍历所有 P，将其 mcache 中未使用的 span 返还给 mcentral。清理stackcache

3. 分层内存采集

   - 大对象
   - 分尺寸对象（**SizeClass**）
   - 微对象

4. ##### **计算全局指标**

```
	totalMapped := gcController.heapInUse.load() + gcController.heapFree.load() + gcController.heapReleased.load() +
		memstats.stacks_sys.load() + memstats.mspan_sys.load() + memstats.mcache_sys.load() +
		memstats.buckhash_sys.load() + memstats.gcMiscSys.load() + memstats.other_sys.load() +
		stackInUse + gcWorkBufInUse + gcProgPtrScalarBitsInUse
```

5. ##### **一致性校验**

6. 生成**MemStats**

### startTheWorld



```
func ReadMemStats(m *MemStats) {
	_ = m.Alloc // nil check test before we switch stacks, see issue 61158
	stw := stopTheWorld(stwReadMemStats)

	systemstack(func() {
		readmemstats_m(m)
	})

	startTheWorld(stw)
}
```

## CheckMemLimits

在回到CheckMemLimits

这里会校验之前在STW状态下读取的内存使用，

1. 如果没有超过软限制就直接返回
2. 超过软限制或者硬限制都会触发强制GC，但二者的冷却时间不同
3. 通过修改ml.mustRefuse来改变consume时的行为

# Consume

memoryLimiterProcessor是通过processorhelper.NewLogs创建的，以log为例，就是当MustRefuse为true时，通过obsreporter记录并返回一个memorylimiter.ErrDataRefused，表示该记录被拒绝

```
func (p *memoryLimiterProcessor) processLogs(ctx context.Context, ld plog.Logs) (plog.Logs, error) {
	numRecords := ld.LogRecordCount()
	if p.memlimiter.MustRefuse() {
		// TODO: actually to be 100% sure that this is "refused" and not "dropped"
		// 	it is necessary to check the pipeline to see if this is directly connected
		// 	to a receiver (ie.: a receiver is on the call stack). For now it
		// 	assumes that the pipeline is properly configured and a receiver is on the
		// 	callstack.
		p.obsrep.refused(ctx, numRecords, pipeline.SignalLogs)
		return ld, memorylimiter.ErrDataRefused
	}

	// Even if the next consumer returns error record the data as accepted by
	// this processor.
	p.obsrep.accepted(ctx, numRecords, pipeline.SignalLogs)
	return ld, nil
}

```

