---
title: client-go源码机制
date: 2025-01-15
update: 2025-03-02
comment: false
tags:
  - kubernetes
categories:
  - kubernetes
---
如果你正在写Kubernetes的Operator或者对这一机制感兴趣，那么就绕不开Client-go。作为 Kubernetes 控制器开发的核心框架，client-go的许多机制是Kubernetes二次开发绕不开的基石，本文将带您深入剖析其核心架构组件

参考：https://github.com/daniel-hutao/Advanced-Kubernetes-Operator

*<!--more-->*
# Client-go中的模块

- Reflector: Reflector从apiserver去watch特定类型的资源，拿到变更通知后，将其放入DeltaFIFO队列当中
- Informer：Informer从DeltaFIFO中pop出相应的对象，然后通过Indexer将对象和索引丢到本地Cache中，再触发相应的事件处理函数
- Indexer：Indexer主要提供一个对象根据一定条件检索的能力，一个典型案例就是通过namespaceKey来构造Key，通过Thread Safe Store来存储对象
- WorkQueue: 一般使用的是延时队列的实现，在Resource Event Handler中会完成将对象的Key放入WorkQeueu的过程，之后在自己的代码中消费这些Key
- ClientSet：提供的是资源的CURD能力，与apiserver交互
- Resource Event Handler：一般在Resource Event Handler中添加一些简单的过滤功能，判断哪些对象需要加到WorkQeueu中进一步处理，对于需要加入WorkQeueu中的对象，就提取key然后入队
- Worker：通常是自己的业务代码处理过程，可以接收WorkQeueu中的任务，可以通过Indexer从本地缓存检索对象，通过ClientSet实现增删改查

![img](https://myblog-1307634347.cos.ap-guangzhou.myqcloud.com/blog/informer-workflow.png)

# WorkQeueu源码

## Struct定义

接口定义如下：

```
type TypedInterface[T comparable] interface {
    Add(item T)
    Len() int
    Get() (item T, shutdown bool)
    Done(item T)
    ShutDown()
    ShutDownWithDrain()
    ShuttingDown() bool
}
```

Type的Interface的实现定义如下

```
type Typed[t comparable] struct {
    // 定义元素的处理顺序，所有元素在dirty中应该都有，而不能出现在Processing当中
    queue Queue[t]

    // 标记所有需要被处理的元素
    dirty set[t]

    // 当前正在被处理的元素，当处理完后，需要检查该元素是否在dirty集合当中
    processing set[t]

    cond *sync.Cond

    shuttingDown bool
    drain        bool

    metrics queueMetrics

    unfinishedWorkUpdatePeriod time.Duration
    clock                      clock.WithTicker
}
```

这个 Queue 的工作逻辑大致是这样，里面的三个属性 queue、dirty、processing 都保存 items，但是含义有所不同：

- **queue**：这是一个 []t 类型，也就是一个切片，因为其有序，所以这里当作一个列表来存储 item 的处理顺序。
- **dirty**：这是一个 set 类型，也就是一个集合，这个集合存储的是所有需要处理的 item
- **processing**：这也是一个 set，存放的是当前正在处理的 item，也就是说这个 item 来自 queue 出队的元素，同时这个元素会被从 dirty 中删除。

### 方法实现

Add用于标记一个新元素需要被处理

```
func (q *Typed[T]) Add(item T) {
	q.cond.L.Lock()
	defer q.cond.L.Unlock()
	if q.shuttingDown {
		return
	}
	if q.dirty.has(item) {
		// 如果在处理之前再次添加了相同的项目，且队列关心此操作（例如，重置其优先级），
		// 则调用 Touch 函数
		if !q.processing.has(item) {
			q.queue.Touch(item)
		}
		return
	}

	q.metrics.add(item)

	q.dirty.insert(item)
	if q.processing.has(item) {
		return
	}
	// 如果没有被处理，则加到q.queue
	q.queue.Push(item)
	q.cond.Signal()
}
```

Get在获取不到元素时会通过cond阻塞并等待信号

```
func (q *Typed[T]) Get() (item T, shutdown bool) {
    q.cond.L.Lock()
    defer q.cond.L.Unlock()
    // 没有元素就阻塞
    for q.queue.Len() == 0 && !q.shuttingDown {
       q.cond.Wait()
    }
    // 接受到信号，queue的长度还是是0，则queue已经被关闭
    if q.queue.Len() == 0 {
       // We must be shutting down.
       return *new(T), true
    }

    item = q.queue.Pop()

    q.metrics.get(item)

    q.processing.insert(item)
    q.dirty.delete(item) // 在dirty集合中删除该元素

    return item, false
}
```

Pop的实现

```
func (q *queue[T]) Pop() (item T) {
    item = (*q)[0]

    // 底层的数组仍然存在并引用此对象，因此该对象不会被垃圾回收机制回收。
    (*q)[0] = *new(T)
    *q = (*q)[1:]

    return item
}
```

Done标记一个元素已经处理完成

```
func (q *Typed[T]) Done(item T) {
    q.cond.L.Lock()
    defer q.cond.L.Unlock()

    q.metrics.done(item)
		// 处理完毕后，在processing集合中删除
    q.processing.delete(item)
    // 这是如果dirty还有就说明需要再次处理
    if q.dirty.has(item) {
       q.queue.Push(item)
       q.cond.Signal()
    } else if q.processing.len() == 0 {
       q.cond.Signal()
    }
}
```

## DelayingQueue

DelayingQueue接口定义，其中嵌套了之前提到的TypedInterface

AddAfter用于延时添加元素

```
type TypedDelayingInterface[T comparable] interface {
    TypedInterface[T]
    // AddAfter adds an item to the workqueue after the indicated duration has passed
    AddAfter(item T, duration time.Duration)
}
```

实现的Struct为DelayingType

```
// delayingType wraps an Interface and provides delayed re-enquing
type delayingType[T comparable] struct {
	TypedInterface[T]

	// clock tracks time for delayed firing
	clock clock.Clock
	stopCh chan struct{}
	// 用来确保 ShutDown() 方法只执行一次
	stopOnce sync.Once
	// 默认10s的心跳，后面用在一个大循环里，避免没有新元素时一直阻塞
	heartbeat clock.Ticker
	// 传递 waitFor 的 channel，默认大小 1000
	waitingForAddCh chan *waitFor

	metrics retryMetrics
}
```

其中waitFor结构体，定义为在waitForPriorityQueue中使用的数据

```
type waitFor struct {
    data    t
    readyAt time.Time
    // index in the priority queue (heap)
    index int
}
```

waitForPriorityQueue是一个[]*waitFor，实现了 heap.Interface 接口

```
// waitForPriorityQueue 实现了一个用于 waitFor 项的优先级队列。
//
// waitForPriorityQueue 实现了 heap.Interface 接口。时间上即将发生的项（即 readyAt 最小的项）位于根节点（索引 0）。
// Peek 方法返回索引 0 处的最小项。Pop 方法在移除队列中的最小项并将其放置在索引 Len()-1 后返回该项，这是由 container/heap 完成的。
// Push 方法在索引 Len() 处添加一个项，而 container/heap 会将其渗透到正确的位置。
type waitForPriorityQueue []*waitFor
```

NewTypedDelayingQueueWithConfig用于创建waitForPriorityQueue，核心是go ret.waitingLoop()

```
func NewTypedDelayingQueueWithConfig[T comparable](config TypedDelayingQueueConfig[T]) TypedDelayingInterface[T] {
    if config.Clock == nil {
       config.Clock = clock.RealClock{}
    }

    if config.Queue == nil {
       config.Queue = NewTypedWithConfig[T](TypedQueueConfig[T]{
          Name:            config.Name,
          MetricsProvider: config.MetricsProvider,
          Clock:           config.Clock,
       })
    }

    return newDelayingQueue(config.Clock, config.Queue, config.Name, config.MetricsProvider)
}
```

```
func newDelayingQueue[T comparable](clock clock.WithTicker, q TypedInterface[T], name string, provider MetricsProvider) *delayingType[T] {
    ret := &delayingType[T]{
       TypedInterface:  q,
       clock:           clock,
       heartbeat:       clock.NewTicker(maxWait),
       stopCh:          make(chan struct{}),
       waitingForAddCh: make(chan *waitFor, 1000),
       metrics:         newRetryMetrics(name, provider),
    }

    go ret.waitingLoop()
    return ret
}
```

### ret.waitingLoop

处理流程

1. 初始化waitingForQueue（核心队列）和waitingEntryByData

   - `waitingEntryByData` 通过数据唯一标识符（如对象 Key）避免同一元素被多次加入延迟队列

2. loop

   1. 检测队列是否正在关闭
   2. 处理到期元素，将堆中已经到期的元素转移到delayingType。并且清理waitingEntryByData

   ```
   for waitingForQueue.Len() > 0 {
       entry := waitingForQueue.Peek().(*waitFor)
       if entry.readyAt.After(now) { break }    // 时间未到，停止处理
       entry = heap.Pop(waitingForQueue).(*waitFor)
       q.Add(entry.data)                        // 将到期元素加入主队列
       delete(waitingEntryByData, entry.data)   // 从去重表中删除
   }
   
   
   ```

   3. 设置下次触发时间。如果队列中有 item，就用第一个 item 的等待时间初始化计时器，如果为空则一直等待

   ```
   nextReadyAt := never
   if waitingForQueue.Len() > 0 {
       entry := waitingForQueue.Peek().(*waitFor)
       nextReadyAtTimer = q.clock.NewTimer(entry.readyAt.Sub(now)) // 计算时间差
       nextReadyAt = nextReadyAtTimer.C()                          // 获取计时器通道
   }
   ```

   4. 多路事件监听
      1. case <-q.heartbeat.C(): // 心跳时间是 10s，到了就继续下一轮循环
      2. case <-nextReadyAt: // 第一个 item 的等到时间到了，继续下一轮循环
      3. case waitEntry := <-q.waitingForAddCh: // waitingForAddCh 收到新的 item
         1. 未到期则入堆
         2. 已到期直接加入主队列
         3. 清理chan中积压的元素

```go
func (q *delayingType) waitingLoop() {
   defer utilruntime.HandleCrash()
   // 队列里没有 item 时实现等待用的
   never := make(<-chan time.Time)
   var nextReadyAtTimer clock.Timer
   // 构造一个优先级队列
   waitingForQueue := &waitForPriorityQueue{}
   heap.Init(waitingForQueue) // 这一行其实是多余的，功能上没有啥作用，不过在可读性上有点帮助。

   // 这个 map 用来处理重复添加逻辑的，下面会讲到
   waitingEntryByData := map[t]*waitFor{}
   for {
      if q.Interface.ShuttingDown() {
         return
      }

      now := q.clock.Now()
      // 队列里有 item 就开始循环
      for waitingForQueue.Len() > 0 {
         // 获取第一个 item
         entry := waitingForQueue.Peek().(*waitFor)
         // 时间还没到，先不处理
         if entry.readyAt.After(now) {
            break
         }
        // 时间到了，pop 出第一个元素；注意 waitingForQueue.Pop() 是最后一个 item，heap.Pop() 是第一个元素
         entry = heap.Pop(waitingForQueue).(*waitFor)
         // 将数据加到延时队列里
         q.Add(entry.data)
         // map 里删除已经加到延时队列的 item
         delete(waitingEntryByData, entry.data)
      }

      // 如果队列中有 item，就用第一个 item 的等待时间初始化计时器，如果为空则一直等待
      nextReadyAt := never
      if waitingForQueue.Len() > 0 {
         if nextReadyAtTimer != nil {
            nextReadyAtTimer.Stop()
         }
         entry := waitingForQueue.Peek().(*waitFor)
         nextReadyAtTimer = q.clock.NewTimer(entry.readyAt.Sub(now))
         nextReadyAt = nextReadyAtTimer.C()
      }

      select {
      case <-q.stopCh:
         return
      case <-q.heartbeat.C(): // 心跳时间是 10s，到了就继续下一轮循环
      case <-nextReadyAt: // 第一个 item 的等到时间到了，继续下一轮循环
      case waitEntry := <-q.waitingForAddCh: // waitingForAddCh 收到新的 item
         // 如果时间没到，就加到优先级队列里，如果时间到了，就直接加到延时队列里
         if waitEntry.readyAt.After(q.clock.Now()) {
            insert(waitingForQueue, waitingEntryByData, waitEntry)
         } else {
            q.Add(waitEntry.data)
         }
         // 下面的逻辑就是将 waitingForAddCh 中的数据处理完
         drained := false
         for !drained {
            select {
            case waitEntry := <-q.waitingForAddCh:
               if waitEntry.readyAt.After(q.clock.Now()) {
                  insert(waitingForQueue, waitingEntryByData, waitEntry)
               } else {
                  q.Add(waitEntry.data)
               }
            default:
               drained = true
            }
         }
      }
   }
}

```

以及用于插入数据的insert

```
func insert(q *waitForPriorityQueue, knownEntries map[t]*waitFor, entry *waitFor) {
   // 这里的主要逻辑是看一个 entry 是否存在，如果已经存在，新的 entry 的 ready 时间更短，就更新时间
   existing, exists := knownEntries[entry.data]
   if exists {
      if existing.readyAt.After(entry.readyAt) {
         existing.readyAt = entry.readyAt // 如果存在就只更新时间
         heap.Fix(q, existing.index)
      }

      return
   }
   // 如果不存在就丢到 q 里，同时在 map 里记录一下，用于查重
   heap.Push(q, entry)
   knownEntries[entry.data] = entry
}
```

### AddAfter

在指定的演示时长到达后，在work Queue中添加一个元素

```
func (q *delayingType[T]) AddAfter(item T, duration time.Duration) {
    // don't add if we're already shutting down
    if q.ShuttingDown() {
       return
    }

    q.metrics.retry()

    // immediately add things with no delay
    if duration <= 0 {
       q.Add(item)
       return
    }

    select {
    case <-q.stopCh:
       // unblock if ShutDown() is called
    case q.waitingForAddCh <- &waitFor{data: item, readyAt: q.clock.Now().Add(duration)}:
    }
}
```

## RateLimitingQueue

**接口定义**

```
// TypedRateLimitingInterface is an interface that rate limits items being added to the queue.
type TypedRateLimitingInterface[T comparable] interface {
    TypedDelayingInterface[T]

    // AddRateLimited adds an item to the workqueue after the rate limiter says it's ok
    AddRateLimited(item T)

    // Forget indicates that an item is finished being retried.  Doesn't matter whether it's for perm failing
    // or for success, we'll stop the rate limiter from tracking it.  This only clears the `rateLimiter`, you
    // still have to call `Done` on the queue.
    Forget(item T)

    // NumRequeues returns back how many times the item was requeued
    NumRequeues(item T) int
}
```

**struct实现**

```
// rateLimitingType wraps an Interface and provides rateLimited re-enquing
type rateLimitingType[T comparable] struct {
	TypedDelayingInterface[T]

	rateLimiter TypedRateLimiter[T]
}
```

可以看到关键是多了rateLimiter，用于速度限制

```
type TypedRateLimiter[T comparable] interface {
	// When gets an item and gets to decide how long that item should wait
	When(item T) time.Duration
	// Forget indicates that an item is finished being retried.  Doesn't matter whether it's for failing
	// or for success, we'll stop tracking it
	Forget(item T)
	// NumRequeues returns back how many failures the item has had
	NumRequeues(item T) int
}
```

具体实现逻辑，就是调用限速器的接口

```
func (q *rateLimitingType) AddRateLimited(item interface{}) {
   // 内部存了一个延时队列，通过限速器计算出一个等待时间，然后传给延时队列
   q.DelayingInterface.AddAfter(item, q.rateLimiter.When(item))
}

func (q *rateLimitingType) NumRequeues(item interface{}) int {
   return q.rateLimiter.NumRequeues(item)
}

func (q *rateLimitingType) Forget(item interface{}) {
   q.rateLimiter.Forget(item)
}

```



#### BucketRateLimiter

用了 golang 标准库的 `golang.org/x/time/rate.Limiter` 实现。BucketRateLimiter 实例化的时候比如传递一个 `rate.NewLimiter(rate.Limit(10), 100)` 进去，表示令牌桶里最多有 100 个令牌，每秒发放 10 个令牌。

#### ItemExponentialFailureRateLimiter

Exponential 是指数的意思，从这个限速器的名字大概能猜到是失败次数越多，限速越长而且是指数级增长的一种限速器。结构体定义如下

```
type ItemExponentialFailureRateLimiter struct {
   failuresLock sync.Mutex
   failures     map[interface{}]int

   baseDelay time.Duration
   maxDelay  time.Duration
}
```

```
func (r *TypedItemExponentialFailureRateLimiter[T]) When(item T) time.Duration {
    r.failuresLock.Lock()
    defer r.failuresLock.Unlock()

    exp := r.failures[item]
    r.failures[item] = r.failures[item] + 1

    // 每调用一次，exp 也就加了1，对应到这里时 2^n 指数爆炸
    backoff := float64(r.baseDelay.Nanoseconds()) * math.Pow(2, float64(exp))
    if backoff > math.MaxInt64 {
       return r.maxDelay
    }

    calculated := time.Duration(backoff)
    if calculated > r.maxDelay {
       return r.maxDelay
    }

    return calculated
}
```

#### ItemFastSlowRateLimiter

快慢限速器，也就是先快后慢，定义一个阈值，超过了就慢慢重试。

```
type ItemFastSlowRateLimiter struct {
   failuresLock sync.Mutex
   failures     map[interface{}]int

   maxFastAttempts int            // 快速重试的次数
   fastDelay       time.Duration  // 快重试间隔
   slowDelay       time.Duration  // 慢重试间隔
}

```

#### MaxOfRateLimiter

内部维护多个限速器，返回延时最严重的一个

```
type MaxOfRateLimiter struct {
   limiters []RateLimiter
}

func (r *MaxOfRateLimiter) When(item interface{}) time.Duration {
   ret := time.Duration(0)
   for _, limiter := range r.limiters {
      curr := limiter.When(item)
      if curr > ret {
         ret = curr
      }
   }

   return ret
}
```

#### WithMaxWaitRateLimiter

就是在其他限速器上包装一个最大延迟的属性，如果到了最大延时，则直接返回

```
type WithMaxWaitRateLimiter struct {
   limiter  RateLimiter   // 其他限速器
   maxDelay time.Duration // 最大延时
}

func NewWithMaxWaitRateLimiter(limiter RateLimiter, maxDelay time.Duration) RateLimiter {
   return &WithMaxWaitRateLimiter{limiter: limiter, maxDelay: maxDelay}
}

func (w WithMaxWaitRateLimiter) When(item interface{}) time.Duration {
   delay := w.limiter.When(item)
   if delay > w.maxDelay {
      return w.maxDelay // 已经超过了最大延时，直接返回最大延时
   }

   return delay
}

```

# DeltaFIFO

## 概要

DeltaFIFO 是 Kubernetes **client-go** 中核心的队列实现，是一个生产者-消费者的队列，生产者是 Reflector，消费者是 Pop 函数。是设计用于高效、可靠地跟踪资源对象（如 Pod、Deployment）的变更事件。

其核心作用是通过记录对象的 **增量变更历史（Delta 序列）**，确保控制器能够按顺序处理所有变更事件，同时解决以下关键问题：

1. **事件去重与有序性**：合并对象的多次变更，避免重复处理。
2. **删除事件处理**：明确记录对象删除操作，防止状态不一致。
3. **全量同步支持**：通过 `Sync` 或 `Replaced` 事件，定期同步对象最新状态。
4. **最终一致性保障**：确保控制器在任何时刻都能看到对象的完整变更历史。

先介绍一下deltas

```
// Delta告诉你发生了什么变化，以及变化后*对象的状态。
// [*] 除非变化是删除，在这种情况下你将得到对象被删除前的最终状态。
type Delta struct {
	Type   DeltaType
	Object interface{}
}

// Deltas 是一个针对单个对象的一个或多个'Delta'的列表。
// 最旧的 Delta 位于索引 0，最新的 Delta 是列表中的最后一个。
type Deltas []Delta
```

Delta 其实就是 Kubernetes 中对象的变化（增、删、改、同步），FIFO 是一个先入先出的队列，那么 DeltaFIFO 就是一个按序的（先入先出）Kubernetes 对象变化的队列。

```
type DeltaType string

const (
    Added   DeltaType = "Added"
    Updated DeltaType = "Updated"
    Deleted DeltaType = "Deleted"
    Replaced DeltaType = "Replaced"
    Sync DeltaType = "Sync"
)
```

## 代码

DeltaFIFO 类似于 FIFO，但在两个方面有所不同。一是与给定对象key关联的累加器不是该对象本身，而是 Deltas，即该对象的 Delta 值切片。将对象应用于 Deltas 意味着追加一个 Delta，除非可能追加的 Delta 是 Deleted 且 Deltas 已经以 Deleted 结尾。在这种情况下，Deltas 不会增长，尽管如果较旧的 Deleted 的对象是 DeletedFinalStateUnknown，则终端 Deleted 将被新的 Deleted 替换。

另一个区别是 DeltaFIFO 有两种额外的将对象应用于累加器的方式：Replaced 和 Sync。如果 EmitDeltaTypeReplaced 未设置为 true，则为了向后兼容，Sync 将用于替换事件。Sync 用于定期重新同步事件。

DeltaFIFO 是一个生产者-消费者队列，其中 Reflector 旨在作为生产者，而消费者是调用 Pop() 方法的任何对象。

DeltaFIFO 解决了以下使用场景：

- 您希望最多处理一次每个对象变更（delta）。
- 当您处理一个对象时，您希望看到自上次处理以来发生的所有事情。
- 您希望处理某些对象的删除。
- 您可能希望定期重新处理对象。

```
type DeltaFIFO struct {
    // lock/cond protects access to 'items' and 'queue'.
    lock sync.RWMutex
    cond sync.Cond

    // `items` maps a key to a Deltas.
    // Each such Deltas has at least one Delta.
    items map[string]Deltas

    // `queue` maintains FIFO order of keys for consumption in Pop().
    // There are no duplicates in `queue`.
    // A key is in `queue` if and only if it is in `items`.
    queue []string

    // populated is true if the first batch of items inserted by Replace() has been populated
    // or Delete/Add/Update/AddIfNotPresent was called first.
    populated bool
    // initialPopulationCount is the number of items inserted by the first call of Replace()
    initialPopulationCount int

    // keyFunc is used to make the key used for queued item
    // insertion and retrieval, and should be deterministic.
    keyFunc KeyFunc

    // knownObjects list keys that are "known" --- affecting Delete(),
    // Replace(), and Resync()
    knownObjects KeyListerGetter

    // Used to indicate a queue is closed so a control loop can exit when a queue is empty.
    // Currently, not used to gate any of CRUD operations.
    closed bool

    // emitDeltaTypeReplaced is whether to emit the Replaced or Sync
    // DeltaType when Replace() is called (to preserve backwards compat).
    emitDeltaTypeReplaced bool

    // Called with every object if non-nil.
    transformer TransformFunc
}
```

## Queue

DeltaFIFO实现了queue接口

```
// Queue 扩展了 Store，包含了一组需要“处理”的 Store 键。
// 每次 Add、Update 或 Delete 操作可能会将对象的键放入该集合中。
// Queue 提供了一种方式，可以根据累加器推导出相应的键。
// Queue 可以并发地被多个 goroutine 访问。
// Queue 可以被“关闭”，关闭后 Pop 操作将返回错误。
type Queue interface {
	Store

  // Pop 会阻塞，直到至少有一个键可供处理或 Queue 被关闭。
  // 在后一种情况下，Pop 会返回错误。
  // 在前一种情况下，Pop 会原子地选取一个key进行处理，
  // 从 Store 中移除该（键，累加器）关联，并处理累加器。
  // Pop 返回被处理的累加器及其处理结果。
  // PopProcessFunc 可能会返回一个 ErrRequeue{inner}，此时 Pop 会：
  // (a) 将该（键，累加器）关联作为原子处理的一部分重新加入 Queue，
  // (b) 从 Pop 返回内部错误 inner。
	Pop(PopProcessFunc) (interface{}, error)

	// AddIfNotPresent 仅在给定keys尚未与一个非空累加器关联时，
  // 将给定的累加器放入 Queue（与该累加器的键关联）。
	AddIfNotPresent(interface{}) error

  // HasSynced 如果第一批keys已全部被弹出，则返回 true。
  // 第一批keys是指在首次 Add、AddIfNotPresent、Update 或 Delete 操作之前的第一个 Replace 操作中的keys；
  // 如果没有这样的 Replace 操作，则第一批键为空。
	HasSynced() bool

	// Close the queue
	Close()
}
```

store的接口定义如下：

```
// Store 是一个通用的对象存储和处理接口。Store 持有一个从字符串键到累加器的映射，并且提供了操作来添加、更新和删除与给定键当前关联的累加器中的对象。Store 还知道如何从给定对象中提取键，因此许多操作仅提供对象即可。
// 在最简单的 Store 实现中，每个累加器仅仅是最后给定的对象，或者在删除后为空，因此 Store 的行为是简单的存储。
// Reflector 知道如何监视服务器并更新 Store。本包提供了多种 Store 的实现。
type Store interface {
    Add(obj interface{}) error
    Update(obj interface{}) error
    Delete(obj interface{}) error
    List() []interface{}
    ListKeys() []string
    Get(obj interface{}) (item interface{}, exists bool, err error)
    GetByKey(key string) (item interface{}, exists bool, err error)
    Replace([]interface{}, string) error
    Resync() error
}
```

## queueActionLocked

DeltaFIFO的核心逻辑在queueActionLocked，通过传递不同参数来实现Add、Update、Delete

作用是负责将对象的变更事件（Delta）追加到 DeltaFIFO 中，并通过 **去重** 和 **合并规则** 确保事件序列的合理性和一致性。它是 DeltaFIFO 所有事件（Add/Update/Delete/Replace/Sync）的最终入口。

#### 处理逻辑：

1. 获取Obj的Key也就是ns/name
2. 调用转换函数
   - 如果 obj 是一个 DeletedFinalStateUnknown 的墓碑对象，或者操作是 Sync，那么该对象已经经过转换器处理。 

3. 增量合并与去重
   1. **合并连续删除**：若最新 Delta 是 `Deleted` 类型，且最后一个旧 Delta 也是 `Deleted`
      - 若旧 Delta 是 `DeletedFinalStateUnknown`（缓存最终状态缺失），则 **替换旧 Delta**。
      - 否则保留原 Delta（避免重复记录删除）。
   2. 忽略无效更新：
      - 若最新 Delta 是 `Updated` 类型，且前一个 Delta 已经是 `Sync/Replaced`（全量同步），则 **丢弃新 Delta**（全量同步已包含最新状态）
4. 更新存储与通知消费者
   - f.queue = append(f.queue, id) // 新增对象：加入队列末尾
   - f.items[id] = newDeltas           // 更新对象的 Delta 序列
   - f.cond.Broadcast()                   // 通知消费者有新事件待处理

## POP

作用是从队列中取出并处理对象的增量事件（Deltas）。它是 Kubernetes 控制器从 DeltaFIFO 消费事件的核心入口，确保事件的 **按序处理** 和 **线程安全**。

Pop 按照元素的添加或更新顺序有序返回一个元素(Deltas)，在队列为空时会阻塞。另外 Pop 过程会先从队列中删除一个元素然后返回，所以如果处理失败了需要通过 `AddIfNotPresent()` 方法将这个元素加回到队列中。

Pop接收一个func(obj interface{}, isInInitialList bool) error类型的函数作为入参

### 处理流程

1. 加锁，并等待cond
2. 取出队列元素

```
id := f.queue[0]      // 取队列头部对象的键（如 "ns/name"）
f.queue = f.queue[1:] // 移除已取出的键
item, ok := f.items[id]
delete(f.items, id)   // 从 Delta 存储中删除
```

3. 初始同步状态跟踪
   1. **初始同步标记**：`isInInitialList` 表示当前是否处于全量同步阶段（如 `Replace()` 后的首次处理）。
   2. `initialPopulationCount` 跟踪全量同步时队列中的对象数量，归零后标记队列完成同步（`hasSynced` 返回 `true`）。

```
isInInitialList := !f.hasSynced_locked()
if f.initialPopulationCount > 0 {
    f.initialPopulationCount-- // 递减初始同步计数器
}
```

4. 性能监控与诊断
5. 事件处理与错误重试

```
err := process(item, isInInitialList) // 调用控制器处理函数
if e, ok := err.(ErrRequeue); ok {    // 判断是否为重试错误
    f.addIfNotPresent(id, item)       // 重新入队
    err = e.Err
}
return item, err
```



## Replace

`Replace` 方法是 DeltaFIFO 实现全量同步的核心，用于将一组新对象 **原子替换** 到队列中，并 **标记不在新列表中的旧对象为删除**。它的设计目标是确保本地缓存（Indexer）与 Kubernetes API Server 的全量状态一致，适用于以下场景：

1. **首次启动**：Informer 通过 List 操作获取全量对象后，调用 `Replace()` 初始化队列。
2. **重新同步（Resync）**：周期性（如 `ResyncPeriod`）强制全量同步，修复可能的增量事件丢失。
3. **Watch 连接中断恢复**：重建 Watch 连接时，通过全量同步弥补断连期间可能遗漏的事件。

### 处理流程

1. 加锁与初始化，兼容旧版本（Sync）与新版本（Replaced）事件类型。
2. 对于每个item添加Sync/Replaced

```
// Add Sync/Replaced action for each new item.
for _, item := range list {
    key, err := f.KeyOf(item)
    if err != nil {
       return KeyError{item, err}
    }
    keys.Insert(key)
    if err := f.queueActionInternalLocked(action, Replaced, item); err != nil {
       return fmt.Errorf("couldn't enqueue object: %v", err)
    }
}
```

3. #### **删除队列中不再存在的旧对象**

DeletedFinalStateUnknown 作用：

- 在无法确定被删除对象最终状态时（如 Watch 断开期间遗漏删除事件），记录最后已知状态。
- 确保控制器能够清理相关资源（如 Deployment 清理已删除的 Pod）。

```
for k, oldItem := range f.items {
    if keys.Has(k) { continue } // 新列表中存在的对象跳过
    deletedObj := oldItem.Newest().Object // 取最新 Delta 的对象
    if d, ok := deletedObj.(DeletedFinalStateUnknown); ok {
        deletedObj = d.Obj // 避免嵌套 DeletedFinalStateUnknown
    }
    f.queueActionLocked(Deleted, DeletedFinalStateUnknown{k, deletedObj})
}
```

4. 清理 knownObjects 中的残留对象

处理本地缓存中存在但新列表和队列中均不存在的对象。

```
if f.knownObjects != nil { // knownObjects 通常是 Indexer（本地缓存）
    knownKeys := f.knownObjects.ListKeys()
    for _, k := range knownKeys {
        if keys.Has(k) || len(f.items[k]) > 0 { continue }
        deletedObj, exists, _ := f.knownObjects.GetByKey(k)
        if !exists { deletedObj = nil } // 标记为需删除
        f.queueActionLocked(Deleted, DeletedFinalStateUnknown{k, deletedObj})
    }
}
```

5. 标记初始同步状态

控制器通过 `HasSynced()` 判断是否完成全量同步（当计数器归零时返回 `true`）。

```
if !f.populated {
    f.populated = true
    f.initialPopulationCount = keys.Len() + queuedDeletions // 初始待处理事件总数
}
```

### 概述





# InDexer和ThreadSafeStore

Indexer是通过TreadSafeStore来实现的缓存机制，主要提供对于Object的条件检索能力并减轻APIServer的压力。最典型的案例就是通过namespace/key来构造key，通过TreadSafeStore来存储Object。

首先来看Indexer的interface定义：

```
type Indexer interface {
    Store
    // 根据indexName和对象，返回符合条件的所有对象
    Index(indexName string, obj interface{}) ([]interface{}, error)
    // 根据indexName和对象，返回符合条件的所有对象的Key
    IndexKeys(indexName, indexedValue string) ([]string, error)
    // 返回指定索引的所有索引值
    ListIndexFuncValues(indexName string) []string
    // 返回符合索引名和索引值的对象
    ByIndex(indexName, indexedValue string) ([]interface{}, error)
    // 获取所有Indexer
    GetIndexers() Indexers

    // 添加更多的索引实现，需要在数据加入存储之前调用
    AddIndexers(newIndexers Indexers) error
}
```

struct定义为下面所示，以Add为例，增删改查的实现基本是先调用keyFunc获取key，之后通过cacheStorage进行操作

```
type cache struct {
    // cacheStorage bears the burden of thread safety for the cache
    cacheStorage ThreadSafeStore
    // keyFunc is used to make the key for objects stored in and retrieved from items, and
    // should be deterministic.
    keyFunc KeyFunc
}

func (c *cache) Add(obj interface{}) error {
	key, err := c.keyFunc(obj)
	if err != nil {
		return KeyError{obj, err}
	}
	c.cacheStorage.Add(key, obj)
	return nil
}
```

内部持有ThreadSafeStore用于处理Object的检索，KeyFunc是获取key值的函数

KeyFunc的实现：生成<namespace>/<name>格式的Key

```
func MetaNamespaceKeyFunc(obj interface{}) (string, error) {
    if key, ok := obj.(ExplicitKey); ok {
       return string(key), nil
    }
    objName, err := ObjectToName(obj)
    if err != nil {
       return "", err
    }
    return objName.String(), nil
}
```

## ThreadSafeStore

ThreadSafeStore就是Indexer调用中的cacheStorage

接口定义为：

```
type ThreadSafeStore interface {
    Add(key string, obj interface{})
    Update(key string, obj interface{})
    Delete(key string)
    Get(key string) (item interface{}, exists bool)
    List() []interface{}
    ListKeys() []string
    Replace(map[string]interface{}, string)
    Index(indexName string, obj interface{}) ([]interface{}, error)
    IndexKeys(indexName, indexedValue string) ([]string, error)
    ListIndexFuncValues(name string) []string
    ByIndex(indexName, indexedValue string) ([]interface{}, error)
    GetIndexers() Indexers

    // AddIndexers adds more indexers to this store. This supports adding indexes after the store already has items.
    AddIndexers(newIndexers Indexers) error
    // Resync is a no-op and is deprecated
    Resync() error
}
```

threadSafeMap是具体实现，其中又包含了storeIndex -> Indexers&Indices

```
type threadSafeMap struct {
    lock  sync.RWMutex
    items map[string]interface{}

    // index implements the indexing functionality
    index *storeIndex
}

type storeIndex struct {
	// indexers maps a name to an IndexFunc
	indexers Indexers
	// indices maps a name to an Index
	indices Indices
}

// Index maps the indexed value to a set of keys in the store that match on that value
type Index map[string]sets.String

// Indexers maps a name to an IndexFunc
type Indexers map[string]IndexFunc

// Indices maps a name to an Index
type Indices map[string]Index
```

 Indexers：保存了索引函数的Map，通常是 namespace作为Key： MetaNamespaceKeyFunc作为Value

Indices：保存了计算后的索引值-> 以索引值为Key的Object Set的映射，

在具体的函数实现上都是通过updateIndices(oldObj interface{}, newObj interface{}, key string)

Add：oldObj为空，newObj为新增的Object

update：oldObj为旧Object，newObj为修改后的Object

delete：newObj为空

#### updateSingleIndex

处理逻辑

1. 获取indexFunc
2. 计算旧/新索引值
3. 获取或初始化Index，也就是map[string]Sets.String
4. 如果索引值未改变则直接返回

5. 删除或添加索引值

```
for _, value := range oldIndexValues {
    i.deleteKeyFromIndex(key, value, index)
}
for _, value := range indexValues {
    i.addKeyToIndex(key, value, index)
}
```



```
// updateSingleIndex must be called from a function that already has a lock on the cache
func (i *storeIndex) updateSingleIndex(name string, oldObj interface{}, newObj interface{}, key string) {
    var oldIndexValues, indexValues []string
    indexFunc, ok := i.indexers[name]
    if !ok {
       // Should never happen. Caller is responsible for ensuring this exists, and should call with lock
       // held to avoid any races.
       panic(fmt.Errorf("indexer %q does not exist", name))
    }
    if oldObj != nil {
       var err error
       oldIndexValues, err = indexFunc(oldObj)
       if err != nil {
          panic(fmt.Errorf("unable to calculate an index entry for key %q on index %q: %v", key, name, err))
       }
    } else {
       oldIndexValues = oldIndexValues[:0]
    }

    if newObj != nil {
       var err error
       indexValues, err = indexFunc(newObj)
       if err != nil {
          panic(fmt.Errorf("unable to calculate an index entry for key %q on index %q: %v", key, name, err))
       }
    } else {
       indexValues = indexValues[:0]
    }

    index := i.indices[name]
    if index == nil {
       index = Index{}
       i.indices[name] = index
    }

    if len(indexValues) == 1 && len(oldIndexValues) == 1 && indexValues[0] == oldIndexValues[0] {
       // We optimize for the most common case where indexFunc returns a single value which has not been changed
       return
    }

    for _, value := range oldIndexValues {
       i.deleteKeyFromIndex(key, value, index)
    }
    for _, value := range indexValues {
       i.addKeyToIndex(key, value, index)
    }
}
```

### Index

下面看一下Indexer的实现函数

```
// Index returns a list of items that match the given object on the index function.
// Index is thread-safe so long as you treat all items as immutable.
func (c *threadSafeMap) Index(indexName string, obj interface{}) ([]interface{}, error) {
    c.lock.RLock()
    defer c.lock.RUnlock()

    storeKeySet, err := c.index.getKeysFromIndex(indexName, obj)
    if err != nil {
       return nil, err
    }

    list := make([]interface{}, 0, storeKeySet.Len())
    for storeKey := range storeKeySet {
       list = append(list, c.items[storeKey])
    }
    return list, nil
}

func (i *storeIndex) getKeysFromIndex(indexName string, obj interface{}) (sets.String, error) {
	indexFunc := i.indexers[indexName]
	if indexFunc == nil {
		return nil, fmt.Errorf("Index with name %s does not exist", indexName)
	}

	indexedValues, err := indexFunc(obj)
	if err != nil {
		return nil, err
	}
	index := i.indices[indexName]

	var storeKeySet sets.String
	if len(indexedValues) == 1 {
		// In majority of cases, there is exactly one value matching.
		// Optimize the most common path - deduping is not needed here.
		storeKeySet = index[indexedValues[0]]
	} else {
		// Need to de-dupe the return list.
		// Since multiple keys are allowed, this can happen.
		storeKeySet = sets.String{}
		for _, indexedValue := range indexedValues {
			for key := range index[indexedValue] {
				storeKeySet.Insert(key)
			}
		}
	}

	return storeKeySet, nil
}
```



# ListWatch

ListWatch是Reflector的主要实现逻辑

接口设计

```
// ListerWatcher is any object that knows how to perform an initial list and start a watch on a resource.
type ListerWatcher interface {
    Lister
    Watcher
}

// Lister is any object that knows how to perform an initial list.
type Lister interface {
	// List should return a list type object; the Items field will be extracted, and the
	// ResourceVersion field will be used to start the watch in the right place.
	List(options metav1.ListOptions) (runtime.Object, error)
}

// Watcher is any object that knows how to start a watch on a resource.
type Watcher interface {
	// Watch should begin a watch at the specified version.
	//
	// If Watch returns an error, it should handle its own cleanup, including
	// but not limited to calling Stop() on the watch, if one was constructed.
	// This allows the caller to ignore the watch, if the error is non-nil.
	Watch(options metav1.ListOptions) (watch.Interface, error)
}
```

struct实现

```
// ListWatch knows how to list and watch a set of apiserver resources.  It satisfies the ListerWatcher interface.
// It is a convenience function for users of NewReflector, etc.
// ListFunc and WatchFunc must not be nil
type ListWatch struct {
    ListFunc  ListFunc
    WatchFunc WatchFunc
    // DisableChunking requests no chunking for this list watcher.
    DisableChunking bool
}

// Getter interface knows how to access Get method from RESTClient.
type Getter interface {
	Get() *restclient.Request
}

```

一般情况下ListWatch函数会初始化为

c.Get().Namespace(namespace).Resource(resource).VersionedParams(&options, metav1.ParameterCodec).Do(context.TODO()).Get()

这里对应的就是Kubernetes的REST API

```
listFunc := func(options metav1.ListOptions) (runtime.Object, error) {
		optionsModifier(&options)
		return c.Get().
			Namespace(namespace).
			Resource(resource).
			VersionedParams(&options, metav1.ParameterCodec).
			Do(context.TODO()).
			Get()
	}
```

这里的Getter就对应了Kubernetes REST API

TODO:  APIServer

> Operator中常用的ClientSet：c.AppV1().Pod().Get()的底层实现就是Getter





# Reflector

Reflector的作用是从APIServer中监听特定类型的资源，拿到资源变更的事件之后放入DeltaFIFO队列，

## 启动过程

BackoffUntil用于处理APIServer短暂失联的情况，核心的处理逻辑在ListAndWatch

```
func (r *Reflector) Run(stopCh <-chan struct{}) {
    klog.V(3).Infof("Starting reflector %s (%s) from %s", r.typeDescription, r.resyncPeriod, r.name)
    wait.BackoffUntil(func() {
       if err := r.ListAndWatch(stopCh); err != nil {
          r.watchErrorHandler(r, err)
       }
    }, r.backoffManager, true, stopCh)
    klog.V(3).Infof("Stopping reflector %s (%s) from %s", r.typeDescription, r.resyncPeriod, r.name)
}
```

ListAndWatch会先列出特定资源的所有对象，然后获取其资源版本，并通过这个资源版本来监听流程。

监听到事件后，会通过watchHandler函数将其加入DeltaFIFO

## ListAndWatch

目前版本的ListAndWatch有两种方式WatchList，还有兼容旧版本的List + Watch。使用WatchList的原因是如果对象过多，那么List请求会有较大的瞬时压力，引入watchlist可以list的请求走watch的方式

当w为空时在后面的流程中就会使用List+Watch的方式

```
func (r *Reflector) ListAndWatch(stopCh <-chan struct{}) error {
    if useWatchList {
       w, err = r.watchList(stopCh)
       if w == nil && err == nil {
          // stopCh was closed
          return nil
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
}
```

## watchHandler

用于将监听到的Event根据EventType（Add/Updatea/Delete）调用各自的处理函数，将对象追加到DeltaFIFO队列。



## Reflector初始化流程



```go
func NewReflectorWithOptions(lw ListerWatcher, expectedType interface{}, store Store, options ReflectorOptions) *Reflector {
    reflectorClock := options.Clock
    if reflectorClock == nil {
       reflectorClock = clock.RealClock{}
    }
    minWatchTimeout := defaultMinWatchTimeout
    if options.MinWatchTimeout > defaultMinWatchTimeout {
       minWatchTimeout = options.MinWatchTimeout
    }
    r := &Reflector{
       name:            options.Name,
       resyncPeriod:    options.ResyncPeriod,
       minWatchTimeout: minWatchTimeout,
       typeDescription: options.TypeDescription,
       listerWatcher:   lw,
       store:           store,
       // We used to make the call every 1sec (1 QPS), the goal here is to achieve ~98% traffic reduction when
       // API server is not healthy. With these parameters, backoff will stop at [30,60) sec interval which is
       // 0.22 QPS. If we don't backoff for 2min, assume API server is healthy and we reset the backoff.
       backoffManager:    wait.NewExponentialBackoffManager(800*time.Millisecond, 30*time.Second, 2*time.Minute, 2.0, 1.0, reflectorClock),
       clock:             reflectorClock,
       watchErrorHandler: WatchErrorHandler(DefaultWatchErrorHandler),
       expectedType:      reflect.TypeOf(expectedType),
    }

    if r.name == "" {
       r.name = naming.GetNameFromCallsite(internalPackages...)
    }

    if r.typeDescription == "" {
       r.typeDescription = getTypeDescriptionFromObject(expectedType)
    }

    if r.expectedGVK == nil {
       r.expectedGVK = getExpectedGVKFromObject(expectedType)
    }

    // don't overwrite UseWatchList if already set
    // because the higher layers (e.g. storage/cacher) disabled it on purpose
    if r.UseWatchList == nil {
       r.UseWatchList = ptr.To(clientfeatures.FeatureGates().Enabled(clientfeatures.WatchListClient))
    }

    return r
}
```











# Informer 

Informer从DeltaFIFO中POP相应的Object，之后通过Indexer将Object和索引存入本地Cache，接着触发相应的事件处理函数

Informer接口定义为Controller

Run是核心，负责：

1. 构造Reflector并利用ListerWatcher将对象 Event更新到DeltaFIFO当中
2. 从DeltaFIFO中Pop对象后调用ProcessFunc来处理

```
type Controller interface {
    // Run does two things.  One is to construct and run a Reflector
    // to pump objects/notifications from the Config's ListerWatcher
    // to the Config's Queue and possibly invoke the occasional Resync
    // on that Queue.  The other is to repeatedly Pop from the Queue
    // and process with the Config's ProcessFunc.  Both of these
    // continue until `stopCh` is closed.
    Run(stopCh <-chan struct{})

    // HasSynced delegates to the Config's Queue
    HasSynced() bool

    // LastSyncResourceVersion delegates to the Reflector when there
    // is one, otherwise returns the empty string
    LastSyncResourceVersion() string
}
```

实现为controller

```
// `*controller` implements Controller
type controller struct {
    config         Config
    reflector      *Reflector
    reflectorMutex sync.RWMutex
    clock          clock.Clock
}
```



# Run

1. 防止重复启动
2. 初始化DeltaFIFO、Controller
3. 启动缓存检测和持剑处理器
4. 启动主循环

```go
func (s *sharedIndexInformer) Run(stopCh <-chan struct{}) {
    if s.HasStarted() {
       klog.Warningf("The sharedIndexInformer has started, run more than once is not allowed")
       return
    }

    func() {
       s.startedLock.Lock()
       defer s.startedLock.Unlock()

       fifo := NewDeltaFIFOWithOptions(DeltaFIFOOptions{
          KnownObjects:          s.indexer,
          EmitDeltaTypeReplaced: true,
          Transformer:           s.transform,
       })

       cfg := &Config{
          Queue:             fifo,
          ListerWatcher:     s.listerWatcher,
          ObjectType:        s.objectType,
          ObjectDescription: s.objectDescription,
          FullResyncPeriod:  s.resyncCheckPeriod,
          RetryOnError:      false,
          ShouldResync:      s.processor.shouldResync,

          Process:           s.HandleDeltas,
          WatchErrorHandler: s.watchErrorHandler,
       }

       s.controller = New(cfg)
       s.controller.(*controller).clock = s.clock
       s.started = true
    }()

    wg.StartWithChannel(processorStopCh, s.cacheMutationDetector.Run)
    wg.StartWithChannel(processorStopCh, s.processor.run)

    s.controller.Run(stopCh)
}
```

HandleDeltas在Config中初始化并通过Config传入到Controller。

### controller.Run

构造Reflector并执行controller.processLoop

```
func (c *controller) Run(stopCh <-chan struct{}) {
    defer utilruntime.HandleCrash()
    go func() {
       <-stopCh
       c.config.Queue.Close()
    }()
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

    c.reflectorMutex.Lock()
    c.reflector = r
    c.reflectorMutex.Unlock()

    wait.Until(c.processLoop, time.Second, stopCh)
    wg.Wait()
}
```

### processLoop

不断从DeltaFIFO中Pop出一个对象并交由PopProcessFunc处理

失败会将该object重新加入到DeltaFIFO当中PopProcessFunc就是之前提到的HandleDeltas（c.config.Process）

```
func (c *controller) processLoop() {
    for {
       obj, err := c.config.Queue.Pop(PopProcessFunc(c.config.Process))
       if err != nil {
          if err == ErrFIFOClosed {
             return
          }
          if c.config.RetryOnError {
             // This is the safe way to re-enqueue.
             c.config.Queue.AddIfNotPresent(obj)
          }
       }
    }
}
```

### HandleDeltas

HandleDeltas中会调用processDeltas，这里会从新到旧遍历deltas，根据获取到的delta类型来操作Indexer，更新本地缓存，并分发通知。

```
func processDeltas(
	// Object which receives event notifications from the given deltas
	handler ResourceEventHandler,
	clientState Store,
	deltas Deltas,
	isInInitialList bool,
) error {
	// from oldest to newest
	for _, d := range deltas {
		obj := d.Object

		switch d.Type {
		case Sync, Replaced, Added, Updated:
			if old, exists, err := clientState.Get(obj); err == nil && exists {
				if err := clientState.Update(obj); err != nil {
					return err
				}
				handler.OnUpdate(old, obj)
			} else {
				if err := clientState.Add(obj); err != nil {
					return err
				}
				handler.OnAdd(obj, isInInitialList)
			}
		case Deleted:
			if err := clientState.Delete(obj); err != nil {
				return err
			}
			handler.OnDelete(obj)
		}
	}
	return nil
}
```





# SharedIndexInformer

![img](https://myblog-1307634347.cos.ap-guangzhou.myqcloud.com/blog/202301061840196.png)

`sharedIndexInformer` 相比普通的 informer 来说, 可以共享 reflector 反射器, 业务代码可以注册多个 resourceEventHandler 方法, 无需重复创建 informer 做监听及事件注册.

如果相同资源实例化多个 informer, 那么每个 informer 都有一个 reflector 和 store. 不仅会有数据序列化的开销, 而且缓存 store 不能复用, 可能一个对象存在多个 informer 的 store 里.

实现上是通过ProcessListener中维护多个listener

并且支持动态注册Handler



https://www.qikqiak.com/k8strain/k8s-code/client-go/deltafifo/