---
title: kubelet源码笔记2-pod创建
date: 2025-03-05
update: 2025-03-09
comment: false
tags:
  - Cilium
  - BPF
categories:
  - BPF
---

kubelet 是 kubernetes 集群中最重要的组件之一，它负责管理节点上的容器。本节主要记录一下 `kubelet` 中 `pod` 的创建流程。

*<!--more-->*
# Pod创建流程

# 在 `kubelet` 启动的时候，会通过三种 pod source 方式来获取 pod 信息：

1. file: 这种方式只要针对 staticPod 来处理，定时观察配置文件是否发生变更情况来写入 pod
2. http方式： 就是通过一个http请求一个 URL 地址，用来获取 `simple Pod` 信息
3. clientSet: 这种方式直接与 APIServer 通讯，对 pod 进行watch

上面这三种 `pod source` ，一旦有pod 的变更信息，将直接写入一个 `kubetypes.PodUpdate` 这个 `channel`，写入的位置如下所示

```Go
// define file config source
if kubeCfg.StaticPodPath != "" {
    klog.InfoS("Adding static pod path", "path", kubeCfg.StaticPodPath)
    config.NewSourceFile(kubeCfg.StaticPodPath, nodeName, kubeCfg.FileCheckFrequency.Duration, cfg.Channel(ctx, kubetypes.FileSource))
}

// define url config source
if kubeCfg.StaticPodURL != "" {
    klog.InfoS("Adding pod URL with HTTP header", "URL", kubeCfg.StaticPodURL, "header", manifestURLHeader)
    config.NewSourceURL(kubeCfg.StaticPodURL, manifestURLHeader, nodeName, kubeCfg.HTTPCheckFrequency.Duration, cfg.Channel(ctx, kubetypes.HTTPSource))
}

if kubeDeps.KubeClient != nil {
    klog.InfoS("Adding apiserver pod source")
    config.NewSourceApiserver(kubeDeps.KubeClient, nodeName, nodeHasSynced, cfg.Channel(ctx, kubetypes.ApiserverSource))
}
```

在之前的启动函数中

 `Kubelet.Run(updates <-chan kubetypes.PodUpdate{})` 中参数 `updates`是一个 `kubetypes.PodUpdate`的类型

```Go
type PodUpdate struct {
    Pods   []*v1.Pod
    Op     PodOperation
    Source string
}

// PodOperation defines what changes will be made on a pod configuration.
type PodOperation int

// These constants identify the PodOperations that can be made on a pod configuration.
const (
    // SET is the current pod configuration.
    SET PodOperation = iota
    // ADD signifies pods that are new to this source.
    ADD
    // DELETE signifies pods that are gracefully deleted from this source.
    DELETE
    // REMOVE signifies pods that have been removed from this source.
    REMOVE
    // UPDATE signifies pods have been updated in this source.
    UPDATE
    // RECONCILE signifies pods that have unexpected status in this source,
    // kubelet should reconcile status with this source.
    RECONCILE
)
```

PodUpdata定义了对于Pod的操作

而在Run函数的最后调用了kl.syncLoop(ctx, updates, kl)，这里的updates参数就是PodUpdate类型，kl是SyncHandler的接口，同时也是实例化的kubelet对象本身可以用来处理Pod变更事件。

# syncLoop

```Go
// syncLoop is the main loop for processing changes. It watches for changes from
// three channels (file, apiserver, and http) and creates a union of them. For
// any new change seen, will run a sync against desired state and running state. If
// no changes are seen to the configuration, will synchronize the last known desired
// state every sync-frequency seconds. Never returns.
func (kl *Kubelet) syncLoop(ctx context.Context, updates <-chan kubetypes.PodUpdate, handler SyncHandler) {

    for {
        if err := kl.runtimeState.runtimeErrors(); err != nil {
            klog.ErrorS(err, "Skipping pod synchronization")
            // exponential backoff
            time.Sleep(duration)
            duration = time.Duration(math.Min(float64(max), factor*float64(duration)))
            continue
        }
        
        // reset backoff if we have a success
        duration = base
       
        kl.syncLoopMonitor.Store(kl.clock.Now())
        if !kl.syncLoopIteration(ctx, updates, handler, syncTicker.C, housekeepingTicker.C, plegCh) {
            break
        }
        kl.syncLoopMonitor.Store(kl.clock.Now())
        }
    }

}
```

参数介绍：

1. `configCh`: 从中读取配置事件的通道，也就是形参 `updates`
2. `handler`: 将 pod 分发到的 `SyncHandler`
3. `syncCh`: 读取周期性同步事件的通道，当前固定为 `1` 秒
4. `housekeepingCh`: 读取 housekeeping 事件的通道
5. `plegCh`: 读取 PLEG 更新的通道

SyncLoop是kubelet的主循环们可以监听到`channel` ，当`file`, `apiserver`, 和 `http` 三种 pod source 的pod变更并合并它们。对于任何变更会对比desired state和当前的running state。未监听到任何变化也会定期执行状态对比。

# syncLoopIteration

当updates中有消息时，会根据Pod操作类型触发相应的函数

```Go
case u, open := <-configCh:
    // Update from a config source; dispatch it to the right handler
    // callback.
    if !open {
       klog.ErrorS(nil, "Update channel is closed, exiting the sync loop")
       return false
    }

    switch u.Op {
    case kubetypes.ADD:
       klog.V(2).InfoS("SyncLoop ADD", "source", u.Source, "pods", klog.KObjSlice(u.Pods))
       // After restarting, kubelet will get all existing pods through
       // ADD as if they are new pods. These pods will then go through the
       // admission process and *may* be rejected. This can be resolved
       // once we have checkpointing.
       handler.HandlePodAdditions(u.Pods)
    case kubetypes.UPDATE:
       klog.V(2).InfoS("SyncLoop UPDATE", "source", u.Source, "pods", klog.KObjSlice(u.Pods))
       handler.HandlePodUpdates(u.Pods)
    case kubetypes.REMOVE:
       klog.V(2).InfoS("SyncLoop REMOVE", "source", u.Source, "pods", klog.KObjSlice(u.Pods))
       handler.HandlePodRemoves(u.Pods)
    case kubetypes.RECONCILE:
       klog.V(4).InfoS("SyncLoop RECONCILE", "source", u.Source, "pods", klog.KObjSlice(u.Pods))
       handler.HandlePodReconcile(u.Pods)
    case kubetypes.DELETE:
       klog.V(2).InfoS("SyncLoop DELETE", "source", u.Source, "pods", klog.KObjSlice(u.Pods))
       // DELETE is treated as a UPDATE because of graceful deletion.
       handler.HandlePodUpdates(u.Pods)
    case kubetypes.SET:
       // TODO: Do we want to support this?
       klog.ErrorS(nil, "Kubelet does not support snapshot update")
    default:
       klog.ErrorS(nil, "Invalid operation type received", "operation", u.Op)
    }

    kl.sourcesReady.AddSource(u.Source)
```

# HandlePodAdditions

这里以Add操作添加Pod为例

```Go
// HandlePodAdditions is the callback in SyncHandler for pods being added from
// a config source.
func (kl *Kubelet) HandlePodAdditions(pods []*v1.Pod) {

    sort.Sort(sliceutils.PodsByCreationTime(pods))
    
    if utilfeature.DefaultFeatureGate.Enabled(features.InPlacePodVerticalScaling) {
        kl.podResizeMutex.Lock()
        defer kl.podResizeMutex.Unlock()
    }
    
    for _, pod := range pods {
        
        existingPods := kl.podManager.GetPods()
        // Always add the pod to the pod manager. Kubelet relies on the pod
        // manager as the source of truth for the desired state. If a pod does
        // not exist in the pod manager, it means that it has been deleted in
        // the apiserver and no action (other than cleanup) is required.
        kl.podManager.AddPod(pod)
        
        // 如果是mirrorPod，直接update
        pod, mirrorPod, wasMirror := kl.podManager.GetPodAndMirrorPod(pod)
        if wasMirror {
            kl.podWorkers.UpdatePod(UpdatePodOptions{
                Pod:        pod,
                MirrorPod:  mirrorPod,
                UpdateType: kubetypes.SyncPodUpdate,
                StartTime:  start,
            })
            continue
        }
        
        // Only go through the admission process if the pod is not requested
        // for termination by another part of the kubelet. If the pod is already
        // using resources (previously admitted), the pod worker is going to be
        // shutting it down. If the pod hasn't started yet, we know that when
        // the pod worker is invoked it will also avoid setting up the pod, so
        // we simply avoid doing any work.
        if !kl.podWorkers.IsPodTerminationRequested(pod.UID) {
        
            // We failed pods that we rejected, so activePods include all admitted
            // pods that are alive.
            activePods := kl.filterOutInactivePods(existingPods)
            
            if utilfeature.DefaultFeatureGate.Enabled(features.InPlacePodVerticalScaling) {
                // To handle kubelet restarts, test pod admissibility using AllocatedResources values
                // (for cpu & memory) from checkpoint store. If found, that is the source of truth.
                // 调整cpu和mem
                podCopy := pod.DeepCopy()
                kl.updateContainerResourceAllocation(podCopy)
                
                // Check if we can admit the pod; if not, reject it.
                if ok, reason, message := kl.canAdmitPod(activePods, podCopy); !ok {
                    kl.rejectPod(pod, reason, message)
                    continue
                }
                // For new pod, checkpoint the resource values at which the Pod has been admitted
                if err := kl.statusManager.SetPodAllocation(podCopy); err != nil {
                    //TODO(vinaykul,InPlacePodVerticalScaling): Can we recover from this in some way? Investigate
                    klog.ErrorS(err, "SetPodAllocation failed", "pod", klog.KObj(pod))
                }
            } else {
                // Check if we can admit the pod; if not, reject it.
                if ok, reason, message := kl.canAdmitPod(activePods, pod); !ok {
                   kl.rejectPod(pod, reason, message)
                   continue
                }
            }
        }
        
        kl.podWorkers.UpdatePod(UpdatePodOptions{
            Pod:        pod,
            MirrorPod:  mirrorPod,
            UpdateType: kubetypes.SyncPodCreate,
            StartTime:  start,
        })
}
```

1. kl.podManager是kubelet的组件，抽象了kubelet的Pods各种来源。
2. Pod InPlacePodVerticalScaling是Kubernetes中的一个功能，用于在保持Pod运行的同时，对Pod的资源配置进行垂直扩缩容。它允许你调整Pod的CPU和内存资源配置，而无需删除或重新创建Pod。Kubernetes将根据新的资源配置来重新分配资源，并在不中断应用程序的情况下继续运行Pod。

主要的流程：

1. 根据普通Pod获取对应的mirror pod
2. podManager中Add新Pod
3. 调用kl.podWorkers.UpdatePod，这里的类型为*SyncPodCreate*

`SyncPodSync` 表示pod已同步为 *`desired state`*

`SyncPodUpdate` 表示 Pod 从 source 更新

`SyncPodCreate` 表示 Pod 从 source 创建

`SyncPodKill` 表示当前Pod中没有处于运行中的 `containers`，对于已 stopped 的Pod 未来可能

# podWorkers.UpdatePod

`UpdatePodOptions` 是一个 UpdatePod 专用的数据类型，它的数据结构为

```Go
// UpdatePodOptions is an options struct to pass to a UpdatePod operation.
type UpdatePodOptions struct {
    // The type of update (create, update, sync, kill).
    UpdateType kubetypes.SyncPodType
    // StartTime is an optional timestamp for when this update was created. If set,
    // when this update is fully realized by the pod worker it will be recorded in
    // the PodWorkerDuration metric.
    StartTime time.Time
    // Pod to update. Required.
    Pod *v1.Pod
    // MirrorPod is the mirror pod if Pod is a static pod. Optional when UpdateType
    // is kill or terminated.
    MirrorPod *v1.Pod
    // RunningPod is a runtime pod that is no longer present in config. Required
    // if Pod is nil, ignored if Pod is set.
    RunningPod *kubecontainer.Pod
    // KillPodOptions is used to override the default termination behavior of the
    // pod or to update the pod status after an operation is completed. Since a
    // pod can be killed for multiple reasons, PodStatusFunc is invoked in order
    // and later kills have an opportunity to override the status (i.e. a preemption
    // may be later turned into an eviction).
    KillPodOptions *KillPodOptions
}
UpdateType:` 更新类型，值可以为 `create`,`update`,`sync`, `kill
```

`StartTime:` 可选字段。创建此更新时的时间戳

`Pod:` 要更新的Pod

`MirrorPod:` 如果pod是静态pod，那么MirrorPod就是镜像pod。如果 UpdateType为`kill` 或 `terminated` 时为可选。

`RunningPod：` RunningPod是一个 `runtime pod`，表示它在配置中已不存在。如果Pod为 `nil` 则为必需的，如果设置了Pod，则可以忽略

`KillPodOptions:` KillPodOptions用于覆盖pod的默认终止行为，或在操作完成后更新pod状态。由于pod可能因多种原因而被终止，因此 `PodStatusFunc` 会按顺序调用，以后的终止有机会覆盖状态（抢占稍后可能会变成驱逐）。

## podWorker

podWork是kubelet中的组件，主要实现对Pod进行一系列操作，它实现了PodWorkers接口

```Go
type PodWorkers interface {
    UpdatePod(options UpdatePodOptions)
    SyncKnownPods(desiredPods []*v1.Pod) (knownPods map[types.UID]PodWorkerSync)
    IsPodKnownTerminated(uid types.UID) bool    
    CouldHaveRunningContainers(uid types.UID) bool    
    ShouldPodBeFinished(uid types.UID) bool    
    IsPodTerminationRequested(uid types.UID) bool    
    ShouldPodContainersBeTerminating(uid types.UID) bool    
    ShouldPodRuntimeBeRemoved(uid types.UID) bool    
    ShouldPodContentBeRemoved(uid types.UID) bool    
    IsPodForMirrorPodTerminatingByFullName(podFullname string) bool
}
```

### UpdatePod()

通知 `pod worker`对一个pod做出变更，然后由每一个goroutine 按 `FIFO` 的顺序进行处理（UID）。 pod 的状态将被传递给 `syncPod` 方法，直到pod 被标记为已 `deleted`，它到达 `terminal`阶段（成功/失败）或者pod被kubelet驱逐。一旦发生这种情况，`syncTerminatingPod` 方法将被调用直到它成功退出，之后所有的 UpdatePod() 调用也将被忽略，直到过期。 一个Pod 如果是 *terminated* 状态，则永远也不可能被重启。

```Go
// UpdatePod carries a configuration change or termination state to a pod. A pod is either runnable,
// terminating, or terminated, and will transition to terminating if: deleted on the apiserver,
// discovered to have a terminal phase (Succeeded or Failed), or evicted by the kubelet.
func (p *podWorkers) UpdatePod(options UpdatePodOptions) {
    // Handle when the pod is an orphan (no config) and we only have runtime status by running only
    // the terminating part of the lifecycle. A running pod contains only a minimal set of information
    // about the pod
    // 1.获取到UID，NS，Name
    if runningPod := options.RunningPod; runningPod != nil {
        if options.Pod == nil {
           // the sythetic pod created here is used only as a placeholder and not tracked
           if options.UpdateType != kubetypes.SyncPodKill {
              klog.InfoS("Pod update is ignored, runtime pods can only be killed", "pod", klog.KRef(runningPod.Namespace, runningPod.Name), "podUID", runningPod.ID, "updateType", options.UpdateType)
              return
           }
           uid, ns, name = runningPod.ID, runningPod.Namespace, runningPod.Name
           isRuntimePod = true
        } else {
           options.RunningPod = nil
           uid, ns, name = options.Pod.UID, options.Pod.Namespace, options.Pod.Name
           klog.InfoS("Pod update included RunningPod which is only valid when Pod is not specified", "pod", klog.KRef(ns, name), "podUID", uid, "updateType", options.UpdateType)
        }
    } else {
        uid, ns, name = options.Pod.UID, options.Pod.Namespace, options.Pod.Name
    }
    
    
    // 2. 根据 pod.UID 获取当前Pod的同步状态，如果为首次同步则设置并记录当前pod的同步状态
    status, ok := p.podSyncStatuses[uid]
    if !ok {
        firstTime = true
        status = &podSyncStatus{
            syncedAt: now,
            fullname: kubecontainer.BuildPodFullName(name, ns),
        }
        ......
        p.podSyncStatuses[uid] = status
   }
   
   // RunningPods represent an unknown pod execution and don't contain pod spec information
    // sufficient to perform any action other than termination. If we received a RunningPod
    // after a real pod has already been provided, use the most recent spec instead. Also,
    // once we observe a runtime pod we must drive it to completion, even if we weren't the
    // ones who started it.
    // 3. RunningPods表示未知的pod执行，并且不包含足以执行除终止之外的任何操作的pod规范信息。这里根据不同情况给 Pod 字段赋值
    pod := options.Pod
    if isRuntimePod {...}
    
    // When we see a create update on an already terminating pod, that implies two pods with the same UID were created in
    // close temporal proximity (usually static pod but it's possible for an apiserver to extremely rarely do something
    // similar) - flag the sync status to indicate that after the pod terminates it should be reset to "not running" to
    // allow a subsequent add/update to start the pod worker again. This does not apply to the first time we see a pod,
    // such as when the kubelet restarts and we see already terminated pods for the first time.
    if !firstTime && status.IsTerminationRequested() {...}
    
    // once a pod is terminated by UID, it cannot reenter the pod worker (until the UID is purged by housekeeping)
    if status.IsFinished() {...}
    
    // check for a transition to terminating
    var becameTerminating bool
    if !status.IsTerminationRequested() {...}
    
    // once a pod is terminating, all updates are kills and the grace period can only decrease
    var wasGracePeriodShortened bool
    switch {
    case status.IsTerminated():
    case status.IsTerminationRequested():
    default:
    }
    
    // 4. 创建并启动一个 pod worker 的goroutine
    // start the pod worker goroutine if it doesn't exist
    podUpdates, exists := p.podUpdates[uid]
    if !exists {
        // buffer the channel to avoid blocking this method
        // 为当前Pod创建一个PodWorkder专用的PodUpdates的channel，便于接受后期的变更信号
        podUpdates = make(chan struct{}, 1)
        p.podUpdates[uid] = podUpdates
    
        // ensure that static pods start in the order they are received by UpdatePod
        if kubetypes.IsStaticPod(pod) {
           p.waitingToStartStaticPodsByFullname[status.fullname] =
              append(p.waitingToStartStaticPodsByFullname[status.fullname], uid)
        }
    
        // allow testing of delays in the pod update channel
        var outCh <-chan struct{}
        if p.workerChannelFn != nil {
           outCh = p.workerChannelFn(uid, podUpdates)
        } else {
           outCh = podUpdates
        }
    
        // spawn a pod worker
        go func() {
           // TODO: this should be a wait.Until with backoff to handle panics, and
           // accept a context for shutdown
           defer runtime.HandleCrash()
           defer klog.V(3).InfoS("Pod worker has stopped", "podUID", uid)
           // 启动PodWorkerLoop服务
           p.podWorkerLoop(uid, outCh)
        }()
    }
    
    
    // notify the pod worker there is a pending update
    // 发送信号到podUpdates channel， 通知pod worker 这是pending update
    status.pendingUpdate = &options
    status.working = true
    klog.V(4).InfoS("Notifying pod of pending update", "pod", klog.KRef(ns, name), "podUID", uid, "workType", status.WorkType())
    select {
    case podUpdates <- struct{}{}:
    default:
    }
    
    if (becameTerminating || wasGracePeriodShortened) && status.cancelFn != nil {
        klog.V(3).InfoS("Cancelling current pod sync", "pod", klog.KRef(ns, name), "podUID", uid, "workType", status.WorkType())
        status.cancelFn()
        return
    }
}
```

这里如果Pod是首次podUpdate，则开启一个PodWorker 的goroutine，并创建一个PodUpdates channel以便接收podUpdates signal，之后会更新status，并向刚才的podUpdate channel发送变更信号。

podWorkerLoop负责具体处理Pod的顺序状态更新，达到最终状态会退出。

### podWorkerLoop

Loop负责驱动Pod主要分为四个阶段：

1. 等待启动：即保证在同一个时间内没有两个相同的ID或相同的完整名称的Pod同时运行
2. 同步：通过协调所需的pod规范和pod的运行时状态来编排pod设置
3. 终止：确保Pod中所有正在运行的容器都已停止
4. 已终止：清理在删除pod之前必须释放的所有资源

podWorkerLoop由传递给UpdatePod的更新和SyncKnownPods()驱动。如果某个特定的同步方法失败， `p.workerQueue` 将使用 `backoff` 进行更新，但kubelet负责触发新的UpdatePod调用。 `SyncKnownPods()` 将只重试调用方不再知道的pods。当pod转换为 `working->terminating` 或 `terminating->terminated` 时，下一次更新会立即排队，不需要kubelet操作。

```Go
// podWorkerLoop manages sequential state updates to a pod in a goroutine, exiting once the final
// state is reached. The loop is responsible for driving the pod through four main phases:
//
// 1. Wait to start, guaranteeing no two pods with the same UID or same fullname are running at the same time
// 2. Sync, orchestrating pod setup by reconciling the desired pod spec with the runtime state of the pod
// 3. Terminating, ensuring all running containers in the pod are stopped
// 4. Terminated, cleaning up any resources that must be released before the pod can be deleted
//
// The podWorkerLoop is driven by updates delivered to UpdatePod and by SyncKnownPods. If a particular
// sync method fails, p.workerQueue is updated with backoff but it is the responsibility of the kubelet
// to trigger new UpdatePod calls. SyncKnownPods will only retry pods that are no longer known to the
// caller. When a pod transitions working->terminating or terminating->terminated, the next update is
// queued immediately and no kubelet action is required.
func (p *podWorkers) podWorkerLoop(podUID types.UID, podUpdates <-chan struct{}) {

    for range podUpdates {
        ctx, update, canStart, canEverStart, ok := p.startPodSync(podUID)
        // If we had no update waiting, it means someone initialized the channel without filling out pendingUpdate.
        if !ok {
            continue
        }
        
        // 2. 同步Pod, 针对SyncPod，TerminatingPod和TerminatedPod三种情况处理。
        err := func() error {
            // The worker is responsible for ensuring the sync method sees the appropriate
            // status updates on resyncs (the result of the last sync), transitions to
            // terminating (no wait), or on terminated (whatever the most recent state is).
            // Only syncing and terminating can generate pod status changes, while terminated
            // pods ensure the most recent status makes it to the api server.
            // worker 负责确保sync 方法在重新同步时可以看到恰当的状态更新（上次同步的结果）、转换到
            // terminated状态（不在等待）、或者正处于terminated状态
            // 只有 syncing and terminating 可以更改Pod的状态，已终止的Pod需要确保最近的状态可以
            // 传递到API服务器
            var status *kubecontainer.PodStatus
            var err error
            switch {
            case update.Options.RunningPod != nil:
               // when we receive a running pod, we don't need status at all because we are
               // guaranteed to be terminating and we skip updates to the pod
            default:
               // wait until we see the next refresh from the PLEG via the cache (max 2s)
               // TODO: this adds ~1s of latency on all transitions from sync to terminating
               //  to terminated, and on all termination retries (including evictions). We should
               //  improve latency by making the pleg continuous and by allowing pod status
               //  changes to be refreshed when key events happen (killPod, sync->terminating).
               //  Improving this latency also reduces the possibility that a terminated
               //  container's status is garbage collected before we have a chance to update the
               //  API server (thus losing the exit code).
               // 需要等待在cache中得到PLEG的下一次刷新
               status, err = p.podCache.GetNewerThan(update.Options.Pod.UID, lastSyncTime)
        
               if err != nil {
                  // This is the legacy event thrown by manage pod loop all other events are now dispatched
                  // from syncPodFn
                  p.recorder.Eventf(update.Options.Pod, v1.EventTypeWarning, events.FailedSync, "error determining status: %v", err)
                  return err
               }
            }
        
            // Take the appropriate action (illegal phases are prevented by UpdatePod)
            switch {
             // TerminatedPod 表示pod已停止，不能再有正在运行的容器，并且可以执行任何前台清理。
            case update.WorkType == TerminatedPod:
               err = p.podSyncer.SyncTerminatedPod(ctx, update.Options.Pod, status)
            // TerminatingPod 是指Pod不再被设置，但某些容器可能正在运行并被销毁。
            case update.WorkType == TerminatingPod:
               var gracePeriod *int64
               if opt := update.Options.KillPodOptions; opt != nil {
                  gracePeriod = opt.PodTerminationGracePeriodSecondsOverride
               }
               podStatusFn := p.acknowledgeTerminating(podUID)
        
               // if we only have a running pod, terminate it directly
               if update.Options.RunningPod != nil {
                  err = p.podSyncer.SyncTerminatingRuntimePod(ctx, update.Options.RunningPod)
               } else {
                  err = p.podSyncer.SyncTerminatingPod(ctx, update.Options.Pod, status, gracePeriod, podStatusFn)
               }
        
            default:
            // 重点:同步Pod
               isTerminal, err = p.podSyncer.SyncPod(ctx, update.Options.UpdateType, update.Options.Pod, update.Options.MirrorPod, status)
            }
        
            lastSyncTime = p.clock.Now()
            return err
        }()
        
        var phaseTransition bool
        switch {
        case err == context.Canceled:
            // when the context is cancelled we expect an update to already be queued
            klog.V(2).InfoS("Sync exited with context cancellation error", "pod", podRef, "podUID", podUID, "updateType", update.WorkType)
        
        case err != nil:
            // we will queue a retry
            klog.ErrorS(err, "Error syncing pod, skipping", "pod", podRef, "podUID", podUID)
        
        case update.WorkType == TerminatedPod:
            // we can shut down the worker
            p.completeTerminated(podUID)
            if start := update.Options.StartTime; !start.IsZero() {
               metrics.PodWorkerDuration.WithLabelValues("terminated").Observe(metrics.SinceInSeconds(start))
            }
            klog.V(4).InfoS("Processing pod event done", "pod", podRef, "podUID", podUID, "updateType", update.WorkType)
            return
        
        case update.WorkType == TerminatingPod:
            // pods that don't exist in config don't need to be terminated, other loops will clean them up
            if update.Options.RunningPod != nil {
               p.completeTerminatingRuntimePod(podUID)
               if start := update.Options.StartTime; !start.IsZero() {
                  metrics.PodWorkerDuration.WithLabelValues(update.Options.UpdateType.String()).Observe(metrics.SinceInSeconds(start))
               }
               klog.V(4).InfoS("Processing pod event done", "pod", podRef, "podUID", podUID, "updateType", update.WorkType)
               return
            }
            // otherwise we move to the terminating phase
            p.completeTerminating(podUID)
            phaseTransition = true
        
        case isTerminal:
            // if syncPod indicated we are now terminal, set the appropriate pod status to move to terminating
            klog.V(4).InfoS("Pod is terminal", "pod", podRef, "podUID", podUID, "updateType", update.WorkType)
            p.completeSync(podUID)
            phaseTransition = true
        }
        
        // queue a retry if necessary, then put the next event in the channel if any
        // 重新入队p.workQueue
        p.completeWork(podUID, phaseTransition, err)
        if start := update.Options.StartTime; !start.IsZero() {
            metrics.PodWorkerDuration.WithLabelValues(update.Options.UpdateType.String()).Observe(metrics.SinceInSeconds(start))
        }
        
    }

}
```

整体流程：

1. 试图更新 Pod 的状态为 `started`，调用 `startPodSync()`
2. 同步Pod信息，同步操作为 `SyncPod`、`TerminatingPod` 和 `TerminatedPod` 中的一个
3. 将 Pod 重新加入 `workQueue` 队列，交给下一个组件

### startPodSync() 

对于 `startPodSync()` 函数，会消费一个`pending update`，初始化上下文，决定pod是否已经`started` 或是否可以 `started`，并更新缓存过的pod状态，以便下游组件可以观察到 `pod worker` goroutine 正在尝试做什么。

```Go
// startPodSync is invoked by each pod worker goroutine when a message arrives on the pod update channel.
// This method consumes a pending update, initializes a context, decides whether the pod is already started
// or can be started, and updates the cached pod state so that downstream components can observe what the
// pod worker goroutine is currently attempting to do. If ok is false, there is no available event. If any
// of the boolean values is false, ensure the appropriate cleanup happens before returning.
//
// This method should ensure that either status.pendingUpdate is cleared and merged into status.activeUpdate,
// or when a pod cannot be started status.pendingUpdate remains the same. Pods that have not been started
// should never have an activeUpdate because that is exposed to downstream components on started pods.
func (p *podWorkers) startPodSync(podUID types.UID) (ctx context.Context, update podWork, canStart, canEverStart, ok bool) {
    p.podLock.Lock()
    defer p.podLock.Unlock()

    // verify we are known to the pod worker still
    status, ok := p.podSyncStatuses[podUID]
    if !ok {
       // pod status has disappeared, the worker should exit
       klog.V(4).InfoS("Pod worker no longer has status, worker should exit", "podUID", podUID)
       return nil, update, false, false, false
    }
    if !status.working {
       // working is used by unit tests to observe whether a worker is currently acting on this pod
       klog.V(4).InfoS("Pod should be marked as working by the pod worker, programmer error", "podUID", podUID)
    }
    if status.pendingUpdate == nil {
       // no update available, this means we were queued without work being added or there is a
       // race condition, both of which are unexpected
       status.working = false
       klog.V(4).InfoS("Pod worker received no pending work, programmer error?", "podUID", podUID)
       return nil, update, false, false, false
    }

    // consume the pending update
    update.WorkType = status.WorkType()
    update.Options = *status.pendingUpdate
    status.pendingUpdate = nil
    select {
    case <-p.podUpdates[podUID]:
       // ensure the pod update channel is empty (it is only ever written to under lock)
    default:
    }

    // initialize a context for the worker if one does not exist
    if status.ctx == nil || status.ctx.Err() == context.Canceled {
       status.ctx, status.cancelFn = context.WithCancel(context.Background())
    }
    ctx = status.ctx

    // if we are already started, make our state visible to downstream components
    if status.IsStarted() {
       status.mergeLastUpdate(update.Options)
       return ctx, update, true, true, true
    }

    // if we are already terminating and we only have a running pod, allow the worker
    // to "start" since we are immediately moving to terminating
    if update.Options.RunningPod != nil && update.WorkType == TerminatingPod {
       status.mergeLastUpdate(update.Options)
       return ctx, update, true, true, true
    }

    // If we receive an update where Pod is nil (running pod is set) but haven't
    // started yet, we can only terminate the pod, not start it. We should not be
    // asked to start such a pod, but guard here just in case an accident occurs.
    if update.Options.Pod == nil {
       status.mergeLastUpdate(update.Options)
       klog.V(4).InfoS("Running pod cannot start ever, programmer error", "pod", klog.KObj(update.Options.Pod), "podUID", podUID, "updateType", update.WorkType)
       return ctx, update, false, false, true
    }

    // verify we can start
    canStart, canEverStart = p.allowPodStart(update.Options.Pod)
    switch {
    case !canEverStart:
       p.cleanupUnstartedPod(update.Options.Pod, status)
       status.working = false
       if start := update.Options.StartTime; !start.IsZero() {
          metrics.PodWorkerDuration.WithLabelValues("terminated").Observe(metrics.SinceInSeconds(start))
       }
       klog.V(4).InfoS("Pod cannot start ever", "pod", klog.KObj(update.Options.Pod), "podUID", podUID, "updateType", update.WorkType)
       return ctx, update, canStart, canEverStart, true
    case !canStart:
       // this is the only path we don't start the pod, so we need to put the change back in pendingUpdate
       status.pendingUpdate = &update.Options
       status.working = false
       klog.V(4).InfoS("Pod cannot start yet", "pod", klog.KObj(update.Options.Pod), "podUID", podUID)
       return ctx, update, canStart, canEverStart, true
    }

    // mark the pod as started
    status.startedAt = p.clock.Now()
    status.mergeLastUpdate(update.Options)

    // If we are admitting the pod and it is new, record the count of containers
    // TODO: We should probably move this into syncPod and add an execution count
    // to the syncPod arguments, and this should be recorded on the first sync.
    // Leaving it here complicates a particularly important loop.
    metrics.ContainersPerPodCount.Observe(float64(len(update.Options.Pod.Spec.Containers)))

    return ctx, update, true, true, true
}
```

可以看到 `startPodSync` 函数只不过试图对 Pod 的 `started` 状态字段进行修改。

如果返回值参数`ok`为`false`,则表示无效的事件；如果其它参数值为`false`，请确保在返回之前进行适当的清理。 此方法应确保清除 `status.pendingUpdate` 并将其合并到 `status.activeUpdate` 中，或者当pod无法启动时， `status.pndingUpdate` 保持不变。尚未启动的pod永远不应该有`activeUpdate`，因为它暴露在已启动的pod上的下游组件中。



# 同步Pod

上面的p.PodWorker实现了PodWorker的接口，实际上就是一个kubelet实例

SyncPod方法

```
// SyncPod is the transaction script for the sync of a single pod (setting up)
// a pod. This method is reentrant and expected to converge a pod towards the
// desired state of the spec. The reverse (teardown) is handled in
// SyncTerminatingPod and SyncTerminatedPod. If SyncPod exits without error,
// then the pod runtime state is in sync with the desired configuration state
// (pod is running). If SyncPod exits with a transient error, the next
// invocation of SyncPod is expected to make progress towards reaching the
// desired state. SyncPod exits with isTerminal when the pod was detected to
// have reached a terminal lifecycle phase due to container exits (for
// RestartNever or RestartOnFailure) and the next method invoked will be
// SyncTerminatingPod. If the pod terminates for any other reason, SyncPod
// will receive a context cancellation and should exit as soon as possible.
//
// Arguments:
//
// updateType - whether this is a create (first time) or an update, should
// only be used for metrics since this method must be reentrant
//
// pod - the pod that is being set up
//
// mirrorPod - the mirror pod known to the kubelet for this pod, if any
//
// podStatus - the most recent pod status observed for this pod which can
// be used to determine the set of actions that should be taken during
// this loop of SyncPod
//

```

SyncPod是同步单个Pod的事务脚本。该方法是可重入的，并将Pod调整为规范的desired state。反向的操作（拆除）由`SyncTerminatingPod` 和 `SyncTerminatedPod` 处理

如果SyncPod无错误地退出，那么Pod的状态与期望的配置状态同步。如果SyncPod以暂时性错误退出，那么下一次调用SyncPod会继续将Pod的状态向期望的状态调整。如果SyncPod以isTerminal退出，那么Pod的lifecycle将被期望终止。并且下一次调用的方法是SyncTermicatingPod。Pod因其他原因终止，SyncPod会收到context取消而退出。

```go
// The workflow is:
//   - If the pod is being created, record pod worker start latency
//   - Call generateAPIPodStatus to prepare an v1.PodStatus for the pod
//   - If the pod is being seen as running for the first time, record pod
//     start latency
//   - Update the status of the pod in the status manager
//   - Stop the pod's containers if it should not be running due to soft
//     admission
//   - Ensure any background tracking for a runnable pod is started
//   - Create a mirror pod if the pod is a static pod, and does not
//     already have a mirror pod
//   - Create the data directories for the pod if they do not exist
//   - Wait for volumes to attach/mount
//   - Fetch the pull secrets for the pod
//   - Call the container runtime's SyncPod callback
//   - Update the traffic shaping for the pod's ingress and egress limits
//
// If any step of this workflow errors, the error is returned, and is repeated
// on the next SyncPod call.
//
// This operation writes all events that are dispatched in order to provide
// the most accurate information possible about an error situation to aid debugging.
// Callers should not write an event if this operation returns an error.
```

工作流程如下：

1. 如果正在创建Pod，则记录Pod的启动延迟
2. 调用 `generateAPIPodStatus` 函数为Pod准备一个 `v1.PodStatus`
3. 如果Pod 被认为是第一次运行，则记录Pod的启动延迟
4. 更新Pod在 `status manager` 中的状态
5. 如果由于 `soft admission` 准入而不应该运行Pod，则停止其容器
6. 确保可运行Pod的任何后台追踪已启动
7. 如果Pod是 `static Pod` 且尚未具有 `mirror Pod`，则创建 `mirrorPod`
8. 如果Pod的数据目录不存在，则创建数据目录
9. 等待卷的挂载
10. Pod拉取密钥
11. 调用容器运行时的 `SyncPod` 回调函数, 真正创建Pod 的地方
12. 更新Pod的入口和出口限制的流量




具体的代码实现如下

```go
func (kl *Kubelet) SyncPod(ctx context.Context, updateType kubetypes.SyncPodType, pod, mirrorPod *v1.Pod, podStatus *kubecontainer.PodStatus) (isTerminal bool, err error) {
		// 如果pod操作为create，则记录pod工作程序启动延迟
		if updateType == kubetypes.SyncPodCreate {
				metrics.PodWorkerStartDuration.Observe(metrics.SinceInSeconds(firstSeenTime))
	  } 
  
    // 根据pod和 status manager 生成最终 API pod status, 如果已是最终的状态，则直接中止操作
    apiPodStatus := kl.generateAPIPodStatus(pod, podStatus, false)
  
  	// If the network plugin is not ready, only start the pod if it uses the host network
		if err := kl.runtimeState.networkErrors(); err != nil && !kubecontainer.IsHostNetworkPod(pod) {
      kl.recorder.Eventf(pod, v1.EventTypeWarning, events.NetworkNotReady, "%s: %v", NetworkNotReadyErrorMsg, err)
      return false, fmt.Errorf("%s: %v", NetworkNotReadyErrorMsg, err)
    }
  
    // Create Cgroups for the pod and apply resource parameters
    // to them if cgroups-per-qos flag is enabled.
    pcm := kl.containerManager.NewPodContainerManager()
  
    // 如果为 staticPod，则为其创建 mirrorPod
    if kubetypes.IsStaticPod(pod) {...}
  
    // 为Pod创建data 目录（每个pod都有自己三类目录 1. Pod目录 2.Volumes 目录 3.插件目录，其中volumes和 插件目录属于pod目录的子目录）
    if err := kl.makePodDataDirs(pod); err != nil {}
  
  	// 为 Pod attach/mount volumes
    if !kl.podWorkers.IsPodTerminationRequested(pod.UID) {
      // Wait for volumes to attach/mount
      if err := kl.volumeManager.WaitForAttachAndMount(pod); err != nil {
        kl.recorder.Eventf(pod, v1.EventTypeWarning, events.FailedMountVolume, "Unable to attach or mount volumes: %v", err)
        klog.ErrorS(err, "Unable to attach or mount volumes for pod; skipping pod", "pod", klog.KObj(pod))
        return false, err
      }
    }
  
    // Fetch the pull secrets for the pod
    pullSecrets := kl.getPullSecretsForPod(pod)

    // Ensure the pod is being probed
    kl.probeManager.AddPod(pod)
  
    // Currently, using cancellation from that context causes test failures. To remove this WithoutCancel,
    // any wait.Interrupted errors need to be filtered from result and bypass the reasonCache - cancelling
    // the context for SyncPod is a known and deliberate error, not a generic error.
    // Use WithoutCancel instead of a new context.TODO() to propagate trace context
    // Call the container runtime's SyncPod callback
  	//正式创建Pod
    sctx := context.WithoutCancel(ctx)
    result := kl.containerRuntime.SyncPod(sctx, pod, podStatus, pullSecrets, kl.backOff)
    kl.reasonCache.Update(pod.UID, result)
    if err := result.Error(); err != nil {
      // Do not return error if the only failures were pods in backoff
      for _, r := range result.SyncResults {
        if r.Error != kubecontainer.ErrCrashLoopBackOff && r.Error != images.ErrImagePullBackOff {
          // Do not record an event here, as we keep all event logging for sync pod failures
          // local to container runtime, so we get better errors.
          return false, err
        }
      }

      return false, nil
    }
}
```

![c69c7d8f911412ce73e](https://myblog-1307634347.cos.ap-guangzhou.myqcloud.com/blog/c69c7d8f911412ce73e66b2b57dec42e%E7%9A%84%E5%89%AF%E6%9C%AC2.png)

kl.containerRuntime.SyncPod这里会正式创建Pod

```
// SyncPod syncs the running pod into the desired pod by executing following steps:
//
//  1. Compute sandbox and container changes.
//  2. Kill pod sandbox if necessary.
//  3. Kill any containers that should not be running.
//  4. Create sandbox if necessary.
//  5. Create ephemeral containers.
//  6. Create init containers.
//  7. Resize running containers (if InPlacePodVerticalScaling==true)
//  8. Create normal containers.
func (m *kubeGenericRuntimeManager) SyncPod(ctx context.Context, pod *v1.Pod, podStatus *kubecontainer.PodStatus, pullSecrets []v1.Secret, backOff *flowcontrol.Backoff) (result kubecontainer.PodSyncResult) {

	
}
```

