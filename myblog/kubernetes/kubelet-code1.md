---
title: kubelet源码笔记1
date: 2025-03-05
update: 2025-03-09
comment: false
tags:
  - Cilium
  - BPF
categories:
  - BPF
---

kubelet 是 kubernetes 集群中最重要的组件之一，它负责管理节点上的容器，会监听 API Server 上的容器创建、删除、更新等事件，然后根据这些事件来创建、删除、更新容器。kubelet 还负责监控容器的运行状态，当容器运行失败时，kubelet 会将容器的运行状态上报给 API Server。

*<!--more-->*
# Kubelet

kubelet 本身，也是按照“控制器”模式来工作的。它实际的工作原理，可以用如下所示的一幅示意图来表示清楚。

![Kubernetes【容器运行时】kubectl与CRI原理剖析_docker](https://myblog-1307634347.cos.ap-guangzhou.myqcloud.com/blog/resize,m_fixed,w_1184)

# kubeletServer

`kubeltServer` 封装了启动 `kubelet` 所需的所有参数，这些可以通过命令行设置，也可以直接设置。

```Go
type KubeletServer struct {
    KubeletFlags    
    kubeletconfig.KubeletConfiguration
}
```

它内嵌了两个数据结构，分别为 `KubeletFlags` 和 `KubeletConfiguration` 。其中 `kubeletFlags` 主要是用来接收执行命令时手动指定的参数，而 `KubeletConfiguration` 则是从配置文件里读取配置信息，其 API 介绍参考 。

对于一些全局不变的配置一般是通过kubeletFlags实现的， 其他的配置一般通过kubeletConfiguration实现。

# kubeletDeps

kubeletDeps是一个依赖注入器，构建一些kubelet需要的组件，例如，VolumePlugins、clientset、auth filters、testability、cloud provider、TravceProvider等。

kubeletDeps中存在着大量的接口、之后的扩展工作可以从这里开始。

# 服务启动

```Go
kubeletServer := &options.KubeletServer{
    KubeletFlags:         *kubeletFlags,
    KubeletConfiguration: *kubeletConfig,
}

kubeletDeps, err := UnsecuredDependencies(kubeletServer, utilfeature.DefaultFeatureGate)

return Run(ctx, kubeletServer, kubeletDeps, utilfeature.DefaultFeatureGate)
```

## Run()-> run()

```Go
//设置kubele特性开关
err = utilfeature.DefaultMutableFeatureGate.SetFromMap(s.KubeletConfiguration.FeatureGates)

//校验kubeletserver
if err := options.ValidateKubeletServer(s)

// 获取lock file
if err := watchForLockfileContention(s.LockFilePath, done);

// 注册kubelet option到configz终端
err = initConfigz(&s.KubeletConfiguration)

//初始化kublet dependies
kubeDeps, err = UnsecuredDependencies(s, featureGate)

// cloudprovider
cloud, err := cloudprovider.InitCloudProvider(s.CloudProvider, s.CloudConfigFile)

// 非stonealone模式下，创建kubeclient、eventclient、heartbeatclient
kubeDeps.KubeClient, err = clientset.NewForConfig(clientConfig)
kubeDeps.EventClient, err = v1core.NewForConfig(&eventClientConfig)
kubeDeps.HeartbeatClient, err = clientset.NewForConfig(&heartbeatClientConfig)

// Auth
auth, runAuthenticatorCAReload, err := BuildAuth(nodeName, kubeDeps.KubeClient, s.KubeletConfiguration)

// 从CRI获取cgroup driver setting
if err := getCgroupDriverFromCRI(ctx, s, kubeDeps)

kubeletCgroup, err := cm.GetKubeletContainer(s.KubeletCgroups)

//初始化 Cadvisor
kubeDeps.CAdvisorInterface, err = cadvisor.New(imageFsInfoProvider, s.RootDirectory, cgroupRoots, cadvisor.UsingLegacyCadvisorStats(s.ContainerRuntimeEndpoint), s.LocalStorageCapacityIsolation)

//初始化 containerManager
kubeDeps.ContainerManager, err = cm.NewContainerManager

//初始化oomAdjuster
oomAdjuster := kubeDeps.OOMAdjuster

// 启动kubelet
if err := RunKubelet(ctx, s, kubeDeps, s.RunOnce)
```

## **RunKubelet**

```Go
// 准备工作
hostname, err := nodeutil.GetHostname(kubeServer.HostnameOverride)
nodeName, err := getNodeName(kubeDeps.Cloud, hostname)
makeEventRecorder(ctx, kubeDeps, nodeName)

nodeIPs, invalidNodeIps, err := nodeutil.ParseNodeIPArgument(kubeServer.NodeIP, kubeServer.CloudProvider)

// 初始化kubelet实例
k, err := createAndInitKubelet(kubeServer,
    kubeDeps,
    hostname,
    hostnameOverridden,
    nodeName,
    nodeIPs)

// 启动kubelet实例
// process pods and exit.
if runOnce {
    if _, err := k.RunOnce(podCfg.Updates()); err != nil {
       return fmt.Errorf("runonce failed: %w", err)
    }
    klog.InfoS("Started kubelet as runonce")
} else {
    startKubelet(k, podCfg, &kubeServer.KubeletConfiguration, kubeDeps, kubeServer.EnableServer)
    klog.InfoS("Started kubelet")
}
```

## createAndInitKubelet()

```Go

```

返回Bootstrap的接口

## startkublet()

```Go
// start the kubelet
go k.Run(podCfg.Updates())

// start the kubelet server
if enableServer {
   go k.ListenAndServe(kubeCfg, kubeDeps.TLSOptions, kubeDeps.Auth, kubeDeps.TracerProvider)
}
if kubeCfg.ReadOnlyPort > 0 {
   go k.ListenAndServeReadOnly(netutils.ParseIPSloppy(kubeCfg.Address), uint(kubeCfg.ReadOnlyPort), kubeDeps.TracerProvider)
}
go k.ListenAndServePodResources()
```

podCfg用于将许多Pod配置到一个统一的结构中，按照顺序向侦听器发送增量更改通知。`podCfg.Updates()` 则表示**接收**Pod更新通知类型的 `channel`。也就是说这个channel只能读取

```Go
// PodConfig is a configuration mux that merges many sources of pod configuration into a single
// consistent structure, and then delivers incremental change notifications to listeners
// in order.
type PodConfig struct {
    pods *podStorage
    mux  *mux

    // the channel of denormalized changes passed to listeners
    updates chan kubetypes.PodUpdate

    // contains the list of all configured sources
    sourcesLock sync.Mutex
    sources     sets.Set[string]
}
```

## Kubelet.Run()

```Go
//启动日志服务
if kl.logServer == nil

// Start the cloud provider sync manager
go kl.cloudResourceSyncManager.Run(wait.NeverStop)

// init modules
if err := kl.initializeModules(); 

// 
kl.warnCgroupV1Usage()

// 启动Volume manager
go kl.volumeManager.Run(kl.sourcesReady, wait.NeverStop)

//
if kl.kubeClient != nil {
    // Start two go-routines to update the status.
    //
    // The first will report to the apiserver every nodeStatusUpdateFrequency and is aimed to provide regular status intervals,
    // while the second is used to provide a more timely status update during initialization and runs an one-shot update to the apiserver
    // once the node becomes ready, then exits afterwards.
    //
    // Introduce some small jittering to ensure that over time the requests won't start
    // accumulating at approximately the same time from the set of nodes due to priority and
    // fairness effect.
    go func() {
       // Call updateRuntimeUp once before syncNodeStatus to make sure kubelet had already checked runtime state
       // otherwise when restart kubelet, syncNodeStatus will report node notReady in first report period
       kl.updateRuntimeUp()
       wait.JitterUntil(kl.syncNodeStatus, kl.nodeStatusUpdateFrequency, 0.04, true, wait.NeverStop)
    }()

    go kl.fastStatusUpdateOnce()

    // start syncing lease
    go kl.nodeLeaseController.Run(context.Background())
}

//5. 调用容器运行时状态回调，每5s执行一次，状态字段 kl.runtimeState
go wait.Until(kl.updateRuntimeUp, 5*time.Second, wait.NeverStop)

// Set up iptables util rules
if kl.makeIPTablesUtilChains {
    kl.initNetworkUtil()
}

// 7. Start component sync loops.
kl.statusManager.Start()

// Start syncing RuntimeClasses if enabled.
if kl.runtimeClassManager != nil {
        kl.runtimeClassManager.Start(wait.NeverStop)
}

// 8. Start the pod lifecycle event generator.
kl.pleg.Start()

// Start eventedPLEG only if EventedPLEG feature gate is enabled.
if utilfeature.DefaultFeatureGate.Enabled(features.EventedPLEG) {
    kl.eventedPleg.Start()
}

kl.syncLoop(ctx, updates, kl)
```

最关键的调用是kl.syncLoop()，用来实现对Pod变更的监听。这里update是Pod变更的channel，kl指的是kubelet的实例，同时也是处理Pod变更的handler。

## syncLoop

```Go
// 1. syncTicker唤醒kubelet，检查是否有pod workers需要同步。检查周期为一秒一次，默认情况下是10秒一次
syncTicker := time.NewTicker(time.Second)

//2. pleg专用channel
plegCh := kl.pleg.Watch()

//检查resolv.conf
if kl.dnsConfigurer != nil && kl.dnsConfigurer.ResolverConfig != "" {
    kl.dnsConfigurer.CheckLimitsForResolvConf()
}

// 核心逻辑，轮询事件
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
    //核心，处理各种Pod事件
    if !kl.syncLoopIteration(ctx, updates, handler, syncTicker.C, housekeepingTicker.C, plegCh) {
       break
    }
    kl.syncLoopMonitor.Store(kl.clock.Now())
}
```

## syncLoopIteration

### 参数

1. `configCh`: 从中读取配置事件的通道，这里指参数 `updates`
2. `handler`: 将 pod 分发到的 `SyncHandler`
3. `syncCh`: 读取周期性同步事件的通道
4. `housekeepingCh`: 读取 `housekeeping` 事件的通道
5. `plegCh`: 读取 PLEG 更新的通道

### 处理逻辑

就是在一个 `Loop` 中不断的从其中一个`channel` 中读取事件，然后再视情况处理事件，最后再更新时间戳。

//   - configCh: dispatch the pods for the config change to the appropriate

//     handler callback for the event type

//   - plegCh: update the runtime cache; sync pod

//   - syncCh: sync all pods waiting for sync

//   - housekeepingCh: trigger cleanup of pods

//   - health manager: sync pods that have failed or in which one or more

//     containers have failed health checks

首先是针对configCh的处理，这里主要是指针对一个pod 操作类型做相应的处理，如创建新Pod，修改Pod、Remove 、 DELETE 或 RECONCILE操作。

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

plegCh读取PodLifecycleEvent的事件，如果事件为 `!pleg.ContainerRemoved` ，则调用GetPodByUID来检查Pod是否存在，如果存在，则接着调用HandlePodSyncs同步

如果事件为 `pleg.ContainerRemoved` ，则调用cleanUpContainersInPod将其容器删除。

```Go
case e := <-plegCh:
    if isSyncPodWorthy(e) {
       // PLEG event for a pod; sync it.
       if pod, ok := kl.podManager.GetPodByUID(e.ID); ok {
          klog.V(2).InfoS("SyncLoop (PLEG): event for pod", "pod", klog.KObj(pod), "event", e)
          handler.HandlePodSyncs([]*v1.Pod{pod})
       } else {
          // If the pod no longer exists, ignore the event.
          klog.V(4).InfoS("SyncLoop (PLEG): pod does not exist, ignore irrelevant event", "event", e)
       }
    }

    if e.Type == pleg.ContainerDied {
       if containerID, ok := e.Data.(string); ok {
          kl.cleanUpContainersInPod(e.ID, containerID)
       }
    }
```

syncCh调用HandlePodSyncs同步Pod

```Go
case <-syncCh:
    // Sync pods waiting for sync
    podsToSync := kl.getPodsToSync()
    if len(podsToSync) == 0 {
       break
    }
    klog.V(4).InfoS("SyncLoop (SYNC) pods", "total", len(podsToSync), "pods", klog.KObjSlice(podsToSync))
    handler.HandlePodSyncs(podsToSync)
```

housekeepingCh调用HandlePodCleanups清理Pod。HandlePodCleanups会执行一系列的清理工作，包括终止Pod工作程序、杀死不需要的pod、以及删除孤立卷Pod目录。在执行此方法时，不会向pod worker发送任何配置更改，这意味着不会出现新的pod。在这个方法完成后，kubelet的期望状态应该与pod worker和其他pod相关组件中的实际状态相协调。???

对于probe的处理主要是通过SetContainerReadiness来设置容器 的状态，以及通过handleProbeSync来同步probe的状态。handleProbeSync最终调用HandlePodSyncs函数完成处理逻辑

```Go
case update := <-kl.livenessManager.Updates():
    if update.Result == proberesults.Failure {
       handleProbeSync(kl, update, handler, "liveness", "unhealthy")
    }
case update := <-kl.readinessManager.Updates():
    ready := update.Result == proberesults.Success
    kl.statusManager.SetContainerReadiness(update.PodUID, update.ContainerID, ready)

    status := ""
    if ready {
       status = "ready"
    }
    handleProbeSync(kl, update, handler, "readiness", status)
```

## HandlePodSyncs

updatePod就是

```Go
for _, pod := range pods {
    // 根据 RegularPod 获取对应的 mirrorPod
    pod, mirrorPod, wasMirror := kl.podManager.GetPodAndMirrorPod(pod)
    kl.podWorkers.UpdatePod(UpdatePodOptions{
        Pod:        pod,
        MirrorPod:  mirrorPod,
        UpdateType: kubetypes.SyncPodSync,
        StartTime:  start,
    })
}
```

#  `RegularPod` 与 `mirrorPod` 的区别

> 在Kubernetes中， `mirrorPod` 和 `RegularPod` 是两种不同类型的Pod。以下是它们之间的主要区别：
>
> 1. **用途**： `RegularPod` 是正常的工作Pod，用于运行应用程序或服务。而 `mirrorPod` 是 `RegularPod` 的一种特殊类型，用于支持调试和监视目的。
> 2. **生命周期**： `RegularPod` 是由用户定义和创建的，可以具有任意的生命周期，包括创建、修改、删除等。而 `mirrorPod` 是由Kubernetes控制平面自动创建和管理的，它是根据关联的 `RegularPod` 创建的，会在 `RegularPod` 删除后自动删除。
> 3. **资源配置**： `MirrorPod` 是一个只读镜像，与关联的 `RegularPod` 共享相同的容器镜像和配置。它不会被调度到任何节点上执行，而是在控制平面上以被动模式运行。这意味着 `MirrorPod` 不占用实际的计算资源，并不处理任何网络请求。
> 4. **监控调试**： `MirrorPod` 被用于支持对关联的 `RegularPod` 进行监控和调试。通过 `kubectl attach` 命令，可以将 `kubectl attach` 到关联的 `RegularPod` 上，并在 `MirrorPod` 中查看它的日志、执行命令等。这为开发人员和运维人员提供了一种方便的方式来检查和诊断正在运行的应用程序。
>
> 总而言之， `mirrorPod` 是一种特殊类型的Pod，主要用于支持调试和监控 `RegularPod` 的目的。它是由Kubernetes自动创建和删除的，共享相同的容器配置，但不执行任何实际的计算工作。