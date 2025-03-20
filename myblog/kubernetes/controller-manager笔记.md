---
title: controller-manager笔记
date: 2025-01-15
update: 2025-03-02
comment: false
tags:
  - kubernetes
categories:
  - kubernetes
---
controller-manager是k8s内置的一个控制器，负责管理集群中所有资源对象的生命周期。它通过监听API Server中的资源对象变化，然后根据资源对象的类型和状态，执行相应的操作。

*<!--more-->*
Controller Manager

Controller-manager是一个deamonset， 主要负责k8s集群各种资源的控制，node、Pod、Sts等。在自动化的概念中，控制环路是调节系统状态的非终止环路。在 Kubernetes 中，Controller是一个控制循环，它通过 apiserver 监视集群的共享状态，并进行更改，尝试将当前状态移动到所需状态。目前随 Kubernetes 一起提供的控制器示例包括

replication controller, endpoints controller, namespace controller, and serviceaccounts controller.

# 源码笔记

**Kubernetes Version: 1.31**

# 整体实现

# NewControllerManagerCommand()

options.NewKubeControllerManagerOptions(): 对所有内置控制器以及全局配置进行初始化

KnownControllers(): 获取内置Controller，这些内置的控制器定义在`cmd/kube-controller-manager/app/`目录下

s.Config(KnownControllers()......) : 生成控制器管理配置项，获取与集群通讯所必须的基本信息(kubeconfig、clientset、event)。

# Run(): 是Controller-manager的核心

EventBroadcaster？？？

CreateControllerContext： 创建控制器 的上下文配置，用来在每个控制器执行时提供公共配置。StartControllers(): 启动所有的Controller

StartControllers(): 

遍历控制器

controllerDescriptor.GetInitFunc()执行控制器，传递 controllerCtx 上下文配置

# 具体的Controller

以statefulset-controller为例

![1727000381733-1](https://myblog-1307634347.cos.ap-guangzhou.myqcloud.com/blog/1727000381733-1.png)

go statefulset.NewStatefulSetController().Run():

For int worker

->go wait.UntilWithContext(ctx, ssc.worker, time.*Second*)

ssc.work-> for ssc.processNextWorkItem(ctx) -> ssc.sync 

## sync()

set, err := ssc.setLister.StatefulSets(namespace).Get(name)

pods, err := ssc.getPodsForStatefulSet(ctx, set, selector)

ssc.syncStatefulSet()

processNextWorkItem() -> 



# Statefulset原理

首先看sync函数，处理流程为：

1. 解析ns和name
2. 根据ns和name获取STS
3. 获取selector，用于筛选Pod
4. 筛选STS的孤儿 controllerrevisions，并尝试与 sts 重新关联（添加 ControllerRef）
5. 获取 sts 所有关联的 pod
6. 执行syncStatefulSet



```
func (ssc *StatefulSetController) sync(ctx context.Context, key string) error {
		namespace, name, err := cache.SplitMetaNamespaceKey(key)
		set, err := ssc.setLister.StatefulSets(namespace).Get(name)
		
		selector, err := metav1.LabelSelectorAsSelector(set.Spec.Selector)
		
		err := ssc.adoptOrphanRevisions(set)
		
		pods, err := ssc.getPodsForStatefulSet(ctx, set, selector)
		return ssc.syncStatefulSet(ctx, set, pods)
}
```

```
func (ssc *StatefulSetController) syncStatefulSet(ctx context.Context, set *apps.StatefulSet, pods []*v1.Pod) error {
		status, err = ssc.control.UpdateStatefulSet(ctx, set, pods)
		if set.Spec.MinReadySeconds > 0 && status != nil && status.AvailableReplicas != *set.Spec.Replicas {
				ssc.enqueueSSAfter(set, time.Duration(set.Spec.MinReadySeconds)*time.Second)
		}
}
```

UpdateStatefulset是核心的调谐流程。默认采用单调更新策略--扩容时按顺序进行，遇到任意Pod处于不健康状态时，不会新建POD，而是按照序号降序终止POD。

```
func (ssc *defaultStatefulSetControl) UpdateStatefulSet(ctx context.Context, set *apps.StatefulSet, pods []*v1.Pod) (*apps.StatefulSetStatus, error) {
		// list all revisions and sort them
		revisions, err := ssc.ListRevisions(set)
		history.SortControllerRevisions(revisions)
		
		currentRevision, updateRevision, status, err := ssc.performUpdate(ctx, set, pods, revisions)
		return status, ssc.truncateHistory(set, pods, revisions, currentRevision, updateRevision)
}

func (ssc *defaultStatefulSetControl) performUpdate() {
		currentStatus, err = ssc.updateStatefulSet(ctx, set, currentRevision, updateRevision, collisionCount, pods)
		statusErr := ssc.updateStatefulSetStatus(ctx, set, currentStatus)
}
```

updateStatefulSet执行具体的更新逻辑，会创建、更新、删除所属的PODs，使Set调谐至目标状态。

STS通过Controllerrevision来保存历史版本。与 replicaset 不同的是 controllerrevision 仅用于回滚阶段， 在 sts 的滚动升级过程中是通过 currentRevision 和 updateRevision 进行控制并不会用到 controllerrevision。

处理逻辑：

1. 取到currentRevision 和 updateRevision 版本所对应的statefulset 

2. 更新status 的 generation 和 revisions

3. 将 statefulset 的 pods分为replicas和 condemned，其中replicas为[0, replicas]范围的Pod，condemned为大于replicas的pod

4. 检查Pod的状态，即[0,replicas]的pod中是否有状态不正常或者确实的Pod，缺失则创建对应编号的Pod

5. 找出replicas和condemned中第一个非健康的Pod

6. 如果replicas正处于删除中则直接返回

7. 遍历replicas中的Pod，如果状态不健康就删除重建

8. 正序处理Replicas

9. 逆序处理condemned

10. 执行滚动更新

11. 终止了序号最大且与更新版本不匹配序号及之后的 Pod

    

```
func (ssc *defaultStatefulSetControl) updateStatefulSet() {
		currentSet, err := ApplyRevision(set, currentRevision)
		updateSet, err := ApplyRevision(set, updateRevision)
		
		updateStatus(&status, set.Spec.MinReadySeconds, currentRevision, updateRevision, pods)
		replicaCount := int(*set.Spec.Replicas)
		replicas := make([]*v1.Pod, replicaCount)
		
		for _, pod := range pods {
		if podInOrdinalRange(pod, set) {
			// if the ordinal of the pod is within the range of the current number of replicas,
			// insert it at the indirection of its ordinal
			replicas[getOrdinal(pod)-getStartOrdinal(set)] = pod
		} else if getOrdinal(pod) >= 0 {
			// if the ordinal is valid, but not within the range add it to the condemned list
			condemned = append(condemned, pod)
		}
		// If the ordinal could not be parsed (ord < 0), ignore the Pod.
	}
		// for any empty indices in the sequence [0,set.Spec.Replicas) create a new Pod at the correct revision
    for ord := getStartOrdinal(set); ord <= getEndOrdinal(set); ord++ {
      replicaIdx := ord - getStartOrdinal(set)
      if replicas[replicaIdx] == nil {
        replicas[replicaIdx] = newVersionedStatefulSetPod(
          currentSet,
          updateSet,
          currentRevision.Name,
          updateRevision.Name, ord)
      }
    }
}
```

### processReplica

处理流程：

1. 若 Pod 处于失败 (`Failed`) 或成功 (`Succeeded`) 状态，且未被标记删除，则删除该 Pod
2. 若 Pod 未被创建 (!`isCreated`)，则进行创建操作。
3. 若 Pod 处于 Pending 状态，触发缺失 PVC 的创建。
4. 如果 Pod 正在终止 (`isTerminating`) 且处于顺序模式 (`monotonic`), 需等待终止完成再继续。
5. 在顺序模式下，严格检查前置 Pod 是否已就绪 (`isRunningAndReady`) 和可用 (`isRunningAndAvailable`)，确保 StatefulSet 的顺序性。
6. 对比 Pod 的 Identity（标签）、存储（Volume）和 PVC 保留策略，若不一致则触发更新。



### processCondemned

1. **终止中的 Pod 处理**
2. 等待第一个非健康Pod处理完成
3. 执行删除操作



### slowStartBatch：**慢启动并发控制**

1. **动态批次调整**：**初始批次大小** (`initialBatchSize`) → **指数增长**（每次翻倍）→ **上限限制** (`MaxBatchSize`)。
2. **并发任务处理**
   1. 每个批次内创建多个 goroutine 并行处理任务。
   2. 使用 `sync.WaitGroup` 和错误通道 (`errCh`) 收集结果。
3. **错误聚合与反馈**



## 滚动更新

updateStatefulSetAfterInvariantEstablished函数时是执行滚动更新的核心

处理流程：

1. 确定partition，也就是滚动更新的分界序号：序号 >= Partition 的 Pod 可以更新，序号 < 的保持旧版。
2. 计算MaxUnavailable，
3. 扫描pod的健康状态，如果不健康Pod已经达到MaxUnavailable，就停止当前操作
4. 逆向滚动删除

# Deployment原理

deployment controller注册了deployment、replicaset与pod对象的EventHandler，也即对这几个对象的event进行监听，把event放入事件队列并做处理

`dc.syncDeployment`方法赋值给`dc.syncHandler`，也即注册为核心处理方法，在`dc.Run`方法中会调用该核心处理方法来调谐deployment对象

```
dInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
    AddFunc: func(obj interface{}) {
       dc.addDeployment(logger, obj)
    },
    UpdateFunc: func(oldObj, newObj interface{}) {
       dc.updateDeployment(logger, oldObj, newObj)
    },
    // This will enter the sync loop and no-op, because the deployment has been deleted from the store.
    DeleteFunc: func(obj interface{}) {
       dc.deleteDeployment(logger, obj)
    },
})
rsInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
    AddFunc: func(obj interface{}) {
       dc.addReplicaSet(logger, obj)
    },
    UpdateFunc: func(oldObj, newObj interface{}) {
       dc.updateReplicaSet(logger, oldObj, newObj)
    },
    DeleteFunc: func(obj interface{}) {
       dc.deleteReplicaSet(logger, obj)
    },
})
podInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
    DeleteFunc: func(obj interface{}) {
       dc.deletePod(logger, obj)
    },
})


dc.syncHandler = dc.syncDeployment
dc.enqueueDeployment = dc.enqueue
```

## syncDeployment

处理逻辑：

1. 根据 deployment 对象的命名空间与名称，获取 deployment 对象；
2. 获取所有Replicas，处理replicaset的匹配关系，发现没有关联就添加ownerReferences
3. 获取所有Pod，根据 replicaset 对象的`UID`返回一个`map[types.UID]*v1.Pod`
4. 如果正处于删除状态，则syncStatusOnly
5. 检查 deployment 是否为`pause`状态，为`true`时，则调用`dc.sync`做处理，调用完成后直接return；
6. 判断是否处于回滚状态，是则调用 `dc.rollback` 方法执行 回滚操作
7. 调用`dc.isScalingEvent`：检查deployment对象是否处于 `scaling` 状态，是则调用`dc.sync`做扩缩容处理
8. 根据策略做更新处理

```
func (dc *DeploymentController) syncDeployment(ctx context.Context, key string) error {
    logger := klog.FromContext(ctx)
    namespace, name, err := cache.SplitMetaNamespaceKey(key)
    if err != nil {
       logger.Error(err, "Failed to split meta namespace cache key", "cacheKey", key)
       return err
    }

    startTime := time.Now()
    logger.V(4).Info("Started syncing deployment", "deployment", klog.KRef(namespace, name), "startTime", startTime)
    defer func() {
       logger.V(4).Info("Finished syncing deployment", "deployment", klog.KRef(namespace, name), "duration", time.Since(startTime))
    }()

    deployment, err := dc.dLister.Deployments(namespace).Get(name)
    if errors.IsNotFound(err) {
       logger.V(2).Info("Deployment has been deleted", "deployment", klog.KRef(namespace, name))
       return nil
    }
    if err != nil {
       return err
    }

    // Deep-copy otherwise we are mutating our cache.
    // TODO: Deep-copy only when needed.
    d := deployment.DeepCopy()

    everything := metav1.LabelSelector{}
    if reflect.DeepEqual(d.Spec.Selector, &everything) {
       dc.eventRecorder.Eventf(d, v1.EventTypeWarning, "SelectingAll", "This deployment is selecting all pods. A non-empty selector is required.")
       if d.Status.ObservedGeneration < d.Generation {
          d.Status.ObservedGeneration = d.Generation
          dc.client.AppsV1().Deployments(d.Namespace).UpdateStatus(ctx, d, metav1.UpdateOptions{})
       }
       return nil
    }

    // List ReplicaSets owned by this Deployment, while reconciling ControllerRef
    // through adoption/orphaning.
    rsList, err := dc.getReplicaSetsForDeployment(ctx, d)
    if err != nil {
       return err
    }
    // List all Pods owned by this Deployment, grouped by their ReplicaSet.
    // Current uses of the podMap are:
    //
    // * check if a Pod is labeled correctly with the pod-template-hash label.
    // * check that no old Pods are running in the middle of Recreate Deployments.
    podMap, err := dc.getPodMapForDeployment(d, rsList)
    if err != nil {
       return err
    }

    if d.DeletionTimestamp != nil {
       return dc.syncStatusOnly(ctx, d, rsList)
    }

    // Update deployment conditions with an Unknown condition when pausing/resuming
    // a deployment. In this way, we can be sure that we won't timeout when a user
    // resumes a Deployment with a set progressDeadlineSeconds.
    if err = dc.checkPausedConditions(ctx, d); err != nil {
       return err
    }

    if d.Spec.Paused {
       return dc.sync(ctx, d, rsList)
    }

    // rollback is not re-entrant in case the underlying replica sets are updated with a new
    // revision so we should ensure that we won't proceed to update replica sets until we
    // make sure that the deployment has cleaned up its rollback spec in subsequent enqueues.
    if getRollbackTo(d) != nil {
       return dc.rollback(ctx, d, rsList)
    }

    scalingEvent, err := dc.isScalingEvent(ctx, d, rsList)
    if err != nil {
       return err
    }
    if scalingEvent {
       return dc.sync(ctx, d, rsList)
    }

    switch d.Spec.Strategy.Type {
    case apps.RecreateDeploymentStrategyType:
       return dc.rolloutRecreate(ctx, d, rsList, podMap)
    case apps.RollingUpdateDeploymentStrategyType:
       return dc.rolloutRolling(ctx, d, rsList)
    }
    return fmt.Errorf("unexpected deployment strategy type: %s", d.Spec.Strategy.Type)
}
```

### rollback

dc.rollback主要逻辑：
（1）获取deployment的所有关联匹配的replicaset对象列表；
（2）获取需要回滚的Revision；
（3）遍历上述获得的replicaset对象列表，比较Revision是否与需要回滚的Revision一致，一致则调用`dc.rollbackToTemplate`做回滚操作（主要是根据特定的Revision的replicaset对象，更改deployment对象的`.Spec.Template`）；
（4）最后，不管有没有回滚成功，都将deployment对象的`.spec.rollbackTo`属性置为nil，然后更新deployment对象。

```go
func (dc *DeploymentController) rollback(ctx context.Context, d *apps.Deployment, rsList []*apps.ReplicaSet) error {
    logger := klog.FromContext(ctx)
    newRS, allOldRSs, err := dc.getAllReplicaSetsAndSyncRevision(ctx, d, rsList, true)
    if err != nil {
       return err
    }

    allRSs := append(allOldRSs, newRS)
    rollbackTo := getRollbackTo(d)
    // If rollback revision is 0, rollback to the last revision
    if rollbackTo.Revision == 0 {
       if rollbackTo.Revision = deploymentutil.LastRevision(logger, allRSs); rollbackTo.Revision == 0 {
          // If we still can't find the last revision, gives up rollback
          dc.emitRollbackWarningEvent(d, deploymentutil.RollbackRevisionNotFound, "Unable to find last revision.")
          // Gives up rollback
          return dc.updateDeploymentAndClearRollbackTo(ctx, d)
       }
    }
    for _, rs := range allRSs {
       v, err := deploymentutil.Revision(rs)
       if err != nil {
          logger.V(4).Info("Unable to extract revision from deployment's replica set", "replicaSet", klog.KObj(rs), "err", err)
          continue
       }
       if v == rollbackTo.Revision {
          logger.V(4).Info("Found replica set with desired revision", "replicaSet", klog.KObj(rs), "revision", v)
          // rollback by copying podTemplate.Spec from the replica set
          // revision number will be incremented during the next getAllReplicaSetsAndSyncRevision call
          // no-op if the spec matches current deployment's podTemplate.Spec
          performedRollback, err := dc.rollbackToTemplate(ctx, d, rs)
          if performedRollback && err == nil {
             dc.emitRollbackNormalEvent(d, fmt.Sprintf("Rolled back deployment %q to revision %d", d.Name, rollbackTo.Revision))
          }
          return err
       }
    }
    dc.emitRollbackWarningEvent(d, deploymentutil.RollbackRevisionNotFound, "Unable to find the revision to rollback to.")
    // Gives up rollback
    return dc.updateDeploymentAndClearRollbackTo(ctx, d)
}
```

### dc.sync

dc.sync主要逻辑：
（1）调用`dc.getAllReplicaSetsAndSyncRevision`获取最新的replicaset对象以及旧的replicaset对象列表；
（2）调用`dc.scale`，判断是否需要进行扩缩容操作，需要则进行扩缩容操作；
（3）当deployment的`.Spec.Paused`为true且不需要做回滚操作时，调用`dc.cleanupDeployment`，根据deployment配置的保留历史版本数（`.Spec.RevisionHistoryLimit`）以及replicaset的创建时间，把最老的旧的replicaset给删除清理掉；
（4）调用`dc.syncDeploymentStatus`，计算并更新deployment对象的status字段。

```
func (dc *DeploymentController) sync(ctx context.Context, d *apps.Deployment, rsList []*apps.ReplicaSet) error {
    newRS, oldRSs, err := dc.getAllReplicaSetsAndSyncRevision(ctx, d, rsList, false)
    if err != nil {
       return err
    }
    if err := dc.scale(ctx, d, newRS, oldRSs); err != nil {
       // If we get an error while trying to scale, the deployment will be requeued
       // so we can abort this resync
       return err
    }

    // Clean up the deployment when it's paused and no rollback is in flight.
    if d.Spec.Paused && getRollbackTo(d) == nil {
       if err := dc.cleanupDeployment(ctx, oldRSs, d); err != nil {
          return err
       }
    }

    allRSs := append(oldRSs, newRS)
    return dc.syncDeploymentStatus(ctx, allRSs, newRS, d)
}
```

### dc.scale

dc.scale主要作用是处理deployment的扩缩容操作，其主要逻辑如下：
（1）调用`deploymentutil.FindActiveOrLatest`，判断是否只有最新的replicaset对象的副本数不为0，是则找到最新的replicaset对象，并判断其副本数是否与deployment期望副本数一致，是则直接return，否则调用`dc.scaleReplicaSetAndRecordEvent`更新其副本数为deployment的期望副本数；
（2）当最新的replicaset对象的副本数与deployment期望副本数一致，且旧的replicaset对象中有副本数不为0的，则从旧的replicset对象列表中找出副本数不为0的replicaset，调用`dc.scaleReplicaSetAndRecordEvent`将其副本数缩容为0，然后return；
（3）当最新的replicaset对象的副本数与deployment期望副本数不一致，旧的replicaset对象中有副本数不为0的，且deployment的更新策略为滚动更新，说明deployment可能正在滚动更新，则按一定的比例对新旧replicaset进行扩缩容操作，保证滚动更新的稳定性

### rolloutRolling

dc.rolloutRolling主要逻辑：
（1）调用`dc.getAllReplicaSetsAndSyncRevision`，获取最新的replicaset对象以及旧的replicaset对象列表，当新的replicaset对象不存在时，将创建一个新的replicaset对象（副本数为0）；
（2）调用`dc.reconcileNewReplicaSet`，调谐新的replicaset对象，根据deployment的滚动更新策略配置`.Spec.Strategy.RollingUpdate.MaxSurge`和现存pod数量进行计算，决定是否对新的replicaset对象进行扩容以及扩容的副本数；
（3）当新的replicaset对象副本数在调谐时被更新，则调用`dc.syncRolloutStatus`更新deployment状态后直接return；
（4）调用`dc.reconcileOldReplicaSets`，根据deployment的滚动更新策略配置`.Spec.Strategy.RollingUpdate.MaxUnavailable`、现存的Available状态的pod数量、新replicaset对象下所属的available的pod数量，决定是否对旧的replicaset对象进行缩容以及缩容的副本数；
（5）当旧的replicaset对象副本数在调谐时被更新，则调用`dc.syncRolloutStatus`更新deployment状态后直接return；
（6）调用`util.DeploymentComplete`，检查deployment的所有pod是否都是updated的和available的，而且没有旧的pod在running，是则继续调用`dc.cleanupDeployment`，根据deployment配置的保留历史版本数（`.Spec.RevisionHistoryLimit`）以及replicaset的创建时间，把最老的旧的replicaset给删除清理掉。
（7）调用`dc.syncRolloutStatus`更新deployment状态。

```
func (dc *DeploymentController) rolloutRolling(ctx context.Context, d *apps.Deployment, rsList []*apps.ReplicaSet) error {
    newRS, oldRSs, err := dc.getAllReplicaSetsAndSyncRevision(ctx, d, rsList, true)
    if err != nil {
       return err
    }
    allRSs := append(oldRSs, newRS)

    // Scale up, if we can.
    scaledUp, err := dc.reconcileNewReplicaSet(ctx, allRSs, newRS, d)
    if err != nil {
       return err
    }
    if scaledUp {
       // Update DeploymentStatus
       return dc.syncRolloutStatus(ctx, allRSs, newRS, d)
    }

    // Scale down, if we can.
    scaledDown, err := dc.reconcileOldReplicaSets(ctx, allRSs, controller.FilterActiveReplicaSets(oldRSs), newRS, d)
    if err != nil {
       return err
    }
    if scaledDown {
       // Update DeploymentStatus
       return dc.syncRolloutStatus(ctx, allRSs, newRS, d)
    }

    if deploymentutil.DeploymentComplete(d, &d.Status) {
       if err := dc.cleanupDeployment(ctx, oldRSs, d); err != nil {
          return err
       }
    }

    // Sync deployment status
    return dc.syncRolloutStatus(ctx, allRSs, newRS, d)
}
```

### reconcileNewReplicaSet

c.reconcileNewReplicaSet主要作用是调谐新的replicaset对象，根据deployment的滚动更新策略配置和现存pod数量进行计算，决定是否对新的replicaset对象进行扩容。

主要逻辑：
（1）当新的replicaset对象的副本数与deployment声明的副本数一致，则说明该replicaset对象无需再调谐，直接return；
（2）当新的replicaset对象的副本数比deployment声明的副本数要大，则调用`dc.scaleReplicaSetAndRecordEvent`，将replicaset对象的副本数缩容至与deployment声明的副本数一致，然后return；
（3）当新的replicaset对象的副本数比deployment声明的副本数要小，则调用`deploymentutil.NewRSNewReplicas`，根据deployment的滚动更新策略配置`.Spec.Strategy.RollingUpdate.MaxSurge`的值计算出新replicaset对象该拥有的副本数量，并调用`dc.scaleReplicaSetAndRecordEvent`更新replicaset的副本数。

```
func (dc *DeploymentController) reconcileNewReplicaSet(ctx context.Context, allRSs []*apps.ReplicaSet, newRS *apps.ReplicaSet, deployment *apps.Deployment) (bool, error) {
    if *(newRS.Spec.Replicas) == *(deployment.Spec.Replicas) {
       // Scaling not required.
       return false, nil
    }
    if *(newRS.Spec.Replicas) > *(deployment.Spec.Replicas) {
       // Scale down.
       scaled, _, err := dc.scaleReplicaSetAndRecordEvent(ctx, newRS, *(deployment.Spec.Replicas), deployment)
       return scaled, err
    }
    newReplicasCount, err := deploymentutil.NewRSNewReplicas(deployment, allRSs, newRS)
    if err != nil {
       return false, err
    }
    scaled, _, err := dc.scaleReplicaSetAndRecordEvent(ctx, newRS, newReplicasCount, deployment)
    return scaled, err
}
```

### reconcileOldReplicaSets

dc.reconcileNewReplicaSet主要作用是调谐旧的replicaset对象，根据deployment的滚动更新策略配置`.Spec.Strategy.RollingUpdate.MaxUnavailable`和现存的Available状态的pod数量进行计算，决定是否对旧的replicaset对象进行缩容。

主要逻辑：
（1）获取旧的replicaset对象的副本数总数，如果是0，则代表旧的replicaset对象已经无法缩容，调谐完毕，直接return；
（2）调用`deploymentutil.MaxUnavailable`，计算获取`maxUnavailable`的值，即最大不可用pod数量（这里注意一点，当deployment滚动更新策略中`MaxUnavailable`与`MaxSurge`的配置值都为0时，此处计算`MaxUnavailable`的值时会返回1，因为这两者均为0时，无法进行滚动更新）；
（3）根据`MaxUnavailable`的值、deployment的期望副本数、新replicaset对象的期望副本数、新replicaset对象的处于`Available`状态的副本数，计算出`maxScaledDown`即最大可缩容副本数，当`maxScaledDown`小于等于0，则代表目前暂不能对旧的replicaset对象进行缩容，直接return；
（4）调用`dc.cleanupUnhealthyReplicas`，按照replicaset的创建时间排序，先清理缩容`Unhealthy`的副本（如`not-ready`的、`unscheduled`的、`pending`的pod），具体逻辑暂不展开分析；
（5）调用`dc.scaleDownOldReplicaSetsForRollingUpdate`，根据deployment的滚动更新策略配置`.Spec.Strategy.RollingUpdate.MaxUnavailable`计算出旧的replicaset对象该拥有的副本数量，调用`dc.scaleReplicaSetAndRecordEvent`缩容旧的replicaset对象（所以这里也可以看到，`dc.cleanupUnhealthyReplicas`与`dc.scaleDownOldReplicaSetsForRollingUpdate`均有可能会对旧的replicaset进行缩容操作）；
（6）如果缩容的副本数大于0，则返回true，否则返回false。

```
func (dc *DeploymentController) reconcileOldReplicaSets(ctx context.Context, allRSs []*apps.ReplicaSet, oldRSs []*apps.ReplicaSet, newRS *apps.ReplicaSet, deployment *apps.Deployment) (bool, error) {
    logger := klog.FromContext(ctx)
    oldPodsCount := deploymentutil.GetReplicaCountForReplicaSets(oldRSs)
    if oldPodsCount == 0 {
       // Can't scale down further
       return false, nil
    }
    allPodsCount := deploymentutil.GetReplicaCountForReplicaSets(allRSs)
    logger.V(4).Info("New replica set", "replicaSet", klog.KObj(newRS), "availableReplicas", newRS.Status.AvailableReplicas)
    maxUnavailable := deploymentutil.MaxUnavailable(*deployment)


    minAvailable := *(deployment.Spec.Replicas) - maxUnavailable
    newRSUnavailablePodCount := *(newRS.Spec.Replicas) - newRS.Status.AvailableReplicas
    maxScaledDown := allPodsCount - minAvailable - newRSUnavailablePodCount
    if maxScaledDown <= 0 {
       return false, nil
    }

    // Clean up unhealthy replicas first, otherwise unhealthy replicas will block deployment
    // and cause timeout. See https://github.com/kubernetes/kubernetes/issues/16737
    oldRSs, cleanupCount, err := dc.cleanupUnhealthyReplicas(ctx, oldRSs, deployment, maxScaledDown)
    if err != nil {
       return false, nil
    }
    logger.V(4).Info("Cleaned up unhealthy replicas from old RSes", "count", cleanupCount)

    // Scale down old replica sets, need check maxUnavailable to ensure we can scale down
    allRSs = append(oldRSs, newRS)
    scaledDownCount, err := dc.scaleDownOldReplicaSetsForRollingUpdate(ctx, allRSs, oldRSs, deployment)
    if err != nil {
       return false, nil
    }
    logger.V(4).Info("Scaled down old RSes", "deployment", klog.KObj(deployment), "count", scaledDownCount)

    totalScaledDown := cleanupCount + scaledDownCount
    return totalScaledDown > 0, nil
}
```

**scaleDownOldReplicaSetsForRollingUpdate**

dc.scaleDownOldReplicaSetsForRollingUpdate主要逻辑是缩容旧的replicaset对象，主要逻辑如下：
（1）根据deployment的滚动更新策略配置`.Spec.Strategy.RollingUpdate.MaxUnavailable`和现存的Available状态的pod数量，计算出`totalScaleDownCount`，即目前需要缩容的副本数；
（2）对旧的replicaset对象按照创建时间先后排序；
（3）遍历旧的replicaset对象，根据需要缩容的副本总数，缩容replicaset。





# replicaset controller

### manageReplicas

核心是manageReplicas核心创建删除pod方法，主要是根据replicaset所期望的pod数量与现存pod数量做比较，然后根据比较结果来创建/删除pod，最终使得replicaset对象所期望的pod数量与现存pod数量相等，需要特别注意的是，每一次调用`rsc.manageReplicas`方法，创建/删除pod的个数上限为500。

#### 创建逻辑

主要逻辑：
（1）运算获取需要创建的pod数量，并设置数量上限500；
（2）调用`rsc.expectations.ExpectCreations`，将本轮调谐期望创建的pod数量设置进expectations；
（3）调用`slowStartBatch`函数来对pod进行创建逻辑处理；
（4）调用`slowStartBatch`函数完成后，计算获取创建失败的pod的数量，然后调用相应次数的`rsc.expectations.CreationObserved`方法，减去本轮调谐中期望创建的pod数量。
为什么要减呢？因为expectations记录了replicaset对象在某一次调谐中期望创建/删除的pod数量，pod创建/删除完成后，replicaset controller会watch到pod的创建/删除事件，从而调用`rsc.expectations.CreationObserved`方法来使期望创建/删除的pod数量减少。当有相应数量的pod创建/删除失败后，replicaset controller是不会watch到相应的pod创建/删除事件的，所以必须把本轮调谐期望创建/删除的pod数量做相应的减法，否则本轮调谐中的期望创建/删除pod数量永远不可能小于等于0，这样的话，`rsc.expectations.SatisfiedExpectations`方法就只会等待expectations超时期限到达才会返回true了。

来看到slowStartBatch，可以看到创建pod的算法为：
（1）每次批量创建的 pod 数依次为 1、2、4、8......，呈指数级增长，起与要创建的pod数量相同的goroutine来负责创建pod。
（2）创建pod按1、2、4、8...的递增趋势分多批次进行，若某批次创建pod有失败的（如apiserver限流，丢弃请求等，注意：超时除外，因为initialization处理有可能超时），则后续批次不再进行，结束本次函数调用。

#### 删除逻辑代码块

主要逻辑：
（1）运算获取需要删除的pod数量，并设置数量上限500；
（2）根据要缩容删除的pod数量，先调用`getPodsToDelete`函数找出需要删除的pod列表；
（3）调用`rsc.expectations.ExpectCreations`，将本轮调谐期望删除的pod数量设置进expectations；
（4）每个pod拉起一个goroutine，调用`rsc.podControl.DeletePod`来删除该pod；
（5）对于删除失败的pod，会调用`rsc.expectations.DeletionObserved`方法，减去本轮调谐中期望创建的pod数量。
至于为什么要减，原因跟上面创建逻辑代码块中分析的一样。
（6）等待所有gorouutine完成，return返回。

#### getPodsToDelete

按照下面的排序规则，从上到下进行排序，各个条件相互互斥，符合其中一个条件则排序完成：
（1）优先删除没有绑定node的pod；
（2）优先删除处于Pending状态的pod，然后是Unknown，最后才是Running；
（3）优先删除Not ready的pod，然后才是ready的pod；
（4）按同node上所属replicaset的pod数量排序，优先删除所属replicaset的pod数量多的node上的pod；
（5）按pod ready的时间排序，优先删除ready时间最短的pod；
（6）优先删除pod中容器重启次数较多的pod；
（7）按pod创建时间排序，优先删除创建时间最短的pod。