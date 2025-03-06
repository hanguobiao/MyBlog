# Statefulset原理

首先看sync函数，没什么好讲的

```
func (ssc *StatefulSetController) sync(ctx context.Context, key string) error {
		namespace, name, err := cache.SplitMetaNamespaceKey(key)
		set, err := ssc.setLister.StatefulSets(namespace).Get(name)
		
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

1. 将当前STS所属的所有POD副本分组，超出数量的副本分到condemned中等待后续删除。需要保留的副本归入replicas
2. 如果知道replicas的序号中间有哪个序号是空的，就创建
3. 获取到第一个不健康的POD

