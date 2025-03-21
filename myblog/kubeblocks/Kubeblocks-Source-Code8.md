---
title: KubeBlocks源码笔记八--Event
date: 2025-03-05
update: 2025-03-05
comment: false
tags:
  - kubeblocks
categories:
  - kubeblocks
---

KubeBlocks依赖Kubernetes中的Event来传递信息，包括Pod角色切换等核心机制都是通过解析Event来获取信息

*<!--more-->*

EventReconciler负责watch Kubernetes中的Event并处理

包括角色探测在内的一些功能需要依赖Event做信息传递

```
event := &corev1.Event{}
if err := r.Client.Get(ctx, req.NamespacedName, event, multicluster.InDataContextUnspecified()); err != nil {
    return intctrlutil.CheckedRequeueWithError(err, reqCtx.Log, "getEventError")
}

if r.isEventHandled(event) {
    return intctrlutil.Reconciled()
}

handlers := []eventHandler{
    &instanceset.PodRoleEventHandler{},
    &component.AvailableEventHandler{},
    &component.KBAgentTaskEventHandler{},
}
for _, handler := range handlers {
    if err := handler.Handle(r.Client, reqCtx, r.Recorder, event); err != nil && !apierrors.IsNotFound(err) {
       return intctrlutil.RequeueWithError(err, reqCtx.Log, "handleEventError")
    }
}
```

通过比较annotations[eventHandledAnnotationKey] 是否等于 count来判断是否已经处理过

# PodRoleEventHandler

某个角色切换的Event的message为：

```
 {
    "event": "Success",
    "operation": "checkRole",
    "originalRole": "secondary",
    "role": "{\"term\":\"1742497580554442\",\"PodRoleNamePairs\":[{\"podName\":\"XXXX\",\"roleName\":\"primary\",\"podUid\":\"c8451692-ee02-475c-8842-ee7c62349a1d\"}]}"
}}
```

负责处理pod自身的role

1. 提取probeEvent中的信息

2. 通过event.Count判断该Event是否被处理

3. 处理Event
   1. snapshot := parseProbeEventMessage
   2. 获取对应的Pod，检查last-role-snapshot-version和
   3. 获取对应的InstanceSet，调用updatePodRoleLabel更新角色

KubeBlocks依赖于Service的**selector**切换主备流量达到读写分离的目的，pod上角色标签的切换就是依赖这里的Handler完成

这里看一下Event是如何发送的

```
// pkg/kbagent/service/probe.go
go func() {
    ticker := time.NewTicker(time.Duration(probe.ReportPeriodSeconds) * time.Second)
    defer ticker.Stop()

    var latestReportedEvent *proto.ProbeEvent
    for range ticker.C {
       latestEvent := gather(r.latestEvent)
       if latestEvent == nil && latestReportedEvent != nil {
          latestEvent = latestReportedEvent
       }
       if latestEvent != nil {
          r.logger.Info("report probe event periodically",
             "code", latestEvent.Code, "output", outputPrefix(latestEvent.Output), "message", latestEvent.Message)
          r.sendEvent(latestEvent)
       }
       latestReportedEvent = latestEvent
    }
}()
```

# KBAgentTaskEventHandler

目前的InstanceSet的副本扩缩容由Event机制进行通知，修改环境变量中的副本数

KubeBlocks会在Transformer_component_workload.go中的scaleOut或者scaleIn中调用发送Event

```
parameters, err := component.NewReplicaTask(r.synthesizeComp.FullCompName, r.synthesizeComp.Generation, source, replicas)
```

KBAgentTaskEventHandler会根据env的不同状态处理

```
	finished := !event.EndTime.IsZero()
	switch {
	case finished && event.Code == 0:
		err = handleNewReplicaTaskEvent4Finished(ctx, cli, its, event)
	case finished:
		err = handleNewReplicaTaskEvent4Failed(ctx, cli, its, event)
	default:
		err = handleNewReplicaTaskEvent4Unfinished(ctx, cli, its, event)
	}
```

具体修改逻辑

```
parameters, err := updateKBAgentTaskEnv(obj.Data, func(task proto.Task) *proto.Task {
       if task.Task == newReplicaTask {
          replicas := strings.Split(task.Replicas, ",")
          replicas = slices.DeleteFunc(replicas, func(r string) bool {
             return r == event.Replica
          })
          if len(replicas) == 0 {
             return nil
          }
          task.Replicas = strings.Join(replicas, ",")
          if task.NewReplica != nil {
             task.NewReplica.Replicas = task.Replicas
          }
       }
       return &task
    })
    if err != nil {
       return err
    }
    if parameters == nil {
       return nil // do nothing
    }

    if obj.Data == nil {
       obj.Data = make(map[string]string)
    }
    for k, v := range parameters {
       obj.Data[k] = v
    }
    return cli.Update(ctx, obj, inDataContext())
}(); err != nil {
    return err
}
```

# AvailableEventHandler

修改Component的available状态