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

# PodRoleEventHandler

负责处理pod自身的ro

1. 提取probeEvent中的信息

2. 通过event.Count判断该Event是否被处理

3. 处理Event
   1. snapshot := parseProbeEventMessage
   2. 获取对应的Pod，检查last-role-snapshot-version和
   3. 获取对应的InstanceSet，调用updatePodRoleLabel更新角色

# KBAgentTaskEventHandler