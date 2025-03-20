---
title: (转+译)Cilium Code Walk Through 3 - Cilium Operator
date: 2025-02-27
update: 2025-02-28
comment: false
tags:
  - Cilium
categories:
  - Cilium
---

Cilium Operator 负责管理集群中那些应该在整个集群范围内统一处理的职责，而不是在集群的每个节点上分别处理。Cilium Operator 不在任何数据转发或网络策略决策的关键路径上。如果 Operator 临时不可用，集群通常仍能继续运行。然而，根据配置，Operator 的不可用可能会导致以下问题：
*<!--more-->*
- 如果需要 Operator 分配新的 IP 地址，则 IP 地址管理（IPAM）可能会延迟，从而导致新工作负载的调度延迟。
- 如果 Operator 无法更新键值存储（kvstore）的心跳键，则会导致代理（agent）认为键值存储不健康并重启。

这意味着：

- `cilium-operator` 是一个集群级别的组件，负责处理集群范围内的事务，相比之下，`cilium-agent` 负责管理节点范围内的事务。
- 如果 `cilium-operator` 出现故障：
  - 对于任何节点上现有的 Pod，流量转发或网络策略决策不会受到影响。
  - 如果使用 ENI 模式（在这种模式下，IP 地址由 `cilium-operator` 分配），则 IPAM 会受到影响。
  - 键值存储（例如 `cilium-etcd`）的健康检查也会受到影响。

![img](https://myblog-1307634347.cos.ap-guangzhou.myqcloud.com/blog/cilium-operator.png)

# 调用栈

```
init                                                 // operator/flags.go
 |-cobra.OnInitialize(option.InitConfig())           // pkg/option/config.go
    |-option.InitConfig()                            // pkg/option/config.go
      |-ReadDirConfig
      |-MergeConfig
         |-viper.MergeConfigMap

runOperator
 |-onOperatorStartLeading

onOperatorStartLeading
  |-alloc := allocatorProviders[ipamMode]                         // Get IPAM (e.g. vendor specific IPAM)
  |-alloc.Init(ctx)                                               // Init IPAM allocator
  |-nodeManager := alloc.Start(&ciliumNodeUpdateImplementation{}) //
  |                       |-instancesAPIResync
  |                          |-instancesAPIs.Resync()             // vendor specific handler
  |                              |-m.vpcs      = vendorAPI.GetVPCs()
  |                              |-m.subnets   = vendorAPI.GetSubnets()
  |                              |-m.instances = vendorAPI.GetInstances()
  |
  |-startSynchronizingCiliumNodes(nodeManager)                    // maintain ENI/IP pool for node
  |  |-ciliumNodeStore, ciliumNodeInformer = NewInformer(
  |  |  cache.ResourceEventHandlerFuncs{
  |  |      AddFunc: func(obj interface{}) {
  |  |          nodeManager.Create(k8s.ObjToCiliumNode(obj))
  |  |      },
  |  |      UpdateFunc: func(oldObj, newObj interface{}) {... },
  |  |      DeleteFunc: func(obj interface{}) {
  |  |          nodeManager.Delete(k8s.ObjToCiliumNode(obj))
  |  |      },
  |  |  },
  |  | )
  |  |
  |  |-go ciliumNodeInformer.Run(wait.NeverStop)
  |
  |-startSynchronizingServices                              // operator/k8s_service_sync.go
  | |-go JoinSharedStore(ClusterService{})                  // pkg/kvstore/store/store.go
  | |    |-listAndStartWatcher                              // pkg/kvstore/store/store.go
  | |      |-go s.watcher                                   // pkg/kvstore/store/store.go
  | |        |-updateKey                                    // pkg/kvstore/store/store.go
  | |          |-KeyCreator()                               // operator/k8s_service_sync.go
  | |            |-insert to k8sSvcCache
  | |-k8s.NewInformer(v1.Service).Run
  | |            |-insert to k8sSvcCache
  | |-k8s.NewInformer(v1.Endpoint).Run
  | |            |-insert to k8sSvcCache
  | |-k8sServiceHandler(k8sSvcCache)                        // operator/k8s_service_sync.go
  |   |-create/update/delete key from shared store
  |
  |-runNodeWatcher                                          // operator/k8s_node.go
  | |-JoinSharedStore                                       // pkg/kvstore/store/store.go
  | |    |-listAndStartWatcher                              // pkg/kvstore/store/store.go
  | |      |-go s.watcher                                   // pkg/kvstore/store/store.go
  | |        |-updateKey                                    // pkg/kvstore/store/store.go
  | |          |-KeyCreator()                               //
  | |            |-insert to cache
  | |-k8s.NewInformer(v1.Node).Run
  |    |-create/update/delete key from shared cache
  |
  |-startKvstoreWatchdog                                    // operator/kvstore_watchdog.go
  |  |-go func() {
  |  |   for {
  |  |     RunLocksGC // GC lock-files in kvstore
  |  | }}()
  |  |
  |  |-go func() {
  |      for {
  |        kvstore.Client().Update(HeartbeatPath)
  |    }}()
  |
  |-startKvstoreIdentityGC
  |  |-allocator.RunGC
  |    |-allocator.RunGC
  |       |-backend.RunGC(staleKeyPrevRound)                // pkg/kvstore/allocator/allocator.go
  |          |-allocated := k.backend.ListPrefix()
  |          |-for key, v in allocated:
  |
  |-enableCiliumEndpointSyncGC                              // operator/k8s_cep_gc.go
  | |-ciliumClient.CiliumEndpoints(cep.Namespace).Delete
  |-enableCNPWatcher
  |-enableCCNPWatcher
```

Cilium会watch 四种K8s资源Service、Endpoint、Node、CNP (Cilium Network Policy)

## `runOperator()`

```
func runOperator(cmd *cobra.Command) {
    k8sInitDone := make(chan struct{})
    isLeader.Store(false)

    // Configure API server for the operator.
    srv := api.NewServer(shutdownSignal, k8sInitDone, getAPIServerAddr()...)

    go func() {
        srv.WithStatusCheckFunc(checkStatus).StartServer()
    }()

    initK8s(k8sInitDone)

    // Register the CRDs after validating that we are running on a supported version of K8s.
    client.RegisterCRDs(); err != nil {

    operatorID := os.Hostname()
    operatorID = rand.RandomStringWithPrefix(operatorID+"-", 10)

    ns := option.Config.K8sNamespace
    // If due to any reason the CILIUM_K8S_NAMESPACE is not set we assume the operator
    // to be in default namespace.
    if ns == "" {
        ns = metav1.NamespaceDefault
    }

    leResourceLock := &resourcelock.LeaseLock{
        LeaseMeta: metav1.ObjectMeta{
            Name:      leaderElectionResourceLockName,
            Namespace: ns,
        },
        Client: k8s.Client().CoordinationV1(),
        LockConfig: resourcelock.ResourceLockConfig{
            // Identity name of the lock holder
            Identity: operatorID,
        },
    }

    // Start the leader election for running cilium-operators
    leaderelection.RunOrDie(leaderElectionCtx, leaderelection.LeaderElectionConfig{
        Name: leaderElectionResourceLockName,

        Lock:            leResourceLock,
        ReleaseOnCancel: true,

        LeaseDuration: operatorOption.Config.LeaderElectionLeaseDuration,
        RenewDeadline: operatorOption.Config.LeaderElectionRenewDeadline,
        RetryPeriod:   operatorOption.Config.LeaderElectionRetryPeriod,

        Callbacks: leaderelection.LeaderCallbacks{
            OnStartedLeading: onOperatorStartLeading,       // start working as leader
            OnStoppedLeading: func() { },
            OnNewLeader: func(identity string) {
                if identity == operatorID {
                    log.Info("Leading the operator HA deployment")
                } else {
                    log.WithFields(logrus.Fields{
                        "newLeader":  identity,
                        "operatorID": operatorID,
                    }).Info("Leader re-election complete")
                }
            },
        },
    })
}
```

## `startSynchronizingCiliumNodes()`

### 1 maintain ENI/IP pool for nodes (ENI mode)

On `CiliumNode` create/update/delete events, node manager’s handlers will be called accordingly, e.g. for `create` events:

```
startSynchronizingCiliumNodes
 |-AddFunc
   |-nodeManager.Create(ciliumnode)
      |-Update
        |-node, ok := n.nodes[ciliumnode.Name] // pkg/ipam/node.Node{}
        |-defer node.UpdatedResource(resource)
        |             |-n.ops.UpdatedNode(resource)
        |             |-n.instanceRunning = true
        |             |-n.recalculate()
        |             |-allocationNeeded := n.allocationNeeded()
        |             |-if allocationNeeded {
        |             |   n.requirePoolMaintenance()
        |             |   n.poolMaintainer.Trigger()
        |             | }
        |
        |-if !ok:
            |-NewTrigger("ipam-pool-maintainer-<nodename>",       func: node.MaintainIPPool)
            |  |-n.maintainIPPool
            |  |   |-determineMaintenanceAction
            |  |      |-PrepareIPAllocation
            |  |      |-n.ops.ReleaseIPs
            |  |      |-n.ops.AllocateIPs
            |  |      |   |-AssignPrivateIPAddresses(eni, numIPs)
            |  |      |       |-vendorAPI
            |  |      |-n.createInterface(ctx, a.allocation)
            |  |          |-n.ops.CreateInterface
            |  |              |-vendorAPI CreateNetworkInterface
            |  |              |-vendorAPI AttachNetworkInterface
            |  |              |-vendorAPI WaitNetworkInterfaceAttached
            |  |              |-n.manager.UpdateVNIC(instanceID, eni)
            |  |
            |  |-n.poolMaintenanceComplete
            |  |-recalculate
            |  |  |-n.ops.ResyncInterfacesAndIPs
            |  |      |-n.manager.ForeachInstance(func {
            |  |        for _, ip := range eni.Addresses
            |  |          available[ip] = ipamTypes.AllocationIP{Resource: e.ID}
            |  |      })
            |  |-n.manager.resyncTrigger.Trigger()
            |
            |-NewTrigger("ipam-pool-maintainer-<nodename>-retry", func: poolMaintainer.Trigger)
            |
            |-NewTrigger("ipam-node-k8s-sync-<nodename>",         func: node.syncToAPIServer)
               |-n.ops.PopulateStatusFields(node)
                   |-n.manager.ForeachInstance(n.node.InstanceID(),
                       func(instanceID, interfaceID string, rev ipamTypes.InterfaceRevision) error {
                         resource.Status.ENIs[interfaceID] = *e.DeepCopy()
                       }
           })
```

对于不依赖 ENI（Elastic Network Interface）进行网络连接的本地部署节点，这一步骤要简单得多，因为不需要维护 ENI/IP 的水位线（watermarks）。

#### 2 Update `CiliumNode` status field

The `ipam-node-k8s-sync-<nodename>` controller calls `PopulateStatusFields()` to update the `status` field of the CR.

# `startSynchronizingServices()`

`startSynchronizingServices()` 的功能是：如果 Kubernetes 中存在 Service/Endpoint 的变更，则将这些变更同步到键值存储（如 Cilium 的 etcd）。为了完成这一任务，它使用了两个变量：

- `k8sSvcCache`：Kubernetes 中 Service 的本地缓存。
- `kvs *store.SharedStore`：键值存储中所有 Kubernetes 集群的 Service 的本地（合并）缓存。在 ClusterMesh 中，所有 Kubernetes 集群的 Service 将被合并为所谓的 ClusterService（ClusterService = clustername/Service）。

```
var (
    k8sSvcCache = k8s.NewServiceCache(nil)
    kvs         *store.SharedStore
)

func startSynchronizingServices() {
    go func() {                                      // list ClusterService from kvstore, merge to kvs
        kvs = store.JoinSharedStore(Configuration{   // ClusterService is used by ClusterMesh
            Prefix: "cilium/states/services/v1" ,
            KeyCreator: func() store.Key { return &serviceStore.ClusterService{} },
            SynchronizationInterval: 5 * time.Minute,
        })
    }()

    svcController := informer.NewInformer(          // Watch for k8s v1.Service changes, save to k8sSvcCache
        cache.NewListWatchFromClient("services", v1.NamespaceAll),
        cache.ResourceEventHandlerFuncs{
            AddFunc: func(obj interface{}) {
                k8sSvc := k8s.ObjToV1Services(obj)
                k8sSvcCache.UpdateService(k8sSvc)
            },
            UpdateFunc: ...
            DeleteFunc: ...
        },
    )
    go svcController.Run(wait.NeverStop)

    switch { // We only enable either "Endpoints" or "EndpointSlice"
    case k8s.SupportsEndpointSlice():
        endpointController, endpointSliceEnabled = endpointSlicesInit(k8s.WatcherCli())
        fallthrough
    default:
        endpointController = endpointsInit(k8s.WatcherCli())
        go endpointController.Run(wait.NeverStop)    // Update endpoint changes to k8sSvcCache
    }

    go func() {
        k8sServiceHandler()  // handle kvs if there are changes in k8sSvcCache
    }()
}
```

## 1 `JoinSharedStore()`

This method will listen to the specified resource, merge them with locally, and start a controller to continuously synchronize the local store with the kvstore (cilium-etcd):

- on receiving create/update/delete events from kvstore, update the local store accordingly
- deletions of stale keys in kvstore rely on periodic GC jobs that is independent from this method

```
// JoinSharedStore creates a new shared store based on the provided configuration.
// Starts a controller to continuously synchronize the store with the kvstore.
func JoinSharedStore(c Configuration) (*SharedStore, error) {
    s := &SharedStore{
        localKeys:  map[string]LocalKey{},
        sharedKeys: map[string]Key{},
    }
    s.name = "store-" + s.conf.Prefix
    s.controllerName = "kvstore-sync-" + s.name

    s.listAndStartWatcher();   // start watcher

    controllers.UpdateController(
        DoFunc: func(ctx ) error { return s.syncLocalKeys(ctx) },
        RunInterval: s.conf.SynchronizationInterval,
    )
}
```

```
func (s *SharedStore) listAndStartWatcher() error {
    go s.watcher(listDone)
}
```

```
func (s *SharedStore) watcher(listDone chan bool) {
    s.kvstoreWatcher = s.backend.ListAndWatch(s.name+"-watcher", s.conf.Prefix)

    for event := range s.kvstoreWatcher.Events {
        if event.Typ == ListDone { // Initial list of objects received from kvstore
            close(listDone)
            continue
        }

        keyName := strings.TrimPrefix(event.Key, s.conf.Prefix)
        if keyName[0] == '/'
            keyName = keyName[1:]

        switch event.Typ {
        case Create, Modify:
            s.updateKey(keyName, event.Value);  // insert into shared store, then notify observer
        case Delete:
            if localKey := s.lookupLocalKey(keyName); localKey != nil {
                s.syncLocalKey(s.conf.Context, localKey)
            } else {
                s.deleteSharedKey(keyName)
            }
        }
    }
}
```

## 2 `endpointSlicesInit()` and `endpointsInit()`

These two methods watch for k8s `v1.Endpoints` changes and push changes into local cache `k8sSvcCache`, let’s look at the latter one:

```
func endpointsInit(k8sClient kubernetes.Interface) cache.Controller {
    endpointController := informer.NewInformer(
        cache.NewListWatchFromClient("endpoints", v1.NamespaceAll,
            // Don't get any events from kubernetes endpoints.
            fields.ParseSelectorOrDie("metadata.name!=kube-scheduler,metadata.name!=kube-controller-manager"),
        ),
        cache.ResourceEventHandlerFuncs{
            AddFunc: func(obj interface{}) {
                k8sEP := k8s.ObjToV1Endpoints(obj)
                k8sSvcCache.UpdateEndpoints(k8sEP, swgEps)
            },
            UpdateFunc: ...
            DeleteFunc: ...
        },
    )
    return endpointController
}
```

## 3 `k8sServiceHandler()`

When there are **Service/Endpoint changes in k8s** (local cache `k8sSvcCache`), method `k8sServiceHandler()` will update the changes to **the shared store of kvstore** (cilium-etcd’s local cache):

```
func k8sServiceHandler() {
    serviceHandler := func(event k8s.ServiceEvent) {
        svc := k8s.NewClusterService(event.ID, event.Service, event.Endpoints)
        svc.Cluster = Config.ClusterName

        // Kubernetes service definition changed
        if !event.Service.Shared { // annotation may have been added, delete an eventual existing service
            kvs.DeleteLocalKey(context.TODO(), &svc)
            return
        }

        switch event.Action {      // k8s actions
        case k8s.UpdateService: kvs.UpdateLocalKeySync(&svc)
        case k8s.DeleteService: kvs.DeleteLocalKey(&svc)
        }
    }

    for {
        event, ok := <-k8sSvcCache.Events // k8s Service/Endpoint changed
        if !ok {
            return
        }
        serviceHandler(event)             // trigger update to local cache of kvstore
    }
}
```

# `runNodeWatcher()`

Similar as `startSynchronizingServices()`, `runNodeWatcher()` synchronizing `CiliumNode` resources from k8s to a local cache of cilium-etcd by simultaneously listening to them.

Only ENI mode uses this (CiliumNode).

```
func runNodeWatcher(nodeManager *allocator.NodeEventHandler) error {
    ciliumNodeStore := store.JoinSharedStore(Configuration{  // listen to kvstore, merge to local cache
        Prefix:     nodeStore.NodeStorePrefix,
        KeyCreator: nodeStore.KeyCreator,
    })

    k8sNodeStore, nodeController := informer.NewInformer(    // listen to k8s, save to local cache
        cache.NewListWatchFromClient("ciliumnodes", v1.NamespaceAll, fields.Everything()),
        cache.ResourceEventHandlerFuncs{
            AddFunc: func(obj interface{}) {
                ciliumNode := k8s.ObjToCiliumNode(obj)
                nodeNew := nodeTypes.ParseCiliumNode(ciliumNode)
                ciliumNodeStore.UpdateKeySync(&nodeNew)
            },
            ...
        },
    )
    go nodeController.Run(wait.NeverStop)

    go func() {
        listOfK8sNodes := k8sNodeStore.ListKeys()

        kvStoreNodes := ciliumNodeStore.SharedKeysMap()
        for k8sNode := range listOfK8sNodes { // The remaining kvStoreNodes are leftovers
            kvStoreNodeName := nodeTypes.GetKeyNodeName(option.Config.ClusterName, k8sNode)
            delete(kvStoreNodes, kvStoreNodeName)
        }

        for kvStoreNode := range kvStoreNodes {
            if strings.HasPrefix(kvStoreNode.GetKeyName(), option.Config.ClusterName)
                ciliumNodeStore.DeleteLocalKey(context.TODO(), kvStoreNode)
        }
    }()

    if Config.EnableCNPNodeStatusGC && Config.CNPNodeStatusGCInterval != 0
        go runCNPNodeStatusGC("cnp-node-gc", false, ciliumNodeStore)

    if Config.EnableCCNPNodeStatusGC && Config.CNPNodeStatusGCInterval != 0
        go runCNPNodeStatusGC("ccnp-node-gc", true, ciliumNodeStore)
}
```

# `startKvstoreWatchdog()`: GC of unused lock files in kvstore

- 每个锁的租约周期（25秒）扫描键值存储（kvstore），查找并移除未使用的锁。
- 更新键值存储的心跳信息（每1分钟）。

```
func startKvstoreWatchdog() {
    backend := NewKVStoreBackend(cache.IdentitiesPath, ...)   // identities in kvstore
    a := allocator.NewAllocatorForGC(backend)

    keysToDelete := map[string]kvstore.Value{}
    go func() {
        for {
            keysToDelete = getOldestLeases(keysToDelete)
            keysToDelete2 := a.RunLocksGC(ctx, keysToDelete)  // perform GC
            keysToDelete = keysToDelete2
            <-time.After(defaults.LockLeaseTTL)               // 25s
        }
    }()

    go func() {
        for {
            kvstore.Client().Update(ctx, kvstore.HeartbeatPath, time.Now())
            <-time.After(kvstore.HeartbeatWriteInterval)      // 1min
        }
    }()
}
```

# `startKvstoreIdentityGC()`

执行定期的身份垃圾回收（GC）。GC 间隔通过 `--identity-gc-interval=<interval>` 配置，默认值为键值存储（kvstore）的租约过期时间（`--kvstore-lease-ttl="15m"`）。

此外，GC 进程会对键值存储产生周期性的 QPS（每秒查询率）峰值（默认 QPS 限制为 20）。可以通过以下方式配置客户端键值存储的 QPS 限制：

### 7.1 Background: identity allocation in cilium-agent side

### Agent: create identity allocator

```
func NewAllocator(typ AllocatorKey, backend Backend, opts ...AllocatorOption) (*Allocator, error) {
    a := &Allocator{
        keyType:      typ,
        backend:      backend,                      // kvstore client
        localKeys:    newLocalKeys(),
        stopGC:       make(chan struct{}),          // keepalive master/slave keys in kvstore
        remoteCaches: map[*RemoteCache]struct{}{},
    }

    for _, fn := range opts {
        fn(a)
    }

    a.mainCache = newCache(a)
    a.idPool = idpool.NewIDPool(a.min, a.max)
    a.initialListDone = a.mainCache.start()

    if !a.disableGC {
        go func() {
            select {
            case <-a.initialListDone:
            case <-time.After(AllocatorListTimeout): // List kvstore contents timed out
                log.Fatalf("Timeout while waiting for initial allocator state")
            }
            a.startLocalKeySync()
        }()
    }

    return a, nil
}
```

### Agent: ensure local keys always in kvstore with sync loop

A loop to periodically check and re-create identity keys if they are missing from KVStore:

- **master key**: identity ID to value
- **slave key**: value to identity ID

```
func (a *Allocator) startLocalKeySync() {
    go func(a *Allocator) {
        for {
            a.syncLocalKeys() // for k in keys: kvstore.UpdateKey()

            select {
            case <-a.stopGC:
                return        // Stopped master key sync routine
            case <-time.After(KVstorePeriodicSync): // 5min
            }
        }
    }(a)
}

// Check the kvstore and verify that a master key exists for all locally used allocations.
// This will restore master keys if deleted for some reason.
func (a *Allocator) syncLocalKeys() error {
    ids := a.localKeys.getVerifiedIDs()

    for id, value := range ids {
        a.backend.UpdateKey(context.TODO(), id, value, false)
    }
}
```

```
// UpdateKey refreshes the record that this node is using this key -> id mapping.
// When reliablyMissing is set it will also recreate missing master or slave keys.
func (k *kvstoreBackend) UpdateKey(ctx , id idpool.ID, key allocator.AllocatorKey, reliablyMissing bool) error {
    var (
        err        error
        recreated  bool
        keyPath    = path.Join(k.idPrefix, id.String())
        keyEncoded = []byte(k.backend.Encode([]byte(key.GetKey())))
        valueKey   = path.Join(k.valuePrefix, k.backend.Encode([]byte(key.GetKey())), k.suffix)
    )

    // Ensures that any existing potentially conflicting key is never overwritten.
    success := k.backend.CreateOnly(ctx, keyPath, keyEncoded, false)
    switch {
    case err != nil:
        return fmt.Errorf("Unable to re-create missing master key "%s" -> "%s": %s", fieldKey, valueKey, err)
    case success:
        log.Warning("Re-created missing master key")
    }

    // Also re-create the slave key in case it has been deleted.
    if reliablyMissing {
        recreated = k.backend.CreateOnly(ctx, valueKey, []byte(id.String()), true)
    } else {
        recreated = k.backend.UpdateIfDifferent(ctx, valueKey, []byte(id.String()), true)
    }
    switch {
    case err != nil:
        return fmt.Errorf("Unable to re-create missing slave key "%s" -> "%s": %s", fieldKey, valueKey, err)
    case recreated:
        log.Warning("Re-created missing slave key")
    }

    return nil
}
```