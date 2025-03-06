# Cilium: What the Agents Do When ClusterMesh Enabled

Ref: https://arthurchiao.art/blog/cilium-code-clustermesh/



![img](https://arthurchiao.art/assets/img/cilium-clustermesh/clustermesh.png)

# 调用栈

```
cell.Provide(NewClusterMesh)
NewClusterMesh
|- lifecycle.Append(cm.common)
clusterMesh.Start
|- createConfigDirectoryWatcher
|  |- fsnotify.NewWatcher()
|  |- watcher.Add(path)
|- cm.configWatcher.watch()
|  |- for f in files
|  |  |- cdw.handle(absolutePath)
|  |  |  |- cdw.lifecycle.add(filename, abspath)
|  |  |  |  |- cm.addLocked(name, path)
|  |  |  |  |  |- if inserted -> cluster.onInsert()
|  |  |  |  |  |  |- rc.restartRemoteConnection()
|  |  |  |  |  |  |- go -> for -> if val := <-rc.changed; val
|  |  |  |  |  |  |  |- rc.restartRemoteConnection()
|  |  |  |  |  |  else ->cluster.changed <- true
|  |  |  |  |  |  |- 
|  |- go cdw.loop() 
```

```
restartRemoteConnection -> rc.controllers.UpdateController -> DoFunc:
|- rc.releaseOldConnection()
|- kvstore.NewClient
|  |- return module.newClient(ctx, options)
|  |  |- for -> connectEtcdClient
|- go rc.watchdog
|  |- select error -> handleErr
|- go rc.Run()
|  |- WatchRemoteIdentities
|  |- mgr = rc.storeFactory.NewWatchStoreManager(backend, rc.name)
|  |- mgr.Register ->  rc.remoteNodes.Watch
|  |- mgr.Register ->  rc.remoteServices.Watch
|  |- mgr.Register ->  rc.ipCacheWatcher.Watch
|  |- mgr.Register ->  rc.remoteIdentityCache.Watch
|  |- mgr.Run(ctx)
|  |  |- mgr.run()
|  |  |- mgr.store.Watch
|  |  |- mgr.wait()
```

# 1 Daemon start: bootstrap ClusterMesh

ClusterMesh通过cell的方式初始化

# 2 Create clustermesh: `NewClusterMesh()`

`NewClusterMesh` 根据提供的信息创建远程集群的缓存：

```
// NewClusterMesh creates a new remote cluster cache based on the
// provided configuration
func NewClusterMesh(lifecycle cell.Lifecycle, c Configuration) *ClusterMesh {
		cm := &ClusterMesh{
      conf:     c,
      nodeName: nodeName,
      globalServices: common.NewGlobalServiceCache(
        c.Metrics.TotalGlobalServices.WithLabelValues(c.ClusterInfo.Name, nodeName),
      ),
      FeatureMetrics: c.FeatureMetrics,
    }
    
    cm.common = common.NewClusterMesh(common.Configuration{
      Config:                       c.Config,
      ClusterInfo:                  c.ClusterInfo,
      ClusterSizeDependantInterval: c.ClusterSizeDependantInterval,
      ServiceResolver:              c.ServiceResolver,

      NewRemoteCluster: cm.NewRemoteCluster,

      NodeName: nodeName,
      Metrics:  c.CommonMetrics,
    })
    
    lifecycle.Append(cm.common)
}
```

它首先创建了一个 `ClusterMesh` 实例，该实例包含一些重要信息，例如：

- `common`：`common` 实现了连接到远程集群的通用逻辑。
- `globalServices`：其后端 Pod 分散在网格中多个集群的 k8s 服务。

接着，它创建了一个目录监视器，该监视器在其 `watch()` 方法中监听配置文件的变化。

## 2.1 Watch config directory

```
func (cdw *configDirectoryWatcher) watch() error {
    files, err := os.ReadDir(cdw.path)
    if err != nil {
       return err
    }

    for _, f := range files {
       if f.IsDir() {
          continue
       }

       absolutePath := filepath.Join(cdw.path, f.Name())
       cdw.handle(absolutePath)
    }

    go cdw.loop()
    return nil
}
```

## 2.2 New config file found

```
func (cm *clusterMesh) add(name, path string) {
    if name == cm.conf.ClusterInfo.Name {
       log.WithField(fieldClusterName, name).Debug("Ignoring configuration for own cluster")
       return
    }

    if err := types.ValidateClusterName(name); err != nil {
       log.WithField(fieldClusterName, name).WithError(err).
          Error("Remote cluster name is invalid. The connection will be forbidden starting from Cilium v1.17")
    }

    cm.mutex.Lock()
    defer cm.mutex.Unlock()
    cm.addLocked(name, path)
}
```



```
func (cm *clusterMesh) addLocked(name, path string) {
inserted := false
    cluster, ok := cm.clusters[name]
    if !ok {
      cluster = cm.newRemoteCluster(name, path)
      cm.clusters[name] = cluster
      inserted = true
    }

    cm.conf.Metrics.TotalRemoteClusters.WithLabelValues(cm.conf.ClusterInfo.Name, 	cm.conf.NodeName).Set(float64(len(cm.clusters)))

    if inserted {
      cluster.onInsert()
    } else {
      // signal a change in configuration
      cluster.changed <- true
    }
}
```

```
func (rc *remoteCluster) onInsert() {
    rc.logger.Info("New remote cluster configuration")

    if skipKvstoreConnection {
       return
    }

    rc.remoteConnectionControllerName = fmt.Sprintf("remote-etcd-%s", rc.name)
    rc.restartRemoteConnection()

    go func() {
       for {
          val := <-rc.changed
          if val {
             rc.logger.Info("etcd configuration has changed, re-creating connection")
             rc.restartRemoteConnection()
          } else {
             rc.logger.Info("Closing connection to remote etcd")
             return
          }
       }
    }()
}
```

`onInsert()` 方法通过调用 `restartRemoteConnection()` 来创建或重新建立与远程 `cilium-etcd` 的连接。

可以通过 CLI 检查远程连接控制器的名称：

```
(node@cluster1) $ cilium status --all-controllers | grep remote
  remote-etcd-k8s-cluster2          73h37m30s ago   never        0       no error
```

# 3 Create/recreate connection to remote etcd

```
func (rc *remoteCluster) restartRemoteConnection() {
	rc.controllers.UpdateController(
		rc.remoteConnectionControllerName,
		controller.ControllerParams{
			Group: remoteConnectionControllerGroup,
			DoFunc: func(ctx context.Context) error {
				rc.releaseOldConnection()
				
				backend, errChan := kvstore.NewClient(ctx, kvstore.EtcdBackendName,
					rc.makeEtcdOpts(), &extraOpts)
					
				rc.mutex.Lock()
				rc.backend = backend
				rc.etcdClusterID = etcdClusterID
				rc.mutex.Unlock()

				ctx, cancel := context.WithCancel(ctx)
				rc.wg.Add(1)
				go func() {
					rc.watchdog(ctx, backend, clusterLock)
					cancel()
					rc.wg.Done()
				}()
				
				config, err := rc.getClusterConfig(ctx, backend)
				
				// Let's execute the long running logic in background. This allows
				// to return early from the controller body, so that the statistics
				// are updated correctly. Instead, blocking until rc.Run terminates
				// would prevent a previous failure from being cleared out.
				rc.wg.Add(1)
				go func() {
					rc.Run(ctx, backend, config, ready)
					cancel()
					rc.wg.Done()
				}()
}
```

```
func (rc *remoteCluster) Run(ctx context.Context, backend kvstore.BackendOperations, config cmtypes.CiliumClusterConfig, ready chan<- error) {

	rc.featureMetrics.AddClusterMeshConfig(ClusterMeshMode(config, option.Config.IdentityAllocationMode), rc.featureMetricMaxClusters)

	defer rc.featureMetrics.DelClusterMeshConfig(ClusterMeshMode(config, option.Config.IdentityAllocationMode), rc.featureMetricMaxClusters)

	remoteIdentityCache, err := rc.remoteIdentityWatcher.WatchRemoteIdentities(rc.name, rc.clusterID, backend, config.Capabilities.Cached)
	
		mgr.Register(adapter(nodeStore.NodeStorePrefix), func(ctx context.Context) {
		rc.remoteNodes.Watch(ctx, backend, path.Join(adapter(nodeStore.NodeStorePrefix), rc.name))
	})

	mgr.Register(adapter(serviceStore.ServiceStorePrefix), func(ctx context.Context) {
		rc.remoteServices.Watch(ctx, backend, path.Join(adapter(serviceStore.ServiceStorePrefix), rc.name))
	})

	mgr.Register(adapter(ipcache.IPIdentitiesPath), func(ctx context.Context) {
		rc.ipCacheWatcher.Watch(ctx, backend, rc.ipCacheWatcherOpts(&config)...)
	})

	mgr.Register(adapter(identityCache.IdentitiesPath), func(ctx context.Context) {
		rc.remoteIdentityCache.Watch(ctx, func(context.Context) { rc.synced.identities.Done() })
	})
	
	mgr.Run(ctx)
}
```

Run 启动管理器，阻塞直到上下文关闭且所有启动的函数终止。

```
// Run starts the manager, blocking until the context is closed and all
// started functions terminated.
func (mgr *wsmSync) Run(ctx context.Context) {
    mgr.run()
    mgr.onUpdate = func(prefix string) { mgr.ready(ctx, prefix) }
    mgr.store.Watch(ctx, mgr.backend, path.Join(kvstore.SyncedPrefix, mgr.clusterName))
    mgr.wait()
}
```

可以看出，在与远程 `cilium-etcd` 建立连接后，它会监听并维护以下远程资源的本地缓存：

- **节点**：远程 `cilium-etcd` 中的 `cilium/state/nodes/v1`
- **服务**：远程 `cilium-etcd` 中的 `cilium/state/services/v1`
- **身份**：远程 `cilium-etcd` 中的 `cilium/state/identities/v1`
- **IP 缓存**：远程 `cilium-etcd` 中的 `cilium/state/ip/v1`

# 4 Sync remote resources to local caches

让我们看看将在此节点上本地缓存的远程资源：

- **节点**
- **服务**
- **身份**
- **IP 缓存**

## 4.1 Sync nodes to local cache

```
// Register registers a function associated with a given kvstore prefix.
// It cannot be called once Run() has started.
func (mgr *wsmCommon) Register(prefix string, function WSMFunc) {
    if mgr.running.Load() {
       mgr.log.Panic("Cannot call Register while the watch store manager is running")
    }

    mgr.functions[prefix] = function
}
```

```
// Run starts the manager, blocking until the context is closed and all
// started functions terminated.
func (mgr *wsmSync) Run(ctx context.Context) {
    mgr.run()
    mgr.onUpdate = func(prefix string) { mgr.ready(ctx, prefix) }
    mgr.store.Watch(ctx, mgr.backend, path.Join(kvstore.SyncedPrefix, mgr.clusterName))
    mgr.wait()
}

func (mgr *wsmSync) OnUpdate(k Key)      { mgr.onUpdate(k.GetKeyName()) }
```

```
// Watch starts watching the specified kvstore prefix, blocking until the context is closed.
// It might be executed multiple times, granted that the previous execution already terminated.
func (rws *restartableWatchStore) Watch(ctx context.Context, backend WatchStoreBackend, prefix string) {
	// The events channel is closed when the context is closed.
	watcher := backend.ListAndWatch(ctx, prefix, 0)
	for event := range watcher.Events {
			rws.drainKeys(true)
			syncedMetric.Set(metrics.BoolToFloat64(true))
			rws.synced.Store(true)
			
			switch event.Typ {
        case kvstore.EventTypeCreate, kvstore.EventTypeModify:
          rws.handleUpsert(key, event.Value)
        case kvstore.EventTypeDelete:
          rws.handleDelete(key)
        }
   }
}

```

```
func (rws *restartableWatchStore) handleUpsert(key string, value []byte) {
    entry := &rwsEntry{key: rws.keyCreator()}
    if err := entry.key.Unmarshal(key, value); err != nil {
       rws.log.WithFields(logrus.Fields{
          logfields.Key:   key,
          logfields.Value: string(value),
       }).WithError(err).Warning("Unable to unmarshal value")
       return
    }

    rws.state[key] = entry
    rws.numEntries.Store(uint64(len(rws.state)))
    rws.entriesMetric.Set(float64(len(rws.state)))
    rws.observer.OnUpdate(entry.key)
}
```

### 4.1.2 On resource update/create/delete

以创建/更新为例。

`updateKey()` 会调用 `onUpdate()`，而 `onUpdate()` 会进一步调用观察者的 `OnUpdate` 处理函数。对于节点资源，

```
func (o *NodeObserver) OnUpdate(k store.Key) {
    if n, ok := k.(*ValidatingNode); ok && !n.IsLocal() {
       nodeCopy := n.DeepCopy()
       nodeCopy.Source = o.source
       o.manager.NodeUpdated(*nodeCopy)
    }
}
```

### 4.1.3 On node updated

```
// NodeUpdated is called after the information of a node has been updated. The
// node in the manager is added or updated if the source is allowed to update
// the node. If an update or addition has occurred, NodeUpdate() of the datapath
// interface is invoked.
func (m *manager) NodeUpdated(n nodeTypes.Node) {
		dpUpdate := true	
		
		for _, address := range n.IPAddresses {
				// Always associate the prefix with metadata, even though this may not
        // end up in an ipcache entry.
        m.ipcache.UpsertMetadata(prefix, n.Source, resource,
          lbls,
          ipcacheTypes.TunnelPeer{Addr: tunnelIP},
          ipcacheTypes.EncryptKey(key))	
        if nodeIdentityOverride {
          m.ipcache.OverrideIdentity(prefix, nodeLabels, n.Source, resource)
        }
        nodeIPsAdded = append(nodeIPsAdded, prefix)
     }
     
      entry, oldNodeExists := m.nodes[nodeIdentifier]
			if oldNodeExists {
					oldNode := entry.node
					entry.node = n
					if dpUpdate {
							m.Iter(func(nh datapath.NodeHandler) { nh.NodeUpdate(oldNode, entry.node); }
			else {
					entry = &nodeEntry{node: n}
					m.nodes[nodeIdentifier] = entry
					if dpUpdate {
							m.Iter(func(nh datapath.NodeHandler) { nh.NodeAdd(entry.node); }
					}
			}
```

### 4.1.4 ipcache insert

`NodeUpdated()` 调用 `ipcache.UpsertMetadata()` 来更新节点信息：

```
// UpsertMetadataBatch applies updates to multiple prefixes in a single transaction,
// reducing potential lock contention.
//
// Returns a revision number that can be passed to WaitForRevision().
func (ipc *IPCache) UpsertMetadataBatch(updates ...MU) (revision uint64) {
    prefixes := make([]netip.Prefix, 0, len(updates))
    ipc.metadata.Lock()
    for _, upd := range updates {
       prefixes = append(prefixes, ipc.metadata.upsertLocked(upd.Prefix, upd.Source, upd.Resource, upd.Metadata...)...)
    }
    ipc.metadata.Unlock()
    revision = ipc.metadata.enqueuePrefixUpdates(prefixes...)
    ipc.TriggerLabelInjection()
    return
}
```







# 5 Misc: create and close connection to remote kvstores







```
// JoinSharedStore creates a new shared store based on the provided
// configuration. An error is returned if the configuration is invalid. The
// store is initialized with the contents of the kvstore. An error is returned
// if the contents cannot be retrieved synchronously from the kvstore. Starts a
// controller to continuously synchronize the store with the kvstore.
func JoinSharedStore(c Configuration) (*SharedStore, error) {
    if err := c.validate(); err != nil {
       return nil, err
    }

    s := &SharedStore{
       conf:       c,
       localKeys:  map[string]LocalKey{},
       sharedKeys: map[string]Key{},
       backend:    c.Backend,
    }

    s.name = "store-" + s.conf.Prefix
    s.controllerName = "kvstore-sync-" + s.name

    if err := s.listAndStartWatcher(); err != nil {
       return nil, err
    }

    controllers.UpdateController(s.controllerName,
       controller.ControllerParams{
          Group: kvstoreSyncControllerGroup,
          DoFunc: func(ctx context.Context) error {
             return s.syncLocalKeys(ctx, true)
          },
          RunInterval: s.conf.SynchronizationInterval,
       },
    )

    return s, nil
}
```

```
func (s *SharedStore) listAndStartWatcher() error {
    listDone := make(chan struct{})

    go s.watcher(listDone)

    select {
    case <-listDone:
    case <-time.After(listTimeoutDefault):
       return fmt.Errorf("timeout while retrieving initial list of objects from kvstore")
    }

    return nil
}
```

```
func (s *SharedStore) watcher(listDone chan struct{}) {
    s.kvstoreWatcher = s.backend.ListAndWatch(s.conf.Context, s.conf.Prefix, watcherChanSize)

    for event := range s.kvstoreWatcher.Events {
       if event.Typ == kvstore.EventTypeListDone {
          s.getLogger().Debug("Initial list of objects received from kvstore")
          close(listDone)
          continue
       }

       logger := s.getLogger().WithFields(logrus.Fields{
          "key":       event.Key,
          "eventType": event.Typ,
       })

       logger.Debugf("Received key update via kvstore [value %s]", string(event.Value))

       keyName := strings.TrimPrefix(event.Key, s.conf.Prefix)
       if keyName[0] == '/' {
          keyName = keyName[1:]
       }

       switch event.Typ {
       case kvstore.EventTypeCreate, kvstore.EventTypeModify:
          if err := s.updateKey(keyName, event.Value); err != nil {
             logger.WithError(err).Warningf("Unable to unmarshal store value: %s", string(event.Value))
          }

       case kvstore.EventTypeDelete:
          if localKey := s.lookupLocalKey(keyName); localKey != nil {
             logger.Warning("Received delete event for local key. Re-creating the key in the kvstore")

             s.syncLocalKey(s.conf.Context, localKey, true)
          } else {
             s.deleteSharedKey(keyName)
          }
       }
    }
}
```