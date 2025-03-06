基于1.16.6版本的Cilium代码来做源码笔记，期望可以学习其中的关键思想

# 0 Overview

```
main                        // daemon/main.go
hive.New(cmd.Agent)
cmd.Execute(cmd.NewAgentCmd(agentHive))         
  |- h.Run()                // pkg/option/config.go
      |- h.Start()
        |- h.lifecycle.Start()
          |-
      |- h.waitForSignalOrShutdown()
      |- h.Stop()

newDaemonPromise            //    daemon/cmd/daemon_main.go
|- newDaemon                // -> daemon/cmd/daemon.go
  |- bootstrapStats.XXX.Start()
  |- initKubeProxyReplacementOptions(params.Sysctl, params.TunnelConfig)
  |- ctmap.InitMapInfo
  |- policymap.InitMapInfo
  |- lbmap.Init(lbmapInitParams)
  |- params.NodeManager.Subscribe
  |- d.configModifyQueue.Run()
  |- d.initPolicy()
  |- // Stop all endpoints (its goroutines) on exit.
 *|- d.initMaps()           // deamon/cmd/datapath.go|- ipv4Nat, ipv6Nat := nat.GlobalMaps
  |  |- lxcmap.LXCMap().OpenOrCreate()
  |  |- ipcachemap.IPCacheMap().Recreate()
  |  |- for ep in d.endpointManager.GetEndpoints() -> ep.InitMap()
  |  |- for ep in d.endpointManager.GetEndpoints()
  |  |  |- for m in  ctmap.LocalMaps() -> m.Create()
  |  |- for m in  ctmap.GlobalMaps() -> m.Create()
  |  |- ipv4Nat, ipv6Nat := nat.GlobalMaps
  |  |- ipv4Nat.Create();ipv6Nat.Create()
  |  |- neighborsmap.InitMaps
  |  |- fragmap.InitMap
  |  |- if !Config.RestoreState -> lxcmap.LXCMap.DeleteAll()
  |  |- lbmap.NewSkipLBMap()
 *|- d.svc.RestoreServices() LOCK
  |  |- s.restoreServicesLocked
  |  |- s.restoreBackendsLocked
  |- d.k8sWatcher.RunK8sServiceHandler() -> go k.k8sServiceHandler()
  |  |- eventHandler := func (event k8s.ServiceEvent)
  |  |  |- switch event.Action
  |  |  |  |- case k8s.UpdateService: k.addK8sSVCs
  |  |  |  |- case k8s.DeleteService: k.delK8sSVCs
  
  |- d.fetchOldEndpoints
  |  |- state.possible = endpoint.ReadEPsFromDirNames
  |- d.bootstrapFQDN
  |- d.nodeDiscovery.UpdateCiliumNodeResource()
  |- agentK8s.WaitForNodeInformation
  |- d.svc.InitMaps()
  |- policymap.InitCallMaps

  
  |- finishKubeProxyReplacementInit(
  
  |- d.k8sWatcher.InitK8sSubsystem(d.ctx, params.CacheStatus)
  |- clearCiliumVeths()
  |- d.initKVStore
  |  |- controller.NewManager().UpdateController("kvstore-locks-gc"
  |  |- kvstore.Setup
  |- d.configureIPAM()
  |  |- node.SetIPv4AllocRange(allocCIDR)
  |  |- node.SetIPv6NodeRange(allocCIDR)
  |  |- node.AutoComplete()
  |- d.startIPAM()
  |  |- d.ipam.ConfigureAllocator()
  |- d.restoreOldEndpoints
  |  |- for op in state.possible 
  |  |  |- ep.SetAllocator
  |  |  |- d.validateEndpoint
  |  |  |- ep.SetDefaultConfiguration()
  |  |  |- ep.SetProxy(d.l7Proxy)
  |  |- for epIP in existingEndpoints
  |  |  |- net.ParseIP(epIP)
  |- d.allocateIPs
  |- d.nodeDiscovery.StartDiscovery()
  |- k8s.AnnotateNode -> updateNodeAnnotation()
  |  |- c.CoreV1().Nodes().Patch()
  |- d.init()
  |  |- os.MkdirAll(globalsDir, defaults.RuntimePathRights)
  |  |- os.Chdir(option.Config.StateDir)
  |  |- d.Datapath().Orchestrator().Reinitialize(d.ctx) -> o.params.Loader.Reinitialize
  |  |  |- l.nodeConfig.Store(&cfg)
  |  |  |- setupBaseDevice
  |  |  |- setupIPIPDevices
  |  |  |- setupTunnelDevice
  |  |  |- l.sysctl.ApplySettings
  |  |  |- addHostDeviceAddr
  |  |  |- if option.Config.EnableIPSec ->  compileNetwork; l.reinitializeIPSec
  |  |  |- 
  |  |- linuxdatapath.NodeEnsureLocalRoutingRule()
  |- d.updateDNSDatapathRules
  |- params.SyncHostIPs.StartAndWaitFirst
  |  |- 
  |- d.ipcache.InitIPIdentityWatcher
  |  |- setupIPIdentityWatcher.Do -> go 
  |  |  |- watcher = NewIPIdentityWatcher()
  |  |  |- watcher.Watch
  |- params.IPsecKeyCustodian.StartBackgroundJobs
  
  
|- startDaemon
 	|- d.ipcache.WaitForRevision
  |- d.initRestore
  |  |- 
  |- params.CTNATMapGC.Enable()
  |- go
  |  |- ms.CollectStaleMapGarbage()
  |  |- ms.RemoveDisabledMaps()
  |  |- d.releaseRestoredIdentities()
  |- d.endpointManager.Subscribe(d)
  |- d.initHealth(params.HealthAPISpec, cleaner, params.Sysctl)
  |- d.startStatusCollector(cleaner)
  |- d.startAgentHealthHTTPService()
  |- d.controllers.UpdateController

```

# cobra启动

```
var daemonCell = cell.Module(
	"daemon",
	"Legacy Daemon",

	cell.Provide(
		newDaemonPromise,
		promise.New[endpointstate.Restorer],
		newSyncHostIPs,
	),
	// Provide a read-only copy of the current daemon settings to be consumed
	// by the debuginfo API
	cell.ProvidePrivate(daemonSettings),
	cell.Invoke(registerEndpointStateResolver),
	cell.Invoke(func(promise.Promise[*Daemon]) {}), // Force instantiation.
	endpointBPFrogWatchdogCell,
)

```



## newDaemon

### bootstrapStats

通过bootstrapStats记录各个部分启动耗时

### initMaps(): open or create all BPF maps

```
initMaps 会打开所有 BPF map（如果不存在则创建它们）。这一操作必须优先于任何读取 BPF map 的操作执行，尤其是在恢复端点（endpoints）和服务（services）之前。
```

#### ipcachemap.IPCacheMap().Recreate()

```
ipcache 在多个端点（endpoints）之间共享。解除由先前 agent 实例创建的旧 ipcache map 的固定（unpin），以防止新端点使用旧的 map。旧的 ipcache 仍会被已加载的 BPF 程序使用，但 agent 将不再更新它。
这样做的目的是允许尚未重新生成的现有端点继续使用当前的 ipcache，直到端点首次被重新生成且其 BPF 程序被替换。
现有的端点使用的策略映射（policy map）可能已经过时，因为本地身份（local identities）在 agent 重启时会被重新分配。
```

### RestoreServices



用于从BPF Maps中恢复service <-> backend的映射

```
// 从 BPF map 中读取现有服务的 ID 并预先保留。这一操作必须在以下两个动作之前完成：
// 1. 连接到 Kubernetes API 服务器
// 2. 对外提供 API 服务
// 这是为了确保服务 ID 在重启过程中不会发生变化，同时防止新服务意外占用已有的服务 ID。
// 此外，还需要根据对应的旧版本（legacy）服务创建缺失的 v2 版本服务。
```

### RunK8sServiceHandler

```
func (k *K8sWatcher) k8sServiceHandler() {
    eventHandler := func(event k8s.ServiceEvent) {
        svc := event.Service

        switch event.Action {
        case k8s.UpdateService:
            k.addK8sSVCs(event.ID, event.OldService, svc, event.Endpoints)
        case k8s.DeleteService:
            k.delK8sSVCs(event.ID, event.Service)
        }
    }

    for {
        select {
					case <-k.stop:
						return
					case event, ok := <-k.k8sSvcCache.Events:
						if !ok {
							return
						}
						eventHandler(event)
				}
    }
}
```



### restoreOldEndpoints

`restoreOldEndpoints` 是恢复端点结构的第二步，它会从 CIDR 块中分配现有 IP 地址，然后将端点插入到端点列表中。在端点构建器准备好之后，需要调用 `regenerateRestoredEndpoints()`。无法与容器工作负载关联的端点将被删除。

```
我们需要在端点生命周期的这个阶段设置身份分配器，因为身份分配器是在端点从磁盘恢复之后才初始化的。这是因为我们需要为通过 IPAM 恢复的端点预留 IP 地址。IP 地址的预留会影响与节点地址相关的 IP 分配，而我们需要在身份分配器初始化之前了解节点地址。我们需要知道节点地址，因为在向键值存储添加引用时，本地节点的 IP 地址被用作键的后缀。
ep.SetAllocator(d.identityAllocator)
```

### AnnotateNode

`AnnotateNode` 会在给定的 Kubernetes 节点名称中写入 IPv4 和 IPv6 的 CIDR 块以及健康检查 IP。如果在更新节点时发生失败，该函数将启动一个 Go 协程，无限次重试节点更新。

### d.init()

```
// Reinitialize (re-)configures the base datapath configuration including global

// BPF programs, netfilter rule configuration and reserving routes in IPAM for

// locally detected prefixes. It may be run upon initial Cilium startup, after

// restore from a previous Cilium run, or during regular Cilium operation.
```

### SyncHostIPs

```
func (s *syncHostIPs) StartAndWaitFirst(ctx context.Context) error {
	close(s.start)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-s.firstError:
		return err
	}
}
```

```go
func (s *syncHostIPs) loop(ctx context.Context, health cell.Health) error {
	// Wait for start signal. This is needed for now to synchronize with initialization
	// (e.g. IPcache restoration, map init) that still happens in newDaemon.
	select {
	case <-s.start:
	case <-ctx.Done():
		s.firstError <- ctx.Err()
		return nil
	}

	first := true
	ticker := time.NewTicker(syncHostIPsInterval)
	defer ticker.Stop()

	for {
		txn := s.params.DB.ReadTxn()
		addrs, watch := s.params.NodeAddresses.AllWatch(txn)

		err := s.sync(addrs)
		if err != nil {
			log.WithError(err).Errorf("Failed to sync host IPs, retrying later")
			health.Degraded("Failed to sync host IPs", err)
		} else {
			health.OK("Synchronized")
		}

		if first {
			first = false
			s.firstError <- err
		}

		select {
		case <-ctx.Done():
			return nil
		case <-watch:
		case <-ticker.C:
		}
	}
}
```

```
// sync adds local host entries to bpf lxcmap, as well as ipcache, if
// needed, and also notifies the daemon and network policy hosts cache if
// changes were made.
func (s *syncHostIPs) sync(addrs statedb.Iterator[tables.NodeAddress]) error {
	type ipIDLabel struct {
		identity.IPIdentityPair
		labels.Labels
	}
	specialIdentities := make([]ipIDLabel, 0, 2)

	addIdentity := func(ip net.IP, mask net.IPMask, id identity.NumericIdentity, labels labels.Labels) {
		specialIdentities = append(specialIdentities, ipIDLabel{
			identity.IPIdentityPair{
				IP:   ip,
				Mask: mask,
				ID:   id,
			},
			labels,
		})
	}

	for addr, _, ok := addrs.Next(); ok; addr, _, ok = addrs.Next() {
		if addr.DeviceName == tables.WildcardDeviceName {
			continue
		}
		ip := addr.Addr.AsSlice()
		if (!option.Config.EnableIPv4 && addr.Addr.Is4()) || (!option.Config.EnableIPv6 && addr.Addr.Is6()) {
			continue
		}
		if option.Config.IsExcludedLocalAddress(ip) {
			continue
		}
		addIdentity(ip, nil, identity.ReservedIdentityHost, labels.LabelHost)
	}

	if option.Config.EnableIPv6 {
		ipv6Ident := identity.ReservedIdentityWorldIPv6
		ipv6Label := labels.LabelWorldIPv6
		if !option.Config.EnableIPv4 {
			ipv6Ident = identity.ReservedIdentityWorld
			ipv6Label = labels.LabelWorld
		}
		addIdentity(net.IPv6zero, net.CIDRMask(0, net.IPv6len*8), ipv6Ident, ipv6Label)
	}

	if option.Config.EnableIPv4 {
		ipv4Ident := identity.ReservedIdentityWorldIPv4
		ipv4Label := labels.LabelWorldIPv4
		if !option.Config.EnableIPv6 {
			ipv4Ident = identity.ReservedIdentityWorld
			ipv4Label = labels.LabelWorld
		}
		addIdentity(net.IPv4zero, net.CIDRMask(0, net.IPv4len*8), ipv4Ident, ipv4Label)
	}

	existingEndpoints, err := lxcmap.DumpToMap()
	if err != nil {
		return fmt.Errorf("dump lxcmap: %w", err)
	}

	daemonResourceID := ipcachetypes.NewResourceID(ipcachetypes.ResourceKindDaemon, "", "reserved")
	for _, ipIDLblsPair := range specialIdentities {
		isHost := ipIDLblsPair.ID == identity.ReservedIdentityHost
		if isHost {
			added, err := lxcmap.SyncHostEntry(ipIDLblsPair.IP)
			if err != nil {
				return fmt.Errorf("Unable to add host entry to endpoint map: %w", err)
			}
			if added {
				log.WithField(logfields.IPAddr, ipIDLblsPair.IP).Debugf("Added local ip to endpoint map")
			}
		}

		delete(existingEndpoints, ipIDLblsPair.IP.String())

		lbls := ipIDLblsPair.Labels
		if ipIDLblsPair.ID.IsWorld() {
			p := netip.PrefixFrom(ippkg.MustAddrFromIP(ipIDLblsPair.IP), 0)
			s.params.IPCache.OverrideIdentity(p, lbls, source.Local, daemonResourceID)
		} else {
			s.params.IPCache.UpsertLabels(ippkg.IPToNetPrefix(ipIDLblsPair.IP),
				lbls,
				source.Local, daemonResourceID,
			)
		}
	}

	// existingEndpoints is a map from endpoint IP to endpoint info. Referring
	// to the key as host IP here because we only care about the host endpoint.
	for hostIP, info := range existingEndpoints {
		if ip := net.ParseIP(hostIP); info.IsHost() && ip != nil {
			if err := lxcmap.DeleteEntry(ip); err != nil {
				return fmt.Errorf("unable to delete obsolete host IP: %w", err)
			} else {
				log.Debugf("Removed outdated host IP %s from endpoint map", hostIP)
			}
			s.params.IPCache.RemoveLabels(ippkg.IPToNetPrefix(ip), labels.LabelHost, daemonResourceID)
		}
	}

	// we have a reference to all ifindex values, so we update the related metric
	maxIfindex := uint32(0)
	for _, endpoint := range existingEndpoints {
		if endpoint.IfIndex > maxIfindex {
			maxIfindex = endpoint.IfIndex
		}
	}
	metrics.EndpointMaxIfindex.Set(float64(maxIfindex))

	return nil
}

```



### InitIPIdentityWatcher

会持续监听 ip -> identity 的映射，这一映射存储在KVstore当中



### initKVStore

初始化KV存储



### initRestore

```
// When we regenerate restored endpoints, it is guaranteed that we have
// received the full list of policies present at the time the daemon
// is bootstrapped.
d.regenerateRestoredEndpoints(restoredEndpoints, endpointsRegenerator)

// Also wait for all shared services to be synchronized with the
// datapath before proceeding.
if d.clustermesh != nil {
	// Do a first pass synchronizing only the services which are not
	// marked as global, so that we can drop their stale backends
	// without needing to wait for full clustermesh synchronization.
	syncServices(true /* only local services */)
}
```



## Other

RegisterCRDs在启动流程中疑似迁移到RegisterCRDsCell

newIPAddressManager即NewIPAM迁移到了Cell









# Agent CIDR Init

Cilium Agent承担着IPAM功能，即节点内IP地址的分配。可以通过下面的方法指定Cilium应当使用的CIDR

- 通过 Kubernetes 控制器管理器：使用 `--allocate-node-cidrs <CIDR>` 指定一个较大的 CIDR，每个 Cilium 代理在启动时会从中请求一个小的 CIDR。
- 通过 Kubernetes 注解：在特定节点上添加 `io.cilium.network.ipv4-pod-cidr=<CIDR>`。
- 其他方式，例如 Cilium CLI

Cilium 代理 CIDR 初始化的总体步骤如下：

1. 启动 Cilium 代理（守护进程），开始初始化。
2. 初始化 Cilium 的 `pkt/k8s` 子模块。
3. 从 Kubernetes 控制器管理器和节点注解中获取 CIDR 信息。
4. 根据特定优先级选择该节点应使用的 CIDR。
5. 将 CIDR 信息写回到 Kubernetes 注解中

## 调用栈

```
runDaemon                                                // daemon/daemon_main.go
  |-k8s.Init                                             // pkg/k8s/init.go
  |-NewDaemon                                            // daemon/daemon.go
    |  |-node := waitForNodeInformation
    |  |         |-retrieveNodeInformation
    |  |           |-GetNode                             // pkg/k8s/node.go
    |  |           | |-c.CoreV1().Nodes().Get(nodeName)
    |  |           |-ParseNode                           // pkg/k8s/node.go
    |  |             |- cidr.ParseCIDR
    |  |-if node != nil
    |  |   useNodeCIDR                                   // pkg/k8s/init.go
    |  |     |-node.SetIPv4AllocRange(n.IPv4AllocCIDR)
    |  |         |-ipv4AllocRange = cidr                 // pkg/node/address.go
    |  |-else
    |  |    if option.Config.K8sRequireIPv4PodCIDR
    |  |        log.Fatal()
    |  |
    |-bootstrapIPAM                                      // daemon/cmd/ipam.go
    |  |-if option.Config.IPv4Range != AutoCIDR
    |  |   allocCIDR := cidr.ParseCIDR(option.Config.IPv4Range)
    |  |   if !allocCIDR:
    |  |      log.Fatal()
    |  |
    |  |   node.SetIPv4AllocRange(allocCIDR)
    |  |         |-ipv4AllocRange = cidr                 // pkg/node/address.go
    |  |-AutoComplete                                    // pkg/node/address.go
    |  |  |-InitDefaultPrefix(option.Config.DirectRoutingDevice)
    |  |     if ipv4AllocRange == nil
    |  |       ipv4AllocRange = cidr.NewCIDR(ip4net) // Using autogenerated IPv4 allocation range
    |  |-d.ipam = ipam.NewIPAM
    |
    |-k8s.Client().AnnotateNode(cidr ...)       // daemon/daemon.go
    | |-updateNodeAnnotation                    // pkg/k8s/annotate.go
    |   |-c.CoreV1().Nodes().Update(node)
```

正如上述代码所示，`NewDaemon` 会初始化 Kubernetes 模块（`pkg/k8s/`），并调用一些模块函数：

- `k8s.Configure` 用于配置 Kubernetes 集群信息，例如 API 服务器地址。
- `k8s.Init` 会连接到 Kubernetes 集群并获取节点信息，其中包括 CIDR 信息；然后它会决定该节点将使用的 CIDR。
- `k8s.Client` 会将节点信息（包括 CIDR 信息）更新回 Kubernetes Anno中。

### waitForNodeInformation

This function will try to get node info via K8S API, will auto-try until it succeeds (`pkg/k8s/init.go`). Call flow:

```
waitForNodeInformation -> retrieveNodeInformation -> GetNode()
```

`GetNode` will call K8S API to retrieve node info, including the CIDR (`pkg/k8s/node.go`):

```
GetNode -> c.CoreV1().Nodes().Get(nodeName, metav1.GetOptions{})
```

### `ParseNode`

```
// ParseNode parses a kubernetes node to a cilium node
func ParseNode(k8sNode *slim_corev1.Node, source source.Source) *nodeTypes.Node {
if len(k8sNode.Spec.PodCIDRs) != 0 {
		if len(k8sNode.Spec.PodCIDRs) > 2 {
			scopedLog.WithField("podCIDR", k8sNode.Spec.PodCIDRs).Errorf("Invalid PodCIDRs expected 1 or 2 PodCIDRs, received %d", len(k8sNode.Spec.PodCIDRs))
		} else {
			for _, podCIDR := range k8sNode.Spec.PodCIDRs {
				if allocCIDR, err := cidr.ParseCIDR(podCIDR); err != nil {
					scopedLog.WithError(err).WithField("podCIDR", k8sNode.Spec.PodCIDR).Warn("Invalid PodCIDR value for node")
				} else {
					if allocCIDR.IP.To4() != nil {
						newNode.IPv4AllocCIDR = allocCIDR
					} else {
						newNode.IPv6AllocCIDR = allocCIDR
					}
				}
			}
		}
	} else if len(k8sNode.Spec.PodCIDR) != 0 {
		if allocCIDR, err := cidr.ParseCIDR(k8sNode.Spec.PodCIDR); err != nil {
			scopedLog.WithError(err).WithField(logfields.V4Prefix, k8sNode.Spec.PodCIDR).Warn("Invalid PodCIDR value for node")
		} else {
			if allocCIDR.IP.To4() != nil {
				newNode.IPv4AllocCIDR = allocCIDR
			} else {
				newNode.IPv6AllocCIDR = allocCIDR
			}
		}
	}
	
		// Spec.PodCIDR takes precedence since it's
	// the CIDR assigned by k8s controller manager
	// In case it's invalid or empty then we fall back to our annotations.
	if newNode.IPv4AllocCIDR == nil {
		if ipv4CIDR, ok := annotation.Get(k8sNode, annotation.V4CIDRName, annotation.V4CIDRNameAlias); !ok || ipv4CIDR == "" {
			scopedLog.Debug("Empty IPv4 CIDR annotation in node")
		} else {
			allocCIDR, err := cidr.ParseCIDR(ipv4CIDR)
			if err != nil {
				scopedLog.WithError(err).WithField(logfields.V4Prefix, ipv4CIDR).Error("BUG, invalid IPv4 annotation CIDR in node")
			} else {
				newNode.IPv4AllocCIDR = allocCIDR
			}
		}
	}
}
```

注意这里的 CIDR 优先级：

- 如果找到 `SpecPodCIDR`，则使用它；此信息由 Kubernetes 控制器管理器提供。
- 如果未找到 `SpecPodCIDR`，则尝试从节点注解中检索 CIDR。
- 换句话说：通过控制器管理器配置的 CIDR 优先级高于通过节点注解配置的 CIDR。

### AnnotateNode

Write node info back to node annotations, among which including the CIDR info.

## Specify Node CIDR via K8S Node Annotations

步骤：

1. 在 Kubernetes 主控节点上：从控制器管理器中移除 `--allocate-node-cidrs` 配置。
2. 在 Kubernetes 主控节点上：为节点添加注解：`kubectl annotate node <NODE_NAME> --overwrite io.cilium.network.ipv4-pod-cidr=<CIDR>`。
3. 在 Kubernetes 节点上：重启 Cilium 代理：`docker restart <Container ID>`。

检查是否按预期工作：

- 在 Kubernetes 主控节点上：`kubectl describe node <NODE_NAME> | grep cilium`，`io.cilium.network.ipv4-pod-cidr` 应该是指定的 CIDR。
- 在 Kubernetes 节点上：`ifconfig cilium_host`，IP 地址（CIDR 网关）应该从指定的 CIDR 中分配。





# Restore Endpoints and Identities


主要步骤：

1. 从文件中恢复端点信息：`restoreOldEndpoints()`。
2. 为端点重新生成 BPF：`regenerateRestoredEndpoints()`。
   1. 为端点分配身份（基于身份的策略，而不是基于端点）。
   2. 为端点重新生成 BPF。



在Cilium Agent 启动时，通过下面的命令恢复endpoints

```
restoredEndpoints := d.restoreOldEndpoints(option.Config.StateDir, true)
```



## restoreOldEndpoints()

默认情况下，传递给 `restoreOldEndpoints()` 方法的 `option.Config.StateDir` 的值是 `/var/run/cilium/`。

该方法是恢复端点结构的第一步，它会从 CIDR 块中分配现有 IP，然后将端点插入到端点列表中。

```
// daemon/cmd/state.go

func (d *Daemon) restoreOldEndpoints(dir string, clean bool) (*endpointRestoreState) {
    state := &endpointRestoreState{
        restored: []*endpoint.Endpoint{},
        toClean:  []*endpoint.Endpoint{},
    }

    existingEndpoints = lxcmap.DumpToMap()             // get previous endpoint IDs from BPF map
    dirFiles := ioutil.ReadDir(dir)                    // state dir: `/var/run/cilium/`
    eptsID := endpoint.FilterEPDir(dirFiles)           // `/var/run/cilium/<ep_id>/lxc_config.h`

    possibleEPs := ReadEPsFromDirNames(dir, eptsID)    // parse endpoint ID from dir name
    for ep := range possibleEPs {
        ep.SetAllocator(d.identityAllocator)
        d.validateEndpoint(ep)  // further call allocateIPsLocked() to retain IP for this endpoint
        ep.SetDefaultConfiguration(true)

        state.restored.append(ep)                      // insert into restored list, will regen bpf for them
        delete(existingEndpoints, ep.IPv4.String())
    }

    for hostIP, info := range existingEndpoints        // for the remaining endpoints, delete them
        if ip := net.ParseIP(hostIP) && !info.IsHost() // from endpoint map
            lxcmap.DeleteEntry(ip)

    return state
}
```

## Reserve IP addresses for existing endpoints

在代理重启时，IPAM（IP 地址管理）状态会被重置，这使得所有在 IPAM 中的 IP 地址都可用于分配——包括那些已经被此主机上运行的容器使用的 IP 地址。

在上一步中，代理通过解析文件 `/var/run/cilium/<ep_id>/lxc_config.h`，恢复了端点当前使用的 IP 地址（IPv4 和/或 IPv6）。

现在，它必须保留或重新分配这些 IP 地址，以防止它们再次被分配出去。这通过调用 `validateEndpoint(ep) -> allocateIPsLocked()` 来完成。

## Regenerate BPF for restored endpoints

在代理重启期间，Kubernetes 集群中的资源可能已经发生了变化，例如 Service 到后端的映射关系。此外，代理的配置也可能发生了更改。

因此，为了保持端点状态的最新性，我们需要为这些端点重新生成 BPF 代码和映射。

```
func (d *Daemon) regenerateRestoredEndpoints(state) (restoreComplete chan struct{}) {
    epRegenerated := make(chan bool, len(state.restored))

    for i := len(state.restored)-1; i >= 0; i-- {
        ep := state.restored[i]
        ep.Expose(d.endpointManager)      // Insert ep into endpoint manager so it can be regenerated
    }                                     // later with RegenerateAllEndpoints().

    for ep := range state.restored        // loop over restored endpoints
        go func() {
            ep.RegenerateAfterRestore()   // perform BPF regeneration
            epRegenerated <- true
        }(ep, epRegenerated)

    for ep := range state.toClean         // clean the endpoints that no need to restore
        d.deleteEndpointQuiet(ep)

    go func() {
        for buildSuccess := range epRegenerated
            if total++ >= len(state.restored) break
        log.Info("Finished regenerating restored endpoints")
    }()
}
```

主要步骤：

1. 通过 `Expose()` 将所有待恢复的端点插入到端点管理器中；这将为每个端点创建一个事件队列，该队列将监听 BPF 重新生成事件。
2. 恢复端点的身份信息。
3. 将一个 `EndpointRegenerationEvent`（端点再生事件）入队到步骤1中创建的端点事件队列中。
4. 在接收到 `EndpointRegenerationEvent` 时，处理程序将执行 BPF 的重新生成。

让我们详细了解一下这些步骤。

### 1 Create per-endpoint event queue

```
func (e *Endpoint) Expose(mgr endpointManager) error {
    newID := mgr.AllocateID(e.ID)
    e.ID = newID

    e.eventQueue = eventqueue.NewEventQueueBuffered("endpoint-"+e.ID, Config.EndpointQueueSize)
    e.eventQueue.Run()

    e.updateReferences(mgr)
    e.getLogger().Info("New endpoint")

    mgr.RunK8sCiliumEndpointSync(e, option.Config)
}
```

```
func (q *EventQueue) Run() {
    go q.eventQueueOnce.Do(func() {
        for ev := range q.events {
            select {
            default:
                ev.Metadata.Handle(ev.eventResults)
            }
        }
    })
}
```

### 2 Restore identities for endpoints

```
// pkg/endpoint/restore.go

// RegenerateAfterRestore performs the following operations on the specified Endpoint:
// * allocates an identity for the Endpoint
// * regenerates the endpoint
func (e *Endpoint) RegenerateAfterRestore() error {
    e.restoreIdentity()

    regenerationMetadata := &regeneration.ExternalRegenerationMetadata{
        Reason:            "syncing state to host",
        RegenerationLevel: regeneration.RegenerateWithDatapathRewrite,
    }

    buildSuccess := <-e.Regenerate(regenerationMetadata)
    log.Info("Restored endpoint")
}
```

### 3 Enqueue `EndpointRegenerationEvent` event into endpoint’s queue

```
// pkg/endpoint/policy.go

// Regenerate forces the regeneration of endpoint programs & policy
// Should only be called with e.state at StateWaitingToRegenerate, StateWaitingForIdentity, or StateRestoring
func (e *Endpoint) Regenerate(regenMetadata *regeneration.ExternalRegenerationMetadata) <-chan bool {
    done := make(chan bool, 1)

    regenContext := ParseExternalRegenerationMetadata(ctx, cFunc, regenMetadata)
    epEvent := eventqueue.NewEvent(&EndpointRegenerationEvent{regenContext: regenContext, ep: e})
    resChan := e.eventQueue.Enqueue(epEvent)

    return done
}
```

#### 4 Event handler: perform BPF regeneration

```
// Handle handles the regeneration event for the endpoint.
func (ev *EndpointRegenerationEvent) Handle(res chan interface{}) {
    e := ev.ep
    doneFunc := e.owner.QueueEndpointBuild(e.ID)
    if doneFunc != nil { // dequeued endpoint from build queue
        ev.ep.regenerate(ev.regenContext)
        doneFunc()
        e.notifyEndpointRegeneration(err)
    }

    res <- &EndpointRegenerationResult{ err: err, }
}
```

```
func (e *Endpoint) regenerate(context *regenerationContext) (retErr error) {
    origDir := e.StateDirectoryPath()
    tmpDir := e.NextDirectoryPath()
    e.removeDirectory(tmpDir)
    os.MkdirAll(tmpDir, 0777)

    defer func() { e.removeDirectory(tmpDir) }()

    revision, stateDirComplete = e.regenerateBPF(context)
    return e.updateRealizedState(stats, origDir, revision, stateDirComplete)
}
```

它创建了一个临时目录用于生成新的 BPF 文件，然后调用了 `regenerateBPF()`。后者会进一步调用更多深层次的方法来完成 BPF 的重新生成。由于这个调用栈相当深，我们在下面专门列出一个部分来展示。

## 5 From `regenerateBPF()` to the eventual `clang/tc` commands

```
// regenerateBPF rewrites all headers and updates all BPF maps to reflect the specified endpoint.
// ReloadDatapath forces the datapath progs to be reloaded. It does not guarantee recompilation of the programs.
//
// Returns the policy revision number when the regeneration has called,
// Whether the new state dir is populated with all new BPF state files.
func (e *Endpoint) regenerateBPF(regenContext) (revnum uint64, stateDirComplete bool) {
    headerfileChanged = e.runPreCompilationSteps()   // execute clang commands to compile BPF

    <-datapathRegenCtxt.ctCleaned                    // Wait for conntrack cleaning to complete
    compilationExecuted = e.realizeBPFState()        // execute tc commands to reload BPF

    if !datapathRegenCtxt.epInfoCache.IsHost() {
        // Hook the endpoint into the endpoint and endpoint to policy tables then expose it
        epErr := eppolicymap.WriteEndpoint(epInfoCache, e.policyMap)
        lxcmap.WriteEndpoint(epInfoCache)
    }

    e.closeBPFProgramChannel() // Signal that BPF program has been generated.
                               // The endpoint has at least L3/L4 connectivity at this point.
    e.syncPolicyMap()          // Synchronously try to update PolicyMap for this endpoint.
    stateDirComplete = headerfileChanged && compilationExecuted
    return datapathRegenCtxt.epInfoCache.revision, stateDirComplete, err
}
```

```
func (e *Endpoint) realizeBPFState() (compilationExecuted bool, err error) {
    if regenLevel == RegenerateWithDatapathRebuild {        // compile AND load
        e.owner.Datapath().Loader().CompileAndLoad()
        compilationExecuted = true
    } else if regenLevel == RegenerateWithDatapathRewrite { // compile OR load
        e.owner.Datapath().Loader().CompileOrLoad()
        compilationExecuted = true
    } else { // RegenerateWithDatapathLoad                  // reload
        e.owner.Datapath().Loader().ReloadDatapath()
    }

    e.bpfHeaderfileHash = datapathRegenCtxt.bpfHeaderfilesHash
    return compilationExecuted, nil
}
```

```
func (l *Loader) CompileOrLoad(ctx context.Context, ep datapath.Endpoint, stats *metrics.SpanStat) error {
    templatePath := l.templateCache.fetchOrCompile(ctx, ep, stats)
    template := elf.Open(templatePath)

    symPath := path.Join(ep.StateDir(), defaults.TemplatePath)
    os.RemoveAll(symPath)
    os.Symlink(templatePath, symPath)

    epObj := endpointObj
    if ep.IsHost()
        epObj = hostEndpointObj

    dstPath := path.Join(ep.StateDir(), epObj)
    opts, strings := ELFSubstitutions(ep)
    template.Write(dstPath, opts, strings)

    return l.ReloadDatapath(ctx, ep, stats)
}

// ReloadDatapath reloads the BPF datapath pgorams for the specified endpoint.
func (l *Loader) ReloadDatapath(ctx context.Context, ep datapath.Endpoint, stats *metrics.SpanStat) (err error) {
    dirs := directoryInfo{
        Library: option.Config.BpfDir,
        Runtime: option.Config.StateDir,
        State:   ep.StateDir(),
        Output:  ep.StateDir(),
    }
    return l.reloadDatapath(ctx, ep, &dirs)
}
```

#### 5.1 Pre-compile BPF

`runPreCompilationSteps()`.

#### 5.2 Compile BPF

`realizeBPFState() -> CompileAndLoad() -> compileAndLoad() -> compileDatapath()`.

```
// CompileAndLoad compiles the BPF datapath programs for the specified endpoint
// and loads it onto the interface associated with the endpoint.
//
// Expects the caller to have created the directory at the path ep.StateDir().
func (l *Loader) CompileAndLoad(ctx context.Context, ep datapath.Endpoint, stats *metrics.SpanStat) error {
    dirs := directoryInfo{
        Library: option.Config.BpfDir,
        Runtime: option.Config.StateDir,
        State:   ep.StateDir(),
        Output:  ep.StateDir(),
    }
    return l.compileAndLoad(ctx, ep, &dirs, stats)
}

func (l *Loader) compileAndLoad(ctx context.Context, ep datapath.Endpoint, dirs *directoryInfo, stats *metrics.SpanStat) error {
    compileDatapath(ctx, dirs, ep.IsHost(), debug, ep.Logger(Subsystem))
    return l.reloadDatapath(ctx, ep, dirs)
}
```

#### 5.3 Reload BPF

All the above three cases will eventually call `reloadDatapath()` to fulfill the BPF reloading for the endpoint.

```
func (l *Loader) reloadDatapath(ctx context.Context, ep datapath.Endpoint, dirs *directoryInfo) error {
    objPath := path.Join(dirs.Output, endpointObj)

    if ep.IsHost() {
        objPath = path.Join(dirs.Output, hostEndpointObj)
        l.reloadHostDatapath(ctx, ep, objPath)
    } else if ep.HasIpvlanDataPath() {
        ...
    } else {
        l.replaceDatapath(ctx, ep.InterfaceName(), objPath, symbolFromEndpoint, dirIngress)

        if ep.RequireEgressProg()
            l.replaceDatapath(ctx, ep.InterfaceName(), objPath, symbolToEndpoint, dirEgress)
    }

    if ep.RequireEndpointRoute() {
        if ip := ep.IPv4Address(); ip.IsSet()
            upsertEndpointRoute(ep, *ip.IPNet(32))
    }
}
```

```
// replaceDatapath the qdisc and BPF program for a endpoint
func (l *Loader) replaceDatapath(ctx context.Context, ifName, objPath, progSec, progDirection string) error {
    replaceQdisc(ifName)

    cmd := exec.CommandContext(ctx, "cilium-map-migrate", "-s", objPath)
    cmd.CombinedOutput(log, true)

    defer func() {
        if err == nil
            retCode = "0"
        else
            retCode = "1"
        args := []string{"-e", objPath, "-r", retCode}
        cmd := exec.CommandContext(ctx, "cilium-map-migrate", args...)
        cmd.CombinedOutput(log, true) // ignore errors
    }()

    args := []string{"filter", "replace", "dev", ifName, progDirection,
        "prio", "1", "handle", "1", "bpf", "da", "obj", objPath, "sec", progSec, }
    cmd = exec.CommandContext(ctx, "tc", args...).WithFilters(libbpfFixupMsg)
    cmd.CombinedOutput(log, true)
}
```
