---
title: (转+译)Cilium Code Walk Through 1.1 - Agent Start
date: 2025-02-27
update: 2025-02-28
comment: false
tags:
  - Cilium
categories:
  - Cilium
---

这里介绍了Cilium Agent的启动过程，主要是对Cilium的整体架构和代码结构有一个初步的了解。

*<!--more-->*

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





