---
title: (转+译)Cilium Code Walk Through 4.1 - CNI Delete
date: 2025-02-27
update: 2025-02-28
comment: false
tags:
  - Cilium
categories:
  - Cilium
---

这一部分讲一下Cilium是如何通过CNI来管理网络的

*<!--more-->*
下面继续解析CNI Delete的实现部分

## 1 CNI: Delete Network

```
// Del is invoked on CNI DEL
//
// Note: ENI specific attributes do not need to be released as the ENIs and ENI
// IPs can be reused and are not released until the node terminates.
func (cmd *Cmd) Del(args *skel.CmdArgs) error {
		n, err := types.LoadNetConf(args.StdinData)

		c, err := lib.NewDeletionFallbackClient(logger)
		
		// If this is a chained plugin, then "delegate" to the special chaining mode and be done.
    // Note: DEL always has PrevResult set, so that doesn't tell us if we're chained. Given
    // that a CNI ADD could not have succeeded with an invalid chained mode, we should always
    // find a valid chained mode
    if chainAction, err := getChainedAction(n, logger)
    		return chainAction.Delete(context.TODO(), ctx, c)
		
		c.EndpointDeleteMany(req)
		
		if err = ns.Do(func() error {
      return link.DeleteByName(args.IfName)
    });
}
```

## 2 EndpointDelete

### 2.1 Client: EndpointDelete

```

// EndpointDeleteMany deletes multiple endpoints based on the endpoint deletion request,
// either by directly accessing the API or dropping in a queued-deletion file.
func (dc *DeletionFallbackClient) EndpointDeleteMany(req *models.EndpointBatchDeleteRequest) error {
		if dc.cli != nil {
      return dc.cli.EndpointDeleteMany(req)
    }
}

// EndpointDeleteMany deletes multiple endpoints
func (c *Client) EndpointDeleteMany(req *models.EndpointBatchDeleteRequest) error {
	params := endpoint.NewDeleteEndpointParams().WithEndpoint(req).WithTimeout(api.ClientTimeout)
	_, _, err := c.Endpoint.DeleteEndpoint(params)
	return Hint(err)
}



```

### 2.2 Server REST API: Handle Delete Endpoint

```
out.EndpointDeleteEndpointIDHandler = wrapAPIHandler(dp, deleteEndpointIDHandler)
```

## 2.3 Daemon: HTTP Handler

```
func deleteEndpointIDHandler(d *Daemon, params DeleteEndpointIDParams) middleware.Responder {
		nerr, err := d.DeleteEndpoint(params.ID);
}

func (d *Daemon) DeleteEndpoint(id string) (int, error) {
		return d.deleteEndpoint(ep), nil
}

func (d *Daemon) deleteEndpoint(ep *endpoint.Endpoint) int {
	// If the IP is managed by an external IPAM, it does not need to be released
	return d.deleteEndpointRelease(ep, ep.DatapathConfiguration.ExternalIpam)
}

func (d *Daemon) deleteEndpointRelease(ep *endpoint.Endpoint, noIPRelease bool) int {
		errs := d.deleteEndpointQuiet(ep, endpoint.DeleteConfig{
      NoIPRelease: noIPRelease,
    })
}

// deleteEndpointQuiet sets the endpoint into disconnecting state and removes
// it from Cilium, releasing all resources associated with it such as its
// visibility in the endpointmanager, its BPF programs and maps, (optional) IP,
// L7 policy configuration, directories and controllers.
//
// Specific users such as the cilium-health EP may choose not to release the IP
// when deleting the endpoint. Most users should pass true for releaseIP.
func (d *Daemon) deleteEndpointQuiet(ep *endpoint.Endpoint, conf endpoint.DeleteConfig) []error {
	return d.endpointManager.RemoveEndpoint(ep, conf)
}

// RemoveEndpoint stops the active handling of events by the specified endpoint,
// and prevents the endpoint from being globally acccessible via other packages.
func (mgr *endpointManager) RemoveEndpoint(ep *endpoint.Endpoint, conf endpoint.DeleteConfig) []error {
	return mgr.deleteEndpoint(ep, conf)
}


mgr.deleteEndpoint = mgr.removeEndpoint
```

```
// removeEndpoint stops the active handling of events by the specified endpoint,
// and prevents the endpoint from being globally acccessible via other packages.
func (mgr *endpointManager) removeEndpoint(ep *endpoint.Endpoint, conf endpoint.DeleteConfig) []error {
    mgr.unexpose(ep)
    result := ep.Delete(conf)

    mgr.mutex.RLock()
    for s := range mgr.subscribers {
       s.EndpointDeleted(ep, conf)
    }
    mgr.mutex.RUnlock()

    return result
}

// EndpointDeleted is a callback to satisfy EndpointManager.Subscriber,
// which works around the difficulties in initializing various subsystems
// involved in managing endpoints, such as the EndpointManager, IPAM and
// the Monitor.
//
// It is called after Daemon calls into d.endpointManager.RemoveEndpoint().
func (d *Daemon) EndpointDeleted(ep *endpoint.Endpoint, conf endpoint.DeleteConfig) {
	d.SendNotification(monitorAPI.EndpointDeleteMessage(ep))

	if !conf.NoIPRelease {
		if option.Config.EnableIPv4 {
			if err := d.ipam.ReleaseIP(ep.IPv4.AsSlice(), ipam.PoolOrDefault(ep.IPv4IPAMPool)); err != nil {
				scopedLog := ep.Logger(daemonSubsys).WithError(err)
				scopedLog.Warning("Unable to release IPv4 address during endpoint deletion")
			}
		}
		if option.Config.EnableIPv6 {
			if err := d.ipam.ReleaseIP(ep.IPv6.AsSlice(), ipam.PoolOrDefault(ep.IPv6IPAMPool)); err != nil {
				scopedLog := ep.Logger(daemonSubsys).WithError(err)
				scopedLog.Warning("Unable to release IPv6 address during endpoint deletion")
			}
		}
	}
}
```

## 2.4 IPAM: Delete IP

```
// ReleaseIP release a IP address. The pool argument must not be empty, it
// must be set to the pool name returned by the `Allocate*` functions when
// the IP was allocated.
func (ipam *IPAM) ReleaseIP(ip net.IP, pool Pool) error {
    ipam.allocatorMutex.Lock()
    defer ipam.allocatorMutex.Unlock()
    return ipam.releaseIPLocked(ip, pool)
}
```

## 2.5 K8S IPAM: Delete IP

```
func (ipam *IPAM) releaseIPLocked(ip net.IP, pool Pool) error {
		ipam.IPv4Allocator.Release(ip, pool)
}
```

```
func (c *multiPoolAllocator) Release(ip net.IP, pool Pool) error {
    return c.manager.releaseIP(ip, pool, c.family, true)
}
```

```
func (m *multiPoolManager) releaseIP(ip net.IP, poolName Pool, family Family, upstreamSync bool) error {
    m.mutex.Lock()
    defer m.mutex.Unlock()

    pool := m.poolByFamilyLocked(poolName, family)
    if pool == nil {
       return fmt.Errorf("unable to release IP %s of unknown pool %q (family %s)", ip, poolName, family)
    }

    pool.release(ip)
    if upstreamSync {
       m.k8sUpdater.TriggerWithReason("release of IP")
    }
    return nil
}
```

```
func (p *podCIDRPool) release(ip net.IP) {
    p.mutex.Lock()
    defer p.mutex.Unlock()

    for _, ipAllocator := range p.ipAllocators {
       cidrNet := ipAllocator.CIDR()
       if cidrNet.Contains(ip) {
          ipAllocator.Release(ip)
          return
       }
    }
}
```

## 2.6 Cleanup Redirects

```
// UpdatePolicyMaps returns a WaitGroup which is signaled upon once all endpoints
// have had their PolicyMaps updated against the Endpoint's desired policy state.
//
// Endpoints will wait on the 'notifyWg' parameter before updating policy maps.
func (mgr *endpointManager) UpdatePolicyMaps(ctx context.Context, notifyWg *sync.WaitGroup) *sync.WaitGroup {
		proxyWaitGroup := completion.NewWaitGroup(ctx)
		
		
		go func() {
				 err := waitForProxyCompletions(proxyWaitGroup);
		}
}
```

```
result := ep.Delete(conf) ->  e.waitForProxyCompletions(proxyWaitGroup)
```

```
// waitForProxyCompletions blocks until all proxy changes have been completed.
// Called with buildMutex held.
func (e *Endpoint) waitForProxyCompletions(proxyWaitGroup *completion.WaitGroup) error {
    if proxyWaitGroup == nil {
       return nil
    }

    err := proxyWaitGroup.Context().Err()
    if err != nil {
       return fmt.Errorf("context cancelled before waiting for proxy updates: %w", err)
    }

    start := time.Now()

    e.getLogger().Debug("Waiting for proxy updates to complete...")
    err = proxyWaitGroup.Wait()
    if err != nil {
       return fmt.Errorf("proxy state changes failed: %w", err)
    }
    e.getLogger().Debug("Wait time for proxy updates: ", time.Since(start))

    return nil
}
```



## Appendix

当删除一个端点时，可能会设置一个布尔标志 `NoIPRelease`，用于指示是否释放该端点的 IP 地址。在大多数情况下，此标志设置为 `false`，表示删除 IP 地址。但有一些特殊情况下，此标志会被设置为 `true`：

1. 在创建端点时遇到致命错误；
2. 在代理重启时清理重新生成失败的端点；
3. 清理 cilium-health 端点。





## How `cilium-health` endpoint retains it’s IP address unchanged during agent re-install?

1. 将 IP 地址通过 K8S 注解（annotations）存储到节点元数据中；
2. 删除端点时，指定 `NoIPRelease=true` 以保留 IP 地址；
3. 重新启动时，从 K8S 节点注解中检索 IP 地址，然后创建端点。