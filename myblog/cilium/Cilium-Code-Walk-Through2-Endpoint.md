---
title: (转+译)Cilium Code Walk Through 2 - Restore Endpoints and Identities?
date: 2025-02-27
update: 2025-02-28
comment: false
tags:
  - Cilium
categories:
  - Cilium
---

这一节讲一下Endpoint和Identities在Cilium中的处理机制

*<!--more-->*
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
