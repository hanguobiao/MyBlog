---
title: kubelet源码笔记3-syncPod
date: 2025-03-05
update: 2025-03-09
comment: false
tags:
  - Cilium
  - BPF
categories:
  - BPF
---

SyncPod是kubelet中负责同步pod的函数，它会根据pod的状态来执行不同的操作，如创建、删除、更新等，也是最核心的Pod控制流程

*<!--more-->*
# SyncPod源码

这里继续对SyncPod的源码进行分析

为了理解下面的代码，需要先讲一下sandbox的概念。k8s有着一类pause容器，这些容器并不是用户配置的， 而是K8s本身的机制，这些pause容器也被称为infra容器





注释中分为一下几个步骤，下面就按照步骤来分析

```
// SyncPod syncs the running pod into the desired pod by executing following steps:
//
//  1. Compute sandbox and container changes.
//  2. Kill pod sandbox if necessary.
//  3. Kill any containers that should not be running.
//  4. Create sandbox if necessary.
//  5. Create ephemeral containers.
//  6. Create init containers.
//  7. Resize running containers (if InPlacePodVerticalScaling==true)
//  8. Create normal containers.
```



1. 调用computePodActions来计算当前sync流程需要执行的操作，返回一个PodAction类型的变量，包含了需要进行的操作和必要的变量

```go
// podActions keeps information what to do for a pod.
type podActions struct {
	// Stop all running (regular, init and ephemeral) containers and the sandbox for the pod.
	KillPod bool
	// Whether need to create a new sandbox. If needed to kill pod and create
	// a new pod sandbox, all init containers need to be purged (i.e., removed).
	CreateSandbox bool
	// The id of existing sandbox. It is used for starting containers in ContainersToStart.
	SandboxID string
	// The attempt number of creating sandboxes for the pod.
	Attempt uint32

	// The next init container to start.
	NextInitContainerToStart *v1.Container
	// InitContainersToStart keeps a list of indexes for the init containers to
	// start, where the index is the index of the specific init container in the
	// pod spec (pod.Spec.InitContainers).
	// NOTE: This is a field for SidecarContainers feature. Either this or
	// NextInitContainerToStart will be set.
	InitContainersToStart []int
	// ContainersToStart keeps a list of indexes for the containers to start,
	// where the index is the index of the specific container in the pod spec (
	// pod.Spec.Containers).
	ContainersToStart []int
	// ContainersToKill keeps a map of containers that need to be killed, note that
	// the key is the container ID of the container, while
	// the value contains necessary information to kill a container.
	ContainersToKill map[kubecontainer.ContainerID]containerToKillInfo
	// EphemeralContainersToStart is a list of indexes for the ephemeral containers to start,
	// where the index is the index of the specific container in pod.Spec.EphemeralContainers.
	EphemeralContainersToStart []int
	// ContainersToUpdate keeps a list of containers needing resource update.
	// Container resource update is applicable only for CPU and memory.
	ContainersToUpdate map[v1.ResourceName][]containerToUpdateInfo
	// UpdatePodResources is true if container(s) need resource update with restart
	UpdatePodResources bool
}
```

2. 如果KillPod为true则调用killPodWithSyncResult来kill pod，否则kill所有不需要的container



### CRI SyncPod

```
// pkg/kubelet/kuberuntime/kuberuntime_manager.go

// SyncPod syncs the running pod into the desired pod by executing following steps:
//  1. Compute sandbox and container changes.
//  2. Kill pod sandbox if necessary.
//  3. Kill any containers that should not be running.
//  4. Create sandbox if necessary.
//  5. Create ephemeral containers.
//  6. Create init containers.
//  7. Create normal containers.
//
func (m *kubeGenericRuntimeManager) SyncPod(pod *v1.Pod, podStatus *kubecontainer.PodStatus,
    pullSecrets []v1.Secret, backOff *flowcontrol.Backoff) (result kubecontainer.PodSyncResult) {

    // Step 1: Compute sandbox and container changes.
    podContainerChanges := m.computePodActions(pod, podStatus)
    if podContainerChanges.CreateSandbox {
        ref := ref.GetReference(legacyscheme.Scheme, pod)
        if podContainerChanges.SandboxID != "" {
            m.recorder.Eventf("Pod sandbox changed, it will be killed and re-created.")
        } else {
            InfoS("SyncPod received new pod, will create a sandbox for it")
        }
    }

    // Step 2: Kill the pod if the sandbox has changed.
    if podContainerChanges.KillPod {
        if podContainerChanges.CreateSandbox {
            InfoS("Stopping PodSandbox for pod, will start new one")
        } else {
            InfoS("Stopping PodSandbox for pod, because all other containers are dead")
        }

        killResult := m.killPodWithSyncResult(pod, ConvertPodStatusToRunningPod(m.runtimeName, podStatus), nil)
        result.AddPodSyncResult(killResult)

        if podContainerChanges.CreateSandbox {
            m.purgeInitContainers(pod, podStatus)
        }
    } else {
        // Step 3: kill any running containers in this pod which are not to keep.
        for containerID, containerInfo := range podContainerChanges.ContainersToKill {
            killContainerResult := NewSyncResult(kubecontainer.KillContainer, containerInfo.name)
            result.AddSyncResult(killContainerResult)
            m.killContainer(pod, containerID, containerInfo)
        }
    }

    // Keep terminated init containers fairly aggressively controlled
    // This is an optimization because container removals are typically handled by container GC.
    m.pruneInitContainersBeforeStart(pod, podStatus)

    // Step 4: Create a sandbox for the pod if necessary.
    podSandboxID := podContainerChanges.SandboxID
    if podContainerChanges.CreateSandbox {
        createSandboxResult := kubecontainer.NewSyncResult(kubecontainer.CreatePodSandbox, format.Pod(pod))
        result.AddSyncResult(createSandboxResult)
        podSandboxID, msg = m.createPodSandbox(pod, podContainerChanges.Attempt)
        podSandboxStatus := m.runtimeService.PodSandboxStatus(podSandboxID)
    }

    // the start containers routines depend on pod ip(as in primary pod ip)
    // instead of trying to figure out if we have 0 < len(podIPs) everytime, we short circuit it here
    podIP := ""
    if len(podIPs) != 0 {
        podIP = podIPs[0]
    }

    // Get podSandboxConfig for containers to start.
    configPodSandboxResult := kubecontainer.NewSyncResult(ConfigPodSandbox, podSandboxID)
    result.AddSyncResult(configPodSandboxResult)
    podSandboxConfig := m.generatePodSandboxConfig(pod, podContainerChanges.Attempt)

    // Helper containing boilerplate common to starting all types of containers.
    // typeName is a label used to describe this type of container in log messages,
    // currently: "container", "init container" or "ephemeral container"
    start := func(typeName string, spec *startSpec) error {
        startContainerResult := kubecontainer.NewSyncResult(kubecontainer.StartContainer, spec.container.Name)
        result.AddSyncResult(startContainerResult)

        isInBackOff, msg := m.doBackOff(pod, spec.container, podStatus, backOff)
        if isInBackOff {
            startContainerResult.Fail(err, msg)
            return err
        }

        m.startContainer(podSandboxID, podSandboxConfig, spec, pod, podStatus, pullSecrets, podIP, podIPs)
        return nil
    }

    // Step 5: start ephemeral containers
    // These are started "prior" to init containers to allow running ephemeral containers even when there
    // are errors starting an init container. In practice init containers will start first since ephemeral
    // containers cannot be specified on pod creation.
    for _, idx := range podContainerChanges.EphemeralContainersToStart {
        start("ephemeral container", ephemeralContainerStartSpec(&pod.Spec.EphemeralContainers[idx]))
    }

    // Step 6: start the init container.
    if container := podContainerChanges.NextInitContainerToStart; container != nil {
        start("init container", containerStartSpec(container))
    }

    // Step 7: start containers in podContainerChanges.ContainersToStart.
    for _, idx := range podContainerChanges.ContainersToStart {
        start("container", containerStartSpec(&pod.Spec.Containers[idx]))
    }
}
```

### CRI create sandbox

kubelet [发起 `RunPodSandbox`](https://github.com/kubernetes/kubernetes/blob/v1.21.0/pkg/kubelet/kuberuntime/kuberuntime_sandbox.go#L51) RPC 调用。

**“sandbox” 是一个 CRI 术语，它表示一组容器，在 K8s 里就是一个 Pod**。 这个词是有意用作比较宽泛的描述，这样对其他运行时的描述也是适用的（例如，在基于 hypervisor 的运行时中，sandbox 可能是一个虚拟机）。

```
// pkg/kubelet/kuberuntime/kuberuntime_sandbox.go

// createPodSandbox creates a pod sandbox and returns (podSandBoxID, message, error).
func (m *kubeGenericRuntimeManager) createPodSandbox(pod *v1.Pod, attempt uint32) (string, string, error) {
    podSandboxConfig := m.generatePodSandboxConfig(pod, attempt)

    // 创建 pod log 目录
    m.osInterface.MkdirAll(podSandboxConfig.LogDirectory, 0755)

    runtimeHandler := ""
    if m.runtimeClassManager != nil {
        runtimeHandler = m.runtimeClassManager.LookupRuntimeHandler(pod.Spec.RuntimeClassName)
        if runtimeHandler != "" {
            InfoS("Running pod with runtime handler", runtimeHandler)
        }
    }

    podSandBoxID := m.runtimeService.RunPodSandbox(podSandboxConfig, runtimeHandler)
    return podSandBoxID, "", nil
}
// pkg/kubelet/cri/remote/remote_runtime.go

// RunPodSandbox creates and starts a pod-level sandbox.
func (r *remoteRuntimeService) RunPodSandbox(config *PodSandboxConfig, runtimeHandler string) (string, error) {

    InfoS("[RemoteRuntimeService] RunPodSandbox", "config", config, "runtimeHandler", runtimeHandler)

    resp := r.runtimeClient.RunPodSandbox(ctx, &runtimeapi.RunPodSandboxRequest{
        Config:         config,
        RuntimeHandler: runtimeHandler,
    })

    InfoS("[RemoteRuntimeService] RunPodSandbox Response", "podSandboxID", resp.PodSandboxId)
    return resp.PodSandboxId, nil
}
```

一点调用栈：

```
podSandboxConfig := m.generatePodSandboxConfig(pod, podContainerChanges.Attempt)
  |-generatePodSandboxLinuxConfig(pod)
     |-lc := &runtimeapi.LinuxPodSandboxConfig{}
     |-lc.Sysctls = sysctls # 用户通过 securityContext 指定的 sysctl 参数，例如 net.core.somaxconn
```

### Create sandbox：docker 相关代码

前面是 CRI 通用代码，如果我们的容器 runtime 是 docker，那接下来就会调用到 docker/containerd 相关代码。 具体流程可参考 [1]。

在这种 runtime 中，**创建一个 sandbox 会转换成创建一个 “pause” 容器的操作**。 Pause container 作为一个 pod 内其他所有容器的父角色，hold 了很多 pod-level 的资源， 具体说就是 Linux namespace，例如 IPC NS、Net NS、IPD NS。

“pause” container 提供了一种持有这些 ns、让所有子容器共享它们 的方式。 例如，共享 netns 的好处之一是，pod 内不同容器之间可以通过 localhost 方式访问彼此。 pause 容器的第二个用处是**回收（reaping）dead processes**。 更多信息，可参考 [这篇博客](https://www.ianlewis.org/en/almighty-pause-container)。

Pause 容器创建之后，会被 checkpoint 到磁盘，然后启动。

```
// pkg/kubelet/dockershim/docker_sandbox.go

// 对于 docker runtime，PodSandbox 实现为一个 holding 网络命名空间（netns）的容器
func (ds *dockerService) RunPodSandbox(ctx context.Context, r *RunPodSandboxRequest) (*RunPodSandboxResponse) {

    // Step 1: Pull the image for the sandbox.
    ensureSandboxImageExists(ds.client, image)

    // Step 2: Create the sandbox container.
    createConfig := ds.makeSandboxDockerConfig(config, image)
    createResp := ds.client.CreateContainer(*createConfig)
    resp := &runtimeapi.RunPodSandboxResponse{PodSandboxId: createResp.ID}

    ds.setNetworkReady(createResp.ID, false) // 容器 network 状态初始化为 false

    // Step 3: Create Sandbox Checkpoint.
    CreateCheckpoint(createResp.ID, constructPodSandboxCheckpoint(config))

    // Step 4: Start the sandbox container。 如果失败，kubelet 会 GC 掉 sandbox
    ds.client.StartContainer(createResp.ID)

    rewriteResolvFile()

    // 如果是 hostNetwork 类型，到这里就可以返回了，无需下面的 CNI 流程
    if GetNetwork() == NamespaceMode_NODE {
        return resp, nil
    }

    // Step 5: Setup networking for the sandbox with CNI
    // 包括分配 IP、设置 sandbox 内的路由、创建虚拟网卡等。
    cID := kubecontainer.BuildContainerID(runtimeName, createResp.ID)
    ds.network.SetUpPod(Namespace, Name, cID, Annotations, networkOptions)

    return resp, nil
}
```

最后调用的 `SetUpPod()` 为容器创建网络，它有会**调用到 plugin manager 的同名方法**：

```
// pkg/kubelet/dockershim/network/plugins.go

func (pm *PluginManager) SetUpPod(podNamespace, podName, id ContainerID, annotations, options) error {
    const operation = "set_up_pod"
    fullPodName := kubecontainer.BuildPodFullName(podName, podNamespace)

    // 调用 CNI 插件为容器设置网络
    pm.plugin.SetUpPod(podNamespace, podName, id, annotations, options)
}
```

> Cgroup 也很重要，是 Linux 掌管资源分配的方式，docker 利用它实现资源隔离。 更多信息，参考 [What even is a Container?](https://jvns.ca/blog/2016/10/10/what-even-is-a-container/)

## 6.3 CNI 前半部分：CNI plugin manager 处理

现在我们的 pod 已经有了一个占坑用的 pause 容器，它占住了 pod 需要用到的所有 namespace。 接下来需要做的就是：**调用底层的具体网络方案**（bridge/flannel/calico/cilium 等等） 提供的 CNI 插件，**创建并打通容器的网络**。

CNI 是 Container Network Interface 的缩写，工作机制与 Container Runtime Interface 类似。简单来说，CNI 是一个抽象接口，不同的网络提供商只要实现了 CNI 中的几个方法，就能接入 K8s，为容器创建网络。kubelet 与CNI 插件之间通过 JSON 数据交互（配置文件放在 `/etc/cni/net.d`），通过 stdin 将配置数据传递给 CNI binary (located in `/opt/cni/bin`)。

CNI 插件有自己的配置，例如，内置的 bridge 插件可能配置如下：

```
{
    "cniVersion": "0.3.1",
    "name": "bridge",
    "type": "bridge",
    "bridge": "cnio0",
    "isGateway": true,
    "ipMasq": true,
    "ipam": {
        "type": "host-local",
        "ranges": [
          [{"subnet": "${POD_CIDR}"}]
        ],
        "routes": [{"dst": "0.0.0.0/0"}]
    }
}
```

还会通过 `CNI_ARGS` 环境变量传递 pod metadata，例如 name 和 ns。

### 调用栈概览

下面的调用栈是 CNI 前半部分：**CNI plugin manager 调用到具体的 CNI 插件**（可执行文件）， 执行 shell 命令为容器创建网络：

```
SetUpPod                                                  // pkg/kubelet/dockershim/network/cni/cni.go
 |-ns = plugin.host.GetNetNS(id)
 |-plugin.addToNetwork(name, id, ns)                      // -> pkg/kubelet/dockershim/network/cni/cni.go
    |-plugin.buildCNIRuntimeConf
    |-cniNet.AddNetworkList(netConf)                      // -> github.com/containernetworking/cni/libcni/api.go
       |-for net := range list.Plugins
       |   result = c.addNetwork
       |              |-pluginPath = FindInPath(c.Path)
       |              |-ValidateContainerID(ContainerID)
       |              |-ValidateNetworkName(name)
       |              |-ValidateInterfaceName(IfName)
       |              |-invoke.ExecPluginWithResult(pluginPath, c.args("ADD", rt))
       |                        |-shell("/opt/cni/bin/xx <args>")
       |
       |-c.cacheAdd(result, list.Bytes, list.Name, rt)
```

最后一层调用 `ExecPlugin()`：

```
// vendor/github.com/containernetworking/cni/pkg/invoke/raw_exec.go

func (e *RawExec) ExecPlugin(ctx, pluginPath, stdinData []byte, environ []string) ([]byte, error) {
    c := exec.CommandContext(ctx, pluginPath)
    c.Env = environ
    c.Stdin = bytes.NewBuffer(stdinData)
    c.Stdout = stdout
    c.Stderr = stderr

    for i := 0; i <= 5; i++ { // Retry the command on "text file busy" errors
        err := c.Run()
        if err == nil { // Command succeeded
            break
        }

        if strings.Contains(err.Error(), "text file busy") {
            time.Sleep(time.Second)
            continue
        }

        // All other errors except than the busy text file
        return nil, e.pluginErr(err, stdout.Bytes(), stderr.Bytes())
    }

    return stdout.Bytes(), nil
}
```

可以看到，经过上面的几层调用，最终是通过 shell 命令执行了宿主机上的 CNI 插件， 例如 `/opt/cni/bin/cilium-cni`，并通过 stdin 传递了一些 JSON 参数。

## 6.4 CNI 后半部分：CNI plugin 实现

下面看 CNI 处理的后半部分：CNI 插件为容器创建网络，也就是可执行文件 `/opt/cni/bin/xxx` 的实现。

CNI 相关的代码维护在一个**单独的项目** [github.com/containernetworking/cni](https://github.com/containernetworking/cni)。 每个 CNI 插件只需要实现其中的几个方法，然后**编译成独立的可执行文件**，放在 `/etc/cni/bin` 下面即可。 下面是一些具体的插件，

```
$ ls /opt/cni/bin/
bridge  cilium-cni  cnitool  dhcp  host-local  ipvlan  loopback  macvlan  noop
```

### 调用栈概览

CNI 插件（可执行文件）执行时会调用到 `PluginMain()`，从这往后的调用栈 （**注意源文件都是 `github.com/containernetworking/cni` 项目中的路径**）：

```
PluginMain                                                     // pkg/skel/skel.go
 |-PluginMainWithError                                         // pkg/skel/skel.go
   |-pluginMain                                                // pkg/skel/skel.go
      |-switch cmd {
          case "ADD":
            checkVersionAndCall(cmdArgs, cmdAdd)               // pkg/skel/skel.go
              |-configVersion = Decode(cmdArgs.StdinData)
              |-Check(configVersion, pluginVersionInfo)
              |-toCall(cmdArgs) // toCall == cmdAdd
                 |-cmdAdd(cmdArgs)
                   |-specific CNI plugin implementations
     
          case "DEL":
            checkVersionAndCall(cmdArgs, cmdDel)
          case "VERSION":
            versionInfo.Encode(t.Stdout)
          default:
            return createTypedError("unknown CNI_COMMAND: %v", cmd)
        }
```

可见**对于 kubelet 传过来的 "ADD" 命令，最终会调用到 CNI 插件的 cmdAdd() 方法** —— 该方法默认是空的，需要由每种 CNI 插件自己实现。 同理，删除 pod 时对应的是 `"DEL"` 操作，调用到的 `cmdDel()` 方法也是要由具体 CNI 插件实现的。

### CNI 插件实现举例：Bridge

[github.com/containernetworking/plugins](https://github.com/containernetworking/plugins) 项目中包含了很多种 CNI plugin 的实现，例如 IPVLAN、Bridge、MACVLAN、VLAN 等等。

`bridge` CNI plugin 的实现见 [plugins/main/bridge/bridge.go](https://github.com/containernetworking/plugins/blob/v0.9.1/plugins/main/bridge/bridge.go)

执行逻辑如下：

1. 在默认 netns 创建一个 Linux bridge，这台宿主机上的所有容器都将连接到这个 bridge。

2. 创建一个 veth pair，将容器和 bridge 连起来。

3. 分配一个 IP 地址，配置到 pause 容器，设置路由。

   IP 从配套的网络服务 IPAM（IP Address Management）中分配的。最场景的 IPAM plugin 是 `host-local`，它从预先设置的一个网段里分配一个 IP，并将状态信息写到宿主机的本地文件系统，因此重启不会丢失。 `host-local` IPAM 的实现见 [plugins/ipam/host-local](https://github.com/containernetworking/plugins/tree/v0.9.1/plugins/ipam/host-local)。

4. 修改 `resolv.conf`，为容器配置 DNS。这里的 DNS 信息是从传给 CNI plugin 的参数中解析的。

以上过程完成之后，容器和宿主机（以及同宿主机的其他容器）之间的网络就通了， CNI 插件会将结果以 JSON 返回给 kubelet。

### CNI 插件实现举例：Noop

再来看另一种**比较有趣的 CNI 插件**：`noop`。这个插件是 CNI 项目自带的， 代码见 [plugins/test/noop/main.go](https://github.com/containernetworking/cni/blob/v0.8.1/plugins/test/noop/main.go#L184)。

```
func cmdAdd(args *skel.CmdArgs) error {
    return debugBehavior(args, "ADD")
}

func cmdDel(args *skel.CmdArgs) error {
    return debugBehavior(args, "DEL")
}
```

从名字以及以上代码可以看出，这个 CNI 插件（几乎）什么事情都不做。用途：

1. **测试或调试**：它可以打印 debug 信息。

2. 给**只支持 hostNetwork 的节点**使用。

   每个 node 上必须有一个配置正确的 CNI 插件，kubelet 自检才能通过，否则 node 会处于 NotReady 状态。

   某些情况下，我们不想让一些 node（例如 master node）承担正常的、创建带 IP pod 的工作， 只要它能创建 hostNetwork 类型的 pod 就行了（这样就无需给这些 node 分配 PodCIDR， 也不需要在 node 上启动 IPAM 服务）。

   这种情况下，就可以用 noop 插件。参考配置：

   ```
    $ cat /etc/cni/net.d/98-noop.conf
    {
        "cniVersion": "0.3.1",
        "type": "noop"
    }
   ```

### CNI 插件实现举例：Cilium

这个就很复杂了，做的事情非常多，可参考 [Cilium Code Walk Through: CNI Create Network](https://arthurchiao.art/blog/cilium-code-cni-create-network/)。

## 6.5 为容器配置跨节点通信网络（inter-host networking）

这项工作**不在 K8s 及 CNI 插件的职责范围内**，是由具体网络方案 在节点上的 agent 完成的，例如 flannel 网络的 flanneld，cilium 网络的 cilium-agent。

简单来说，跨节点通信有两种方式：

1. 隧道（tunnel or overlay）
2. 直接路由

这里赞不展开，可参考 [迈入 Cilium+BGP 的云原生网络时代](https://arthurchiao.art/blog/trip-stepping-into-cloud-native-networking-era-zh/)。

## 6.6 创建 `init` 容器及业务容器

至此，网络部分都配置好了。接下来就开始**启动真正的业务容器**。

Sandbox 容器初始化完成后，kubelet 就开始创建其他容器。 首先会启动 `PodSpec` 中指定的所有 init 容器， [代码](https://github.com/kubernetes/kubernetes/blob/v1.21.0/pkg/kubelet/kuberuntime/kuberuntime_manager.go#L690) 然后才启动主容器（main containers）。

### 调用栈概览

```
startContainer
 |-EnsureImageExists
 |
 |-generateContainerConfig                               // pkg/kubelet/kuberuntime/kuberuntime_container.go
 |  |-GenerateRunContainerOptions                        // pkg/kubelet/kubelet_pods.go
 |     |-makeEnvironmentVariables                        // pkg/kubelet/kubelet_pods.go
 |
 |-m.runtimeService.CreateContainer                      // pkg/kubelet/cri/remote/remote_runtime.go
 |  |-r.runtimeClient.CreateContainer                    // -> pkg/kubelet/dockershim/docker_container.go
 |       |-new(CreateContainerResponse)                  // staging/src/k8s.io/cri-api/pkg/apis/runtime/v1/api.pb.go
 |       |-Invoke("/runtime.v1.RuntimeService/CreateContainer")
 |
 |  CreateContainer // pkg/kubelet/dockershim/docker_container.go
 |      |-ds.client.CreateContainer                      // -> pkg/kubelet/dockershim/libdocker/instrumented_client.go
 |            |-d.client.ContainerCreate                 // -> vendor/github.com/docker/docker/client/container_create.go
 |               |-cli.post("/containers/create")
 |               |-json.NewDecoder().Decode(&resp)
 |
 |-m.runtimeService.StartContainer(containerID)          // -> pkg/kubelet/cri/remote/remote_runtime.go
 |  |-r.runtimeClient.StartContainer
 |       |-new(CreateContainerResponse)                  // staging/src/k8s.io/cri-api/pkg/apis/runtime/v1/api.pb.go
 |       |-Invoke("/runtime.v1.RuntimeService/StartContainer")
 |
 |-m.runner.Run(PostStart)
```

### 具体过程

```
// pkg/kubelet/kuberuntime/kuberuntime_container.go

func (m *kubeGenericRuntimeManager) startContainer(podSandboxID, podSandboxConfig, spec *startSpec, pod *v1.Pod,
     podStatus *PodStatus, pullSecrets []v1.Secret, podIP string, podIPs []string) (string, error) {

    container := spec.container

    // Step 1: 拉镜像
    m.imagePuller.EnsureImageExists(pod, container, pullSecrets, podSandboxConfig)

    // Step 2: 通过 CRI 创建容器，其中包括给 pod 注入环境变量
    containerConfig := m.generateContainerConfig(container, pod, restartCount, podIP, imageRef, podIPs, target)

    m.internalLifecycle.PreCreateContainer(pod, container, containerConfig)
    containerID := m.runtimeService.CreateContainer(podSandboxID, containerConfig, podSandboxConfig)
    m.internalLifecycle.PreStartContainer(pod, container, containerID)

    // Step 3: 启动容器
    m.runtimeService.StartContainer(containerID)

    legacySymlink := legacyLogSymlink(containerID, containerMeta.Name, sandboxMeta.Name, sandboxMeta.Namespace)
    m.osInterface.Symlink(containerLog, legacySymlink)

    // Step 4: 执行 post start hook
    m.runner.Run(kubeContainerID, pod, container, container.Lifecycle.PostStart)
}
```

过程：

1. [拉镜像](https://github.com/kubernetes/kubernetes/blob/v1.21.0/pkg/kubelet/kuberuntime/kuberuntime_container.go#L140)。 如果是私有镜像仓库，就会从 PodSpec 中寻找访问仓库用的 secrets。

2. 通过 CRI [创建 container](https://github.com/kubernetes/kubernetes/blob/v1.21.0/pkg/kubelet/kuberuntime/kuberuntime_container.go#L179)。

   从 parent PodSpec 的 `ContainerConfig` struct 中解析参数（command, image, labels, mounts, devices, env variables 等等）， 然后通过 protobuf 发送给 CRI plugin。例如对于 docker，收到请求后会反序列化，从中提取自己需要的参数，然后发送给 Daemon API。 过程中它会给容器添加几个 metadata labels （例如 container type, log path, sandbox ID）。

   **这里稍微展开一点**：如果想通过 API 访问 K8s 资源，最常见的 方式是用 `client-go` **初始化一个 K8s client**：初始化时指定 kubeconfig 文件路径或 apiserver 地址。**不传行不行呢？**

   如果是**以 pod 方式部署**这个程序，还真可以不传：client-go 代码会 fallback 到所谓的 `InClusterConfig` 模式，自动从当前 pod 中获取 `KUBERNETES_SERVICE_HOST` 和 `KUBERNETES_SERVICE_PORT` 这两个环境变量，二者拼起来就是 **kube-apiserver 的 Service 入口**，例如 `10.224.0.1:443`。

   这两个环境变量就是在这一步注入的。

   > **Service 网段是在 apiserver 中配置的**，例如 `--service-cluster-ip-range=10.224.0.0/16`。

3. 然后通过 `runtimeService.startContainer()` 启动容器；

4. 如果注册了 post-start hooks，接下来就执行这些 hooks。**post Hook 类型**：

- `Exec`：在容器内执行具体的 shell 命令。
- `HTTP`：对容器内的服务（endpoint）发起 HTTP 请求。

如果 PostStart hook 运行时间过长，或者 hang 住或失败了，容器就无法进入 `running` 状态。

