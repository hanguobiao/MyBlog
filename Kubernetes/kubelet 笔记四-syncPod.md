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

KillPod