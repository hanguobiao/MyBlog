# Kubeblocks源码笔记四--workload

Kubeblocks不再使用Statefulset来管理Pod的方案，而是采用了InstanceSet直接管理Pod。优势在于InstanceSet根据数据库集群的需求设计，添加了对于角色的管理，并支持指定节点下线等功能。InstanceSet采用了一种类似于之前DAG的方式，但存在一些不同。

InstanceSet作为底层的资源不会反向依赖App类型的API，如何Reconcile只取决于自身的状态。Component会增删改InstanceSet，之后InstanceSet捕捉到自身状态的变化，并根据自身的变化进行Reconcile

```
func (r *InstanceSetReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
    logger := log.FromContext(ctx).WithValues("InstanceSet", req.NamespacedName)

    res, err := kubebuilderx.NewController(ctx, r.Client, req, r.Recorder, logger).
       Prepare(instanceset.NewTreeLoader()).
       Do(instanceset.NewAPIVersionReconciler()).
       Do(instanceset.NewFixMetaReconciler()).
       Do(instanceset.NewDeletionReconciler()).
       Do(instanceset.NewStatusReconciler()).
       Do(instanceset.NewRevisionUpdateReconciler()).
       Do(instanceset.NewAssistantObjectReconciler()).
       Do(instanceset.NewReplicasAlignmentReconciler()).
       Do(instanceset.NewUpdateReconciler()).
       Commit()

    // TODO(free6om): handle error based on ErrorCode (after defined)

    return res, err
}
```

新的Controller的struct中仍然存咋oldTree，tree。Reconciler仍然是改变OldTree和Tree的状态，最后的Commit阶段根据oldTree和Tree的diff对资源进行实际的修改。

Tree的根节点为当前的Instance，子节点为InstanceSet的子资源。由于目前的依赖程度不深，所有树仅为两层

Prepare阶段会将需要的信息提取出来，以及multi-cluster架构使用的intoContext()

```
type controller struct {
	ctx      context.Context
	cli      client.Client
	req      ctrl.Request
	recorder record.EventRecorder
	logger   logr.Logger

	res Result
	err error

	oldTree *ObjectTree
	tree    *ObjectTree
}

func (c *controller) Prepare(reader TreeLoader) Controller {
    c.oldTree, c.err = reader.Load(c.ctx, c.cli, c.req, c.recorder, c.logger)
    if c.err != nil {
       return c
    }
    if c.oldTree == nil {
       c.err = fmt.Errorf("nil tree loaded")
       return c
    }
    c.tree, c.err = c.oldTree.DeepCopy()

    // init placement
    c.ctx = intoContext(c.ctx, placement(c.oldTree.GetRoot()))

    return c
}
```

load函数中会生成具体的Tree对象，以及提取Instance模版用于生成与更新Pod。

ReadObjectTree会通过反射获取到Root的类型，之后会通过goClient的list获取到相关的资源。需要获取的资源都写在ownedKinds()中，获取到这些资源后，都挂到当前Root节点的子节点中。

```
func (r *treeLoader) Load(ctx context.Context, reader client.Reader, req ctrl.Request, recorder record.EventRecorder, logger logr.Logger) (*kubebuilderx.ObjectTree, error) {
    ml := getMatchLabels(req.Name)
    kinds := ownedKinds()
    tree, err := kubebuilderx.ReadObjectTree[*workloads.InstanceSet](ctx, reader, req, ml, kinds...)
    if err != nil {
       return nil, err
    }

    // load compressed instance templates if present
    if err = loadCompressedInstanceTemplates(ctx, reader, tree); err != nil {
       return nil, err
    }

    tree.EventRecorder = recorder
    tree.Logger = logger
    tree.SetFinalizer(finalizer)

    return tree, err
}
```



**还有通过ComfigMap模版获得模版，猜测和异构Pod有关？存疑**

```
// ReadObjectTree reads all objects owned by the root object which is type of 'T' with key in 'req'.
func ReadObjectTree[T client.Object](ctx context.Context, reader client.Reader, req ctrl.Request, ml client.MatchingLabels, kinds ...client.ObjectList) (*ObjectTree, error) {
    tree := NewObjectTree()

    // read root object
    var obj T
    t := reflect.TypeOf(obj)
    if t.Kind() == reflect.Ptr {
       t = t.Elem()
    }
    rootObj := reflect.New(t).Interface()
    root, _ := rootObj.(T)
    if err := reader.Get(ctx, req.NamespacedName, root); err != nil {
       if apierrors.IsNotFound(err) {
          return tree, nil
       }
       return nil, err
    }
    tree.SetRoot(root)

    // init placement
    ctx = intoContext(ctx, placement(root))

    // read child objects
    inNS := client.InNamespace(req.Namespace)
    for _, list := range kinds {
       if err := reader.List(ctx, list, inNS, ml, inDataContext4C()); err != nil {
          return nil, err
       }
       // reflect get list.Items
       items := reflect.ValueOf(list).Elem().FieldByName("Items")
       l := items.Len()
       for i := 0; i < l; i++ {
          // get the underlying object
          object := items.Index(i).Addr().Interface().(client.Object)
          if len(object.GetOwnerReferences()) > 0 && !model.IsOwnerOf(root, object) {
             continue
          }
          if err := tree.Add(object); err != nil {
             return nil, err
          }
       }
    }

    return tree, nil
}
```

新的Reconciler的接口定义如下

```
type Reconciler interface {
    PreCondition(*ObjectTree) *CheckResult
    Reconcile(tree *ObjectTree) (Result, error)
}
```

判断是否执行某个Reconciler不再放到Reconcile当中，而是由PreCondition方法判断，并且出现Error也不会停止执行，而是依次处理所有Reconciler

```
func (c *controller) Do(reconcilers ...Reconciler) Controller {
    if c.err != nil {
       return c
    }
    if c.res.Next != cntn && c.res.Next != cmmt && c.res.Next != rtry {
       c.err = fmt.Errorf("unexpected next action: %s. should be one of Continue, Commit or Retry", c.res.Next)
       return c
    }
    if c.res.Next != cntn {
       return c
    }
    if len(reconcilers) == 0 {
       return c
    }

    reconciler := reconcilers[0]
    switch result := reconciler.PreCondition(c.tree); {
    case result.Err != nil:
       c.err = result.Err
       return c
    case !result.Satisfied:
       return c
    }
    c.res, c.err = reconciler.Reconcile(c.tree)

    return c.Do(reconcilers[1:]...)
}
```

下面对每个Reconciler进行介绍



# fixMetaReconciler

为Root节点即Instance添加Finalizer

```
func (r *fixMetaReconciler) Reconcile(tree *kubebuilderx.ObjectTree) (kubebuilderx.Result, error) {
    // The object is not being deleted, so if it does not have our finalizer,
    // then lets add the finalizer and update the object. This is equivalent
    // registering our finalizer.
    controllerutil.AddFinalizer(tree.GetRoot(), finalizer)
    return kubebuilderx.Commit, nil
}
```

# deletionReconciler

处理删除时的逻辑，先删除Instance所有子资源，之后删除Root也就是Instance本身

这里只是在内存的ObjectTree中处理

```
func (r *deletionReconciler) Reconcile(tree *kubebuilderx.ObjectTree) (kubebuilderx.Result, error) {
    // delete secondary objects first
    if len(tree.GetSecondaryObjects()) > 0 {
       tree.DeleteSecondaryObjects()
       return kubebuilderx.Continue, nil
    }

    // delete root object
    tree.DeleteRoot()
    return kubebuilderx.Continue, nil
}
```

# statusReconciler

获取当前所有Pod list

根据pod的状态来计算和更新Instance的status

```
// 1. get all pods
pods := tree.List(&corev1.Pod{})

// 2. calculate status summary
updateRevisions, err := GetRevisions(its.Status.UpdateRevisions)

its.Status.Replicas = replicas
its.Status.ReadyReplicas = readyReplicas
its.Status.AvailableReplicas = availableReplicas
its.Status.CurrentReplicas = currentReplicas
its.Status.UpdatedReplicas = updatedReplicas
its.Status.CurrentRevisions, _ = buildRevisions(currentRevisions)
its.Status.TemplatesStatus = buildTemplatesStatus(template2TemplatesStatus)

readyCondition, err := buildReadyCondition(its, readyReplicas >= replicas, notReadyNames)
if err != nil {
  return kubebuilderx.Continue, err
}
meta.SetStatusCondition(&its.Status.Conditions, *readyCondition)

availableCondition, err := buildAvailableCondition(its, availableReplicas >= replicas, notAvailableNames)
if err != nil {
  return kubebuilderx.Continue, err
}
meta.SetStatusCondition(&its.Status.Conditions, *availableCondition)

// 3. set InstanceFailure condition
failureCondition, err := buildFailureCondition(its, podList)
if err != nil {
  return kubebuilderx.Continue, err
}
if failureCondition != nil {
  meta.SetStatusCondition(&its.Status.Conditions, *failureCondition)
} else {
  meta.RemoveStatusCondition(&its.Status.Conditions, string(workloads.InstanceFailure))
}

// 4. set members status
setMembersStatus(its, podList)
```

# revisionUpdateReconciler



`revisionUpdateReconciler`的核心功能是根据InstanceSet中的Pod模板生成唯一的Revision，并将这些Revision信息记录在InstanceSet的状态字段中。其主要作用包括：

1. **生成Revision**：为每个Pod实例生成唯一的版本号（Revision），基于Pod模板和InstanceSet的配置。
2. 更新状态：将生成的Revision信息更新到InstanceSet的Status字段中，包括：
   - `UpdateRevisions`：记录每个Pod实例的当前版本。
   - `UpdateRevision`：记录最新的版本号。
   - `UpdatedReplicas`：计算已更新的Pod副本数。
3. **优化性能**：通过`ObservedGeneration`字段，仅在InstanceSet的Spec更新时才重新计算Revision信息，避免不必要的性能开销。

### 构建实例模板

buildInstanceTemplateExts函数会将InstanceSet的默认Pod模板与instanceTemplates覆盖合并，生成最终的实例模板列表

### 生成实例名，计算Revision

这里会根据Instance的InstanceTemplate与默认配置进行合并，生成最终异构Pod模本

为这些异构Pod生成名字，验证是否有重复命名

```
for _, template := range instanceTemplateList {
    ordinalList, err := GetOrdinalListByTemplateName(itsExt.its, template.Name)
    if err != nil {
       return kubebuilderx.Continue, err
    }
    instanceNames, err := GenerateInstanceNamesFromTemplate(its.Name, template.Name, template.Replicas, itsExt.its.Spec.OfflineInstances, ordinalList)
    if err != nil {
       return kubebuilderx.Continue, err
    }
    revision, err := BuildInstanceTemplateRevision(&template.PodTemplateSpec, its)
    if err != nil {
       return kubebuilderx.Continue, err
    }
    for _, name := range instanceNames {
       instanceRevisionList = append(instanceRevisionList, instanceRevision{name: name, revision: revision})
    }
}
```

### 持久化Revision

计算Revision，并将生成的Revision保存到Status字段

```
revisions, err := buildRevisions(updatedRevisions)

its.Status.UpdateRevision = updateRevision
updatedReplicas, err := calculateUpdatedReplicas(its, tree.List(&corev1.Pod{}))
if err != nil {
  return kubebuilderx.Continue, err
}
its.Status.UpdatedReplicas = updatedReplicas
// The 'ObservedGeneration' field is used to indicate whether the revisions have been updated.
// Computing these revisions in each reconciliation loop can be time-consuming, so we optimize it by
// performing the computation only when the 'spec' is updated.
its.Status.ObservedGeneration = its.Generation
```

#### status.observedGeneration

在 Kubernetes 中，`metadata.generation` 和 `status.observedGeneration` 都是与资源对象的生命周期和状态跟踪相关的字段，但它们有不同的作用和用途。

1. `metadata.generation`：
   `metadata.generation` 是一个资源对象的元数据字段，通常出现在该资源对象的元数据（metadata）部分。它表示资源对象的生成代数（generation），每当资源对象的定义（specification）发生变化时，这个值就会增加。这是一个只读字段，不能手动设置。

   例如，当你更新一个 Deployment 的定义时，Deployment 的 `metadata.generation` 会自增，这会触发 Kubernetes 控制器去检测变化并执行相应的操作，比如更新副本数量或滚动更新。

2. `status.observedGeneration`：
   `status.observedGeneration` 是资源对象的状态（status）字段，通常出现在该资源对象的状态部分。它表示控制器最后一次观察到的 `metadata.generation` 值。当 `metadata.generation` 增加时，控制器会更新 `status.observedGeneration`，以便追踪它最后一次处理过的生成代数。

   这个字段在实现控制器时非常有用，因为控制器可以通过比较 `metadata.generation` 和 `status.observedGeneration` 来判断是否需要采取进一步的操作。如果二者不相等，控制器可以知道资源对象的定义已经更新，从而触发适当的调谐操作。



## 4. **执行流程**

1. **加载实例模板**：通过`buildInstanceTemplateExts`生成实例模板。将InstanceSet的默认Pod模板与实例级别的模板覆盖合并，生成最终的实例模板列表。
2. **生成实例名称**：根据模板名称、副本数、离线实例等信息，为每个实例生成唯一的名称。
3. **生成Revision**：基于实例模板和InstanceSet对象生成版本号。
4. **验证名称唯一性**：确保生成的实例名称没有重复。
5. **更新状态**：将生成的版本信息更新到InstanceSet的Status字段中，包括：
   - `UpdateRevisions`：记录每个实例的当前版本
   - `UpdateRevision`：记录最新的版本号
   - `UpdatedReplicas`：计算已更新的副本数
   - `ObservedGeneration`：记录当前处理的Generation，用于优化性能，避免在Spec未更新时重复计算
6. **优化性能**：通过`ObservedGeneration`字段，仅在InstanceSet的Spec更新时才重新计算版本信息，避免不必要的计算开销。

# assistantObjectReconciler

用于管理非Workload对象，例如Headless-Service，和用于保存Template信息的CM。这些对象用于辅助Instance的生成。

`assistantObjectReconciler`的核心功能包括：

1. 生成辅助对象：
   - 为InstanceSet生成Headless Service，以支持Pod Headless的访问方式。
   - 管理和生成与InstanceSet相关的ConfigMap，用于保存模板信息等。
2. 对象管理：
   - 通过对比新旧对象的快照（Snapshot），计算需要创建、更新或删除的对象。
   - 将生成的辅助对象添加到ObjectTree中，确保它们能够被后续的Commit阶段正确处理。
3. 权限管理：
   - 为辅助对象设置OwnerReference，确保它们与InstanceSet的生命周期一致。

### 设置**OwnerReference**

为每个辅助对象设置OwnerReference，确保它们与InstanceSet的生命周期绑定。

```
headLessSvc := buildHeadlessSvc(*its, labels, headlessSelectors)
objects = append(objects, headLessSvc)

for _, object := range objects {
  if err := intctrlutil.SetOwnership(its, object, model.GetScheme(), finalizer); err != nil {
    return kubebuilderx.Continue, err
  }
}


```

### 增删改Object

根据集合的差异集，在ObjectTree中进行相应的操作。

```
// compute create/update/delete set
newSnapshot := make(map[model.GVKNObjKey]client.Object)
for _, object := range objects {
  name, err := model.GetGVKName(object)
  if err != nil {
    return kubebuilderx.Continue, err
  }
  newSnapshot[*name] = object
}

oldSnapshot := make(map[model.GVKNObjKey]client.Object)
svcList := tree.List(&corev1.Service{})
cmList := tree.List(&corev1.ConfigMap{})
cmListFiltered, err := filterTemplate(cmList, its.Annotations)
if err != nil {
  return kubebuilderx.Continue, err
}
for _, objectList := range [][]client.Object{svcList, cmListFiltered} {
  for _, object := range objectList {
    name, err := model.GetGVKName(object)
    if err != nil {
      return kubebuilderx.Continue, err
    }
    oldSnapshot[*name] = object
  }
}

createSet := newNameSet.Difference(oldNameSet)
updateSet := newNameSet.Intersection(oldNameSet)
deleteSet := oldNameSet.Difference(newNameSet)
for name := range createSet {
  if err := tree.Add(newSnapshot[name]); err != nil {
    return kubebuilderx.Continue, err
  }
}
for name := range updateSet {
  oldObj := oldSnapshot[name]
  newObj := copyAndMerge(oldObj, newSnapshot[name])
  if err := tree.Update(newObj); err != nil {
    return kubebuilderx.Continue, err
  }
}
for name := range deleteSet {
  if err := tree.Delete(oldSnapshot[name]); err != nil {
    return kubebuilderx.Continue, err
  }
}
```

### 总结

`assistantObjectReconciler`的主要职责是管理和维护与InstanceSet相关的辅助对象，如Headless Service和ConfigMap。通过生成和更新这些辅助对象，它确保InstanceSet的正常运行和功能扩展。该Reconciler的核心逻辑包括：

1. **生成辅助对象**：根据InstanceSet的配置生成Headless Service等对象。
2. **对象管理**：通过对比新旧对象快照，计算并应用差异集。
3. **权限管理**：为辅助对象设置OwnerReference，确保它们与InstanceSet的生命周期一致。

通过精细化的对象管理，`assistantObjectReconciler`为Kubeblocks的实例管理提供了坚实的基础支持。

# instanceAlignmentReconciler

`instanceAlignmentReconciler` 是 InstanceSet 编排体系中最核心的 Pod 生命周期管理器，负责实现实例数量对齐、拓扑调度约束、异构实例管理等核心能力。其核心功能包括：

1. **实例拓扑映射**：基于 InstanceTemplate 配置，通过 Ordinals 声明式指定实例的分布拓扑
2. **滚动更新控制**：实现按模板分组的有序编排策略，支持批量创建/删除操作
3. **异构实例管理**：支持在同一 InstanceSet 下基于不同模板创建差异化 Pod 实例
4. **持久化存储管理**：自动维护 PVC 与 Pod 实例的绑定关系

会根据Range分配实际的Pod，only handle instance count, don't care instance revision.

#### 1. 实例模板

首先获取到Instance的模版，InstanceTemplate中包括pod的信息以及pod的分配范围Ordinals Ordinals，这代表Pod的分配是不连续的。并且可以通过不同的InstanceTemplate支持异构的Pod，即一个InstanceSet下可以有不同Template创建的Pod

##### 执行实例下线

不连续的序号就提供这样一个功能，执行实例下线

K8s Statefulset缩容必须是序号最大的实现最先被缩容。而InstanceSet则支持下线指定序号的实例，原理就是将原来的Ordinals断开，生成不同的Ordinals，这样在InstanceSet的Reconcile流程中，就会通过diff将这个实例下线

这样的设计可能不够云原生，但确实有他的应用场景。Statefulset的假设是Pod采用云存储，可以漂移到其他Pod。而目前的实际使用场景，往往是使用hostPath，直接使用主机的存储来实现更低的存储成本和更优的性能，这种情况下指定节点下线的功能就派上用场。

```
// InstanceTemplate allows customization of individual replica configurations within a Component,
// without altering the base component template defined in ClusterComponentSpec.
// It enables the application of distinct settings to specific instances (replicas),
// providing flexibility while maintaining a common configuration baseline.
type InstanceTemplate struct {
    // Name specifies the unique name of the instance Pod created using this InstanceTemplate.
    // This name is constructed by concatenating the component's name, the template's name, and the instance's ordinal
    // using the pattern: $(cluster.name)-$(component.name)-$(template.name)-$(ordinal). Ordinals start from 0.
    // The specified name overrides any default naming conventions or patterns.
    //
    Name string `json:"name"`

    // Specifies the number of instances (Pods) to create from this InstanceTemplate.
    // This field allows setting how many replicated instances of the component,
    // with the specific overrides in the InstanceTemplate, are created.
    // The default value is 1. A value of 0 disables instance creation.
    Replicas *int32 `json:"replicas,omitempty"`

    // Specifies the desired Ordinals of this InstanceTemplate.
    // The Ordinals used to specify the ordinal of the instance (pod) names to be generated under this InstanceTemplate.
    //
    // For example, if Ordinals is {ranges: [{start: 0, end: 1}], discrete: [7]},
    // then the instance names generated under this InstanceTemplate would be
    // $(cluster.name)-$(component.name)-$(template.name)-0、$(cluster.name)-$(component.name)-$(template.name)-1 and
    // $(cluster.name)-$(component.name)-$(template.name)-7
    Ordinals Ordinals `json:"ordinals,omitempty"`

    // Specifies an override for the first container's image in the pod.
    Image *string `json:"image,omitempty"`

    // Specifies an override for the resource requirements of the first container in the Pod.
    // This field allows for customizing resource allocation (CPU, memory, etc.) for the container.
    Resources *corev1.ResourceRequirements `json:"resources,omitempty"`

    // Defines Env to override.
    // Add new or override existing envs.
    Env []corev1.EnvVar `json:"env,omitempty"`

    // Defines Volumes to override.
    // Add new or override existing volumes.
    Volumes []corev1.Volume `json:"volumes,omitempty"`

    // Defines VolumeMounts to override.
    // Add new or override existing volume mounts of the first container in the pod.
    VolumeMounts []corev1.VolumeMount `json:"volumeMounts,omitempty"`
}
```

#### 2. **生成实例名称与计算差异集**

```
nameToTemplateMap, err := buildInstanceName2TemplateMap(itsExt)
if err != nil {
    return kubebuilderx.Continue, err
}

```

buildInstanceName2TemplateMap将所有的 InstanceTemplate 展开为具体的实例名称，确保无重复且符合命名约束

对于Instance（也就是Pod）的命名规则：$(parent.name)-$(template.name)-$(ordinal).

```
// 1. 遍历 InstanceTemplate 列表
for _, template := range instanceTemplateList {
    // 2. 解析拓扑规则生成实例序号
    ordinalList := parseOrdinals(template.Ordinals)
    // 3. 生成实例名称列表 $(parent)-$(template)-$(ordinal)
    instanceNames := GenerateInstanceNamesFromTemplate(its.Name, template.Name, ordinalList)
    // 4. 填充映射表
    for _, name := range instanceNames {
        nameToTemplateMap[name] = template
    }
}
```

之后通过计算差异集，来确定更新逻辑

```
createNameSet := newNameSet.Difference(oldNameSet)
deleteNameSet := oldNameSet.Difference(newNameSet)
```



#### 3.计算并发量并构建实例

```go
concurrency, err = CalculateConcurrencyReplicas(its.Spec.ParallelPodManagementConcurrency, int(*its.Spec.Replicas))

var currentAlignedNameList []string
for i, name := range newNameList {
		if _, ok := createNameSet[name]; !ok {
			currentAlignedNameList = append(currentAlignedNameList, name)
			continue
		}
		if !isOrderedReady && concurrency <= 0 {
			break
		}
		predecessor := getPredecessor(i)
  	// 获取该实例对应的模板配置，并构建pod实例
  	inst, err := buildInstanceByTemplate(name, nameToTemplateMap[name], its, "")
  	if err := tree.Add(inst.pod); err != nil {
			return kubebuilderx.Continue, err
		}
  	currentAlignedNameList = append(currentAlignedNameList, name)
  	
  	if isOrderedReady {
			break
		}
		concurrency--
		// create PVCs
		for _, name := range currentAlignedNameList {
        pvcs := buildInstancePVCByTemplate(name, nameToTemplateMap[name], its)
        for _, pvc := range pvcs {
            switch oldPvc, err := tree.Get(pvc); {
            case err != nil:
              return kubebuilderx.Continue, err
            case oldPvc == nil:
              if err = tree.Add(pvc); err != nil {
                return kubebuilderx.Continue, err
              }
            default:
              pvcObj := copyAndMerge(oldPvc, pvc)
              if pvcObj != nil {
                if err = tree.Update(pvcObj); err != nil {
                  return kubebuilderx.Continue, err
                }
              }
            }
        }
    }
 

  if isOrderedReady {
    break
  }
  concurrency--
}

```

#### 4.下线冗余实例

```
for _, object := range oldInstanceList {
  pod, _ := object.(*corev1.Pod)
  if _, ok := deleteNameSet[pod.Name]; !ok {
    continue
  }
  if !isOrderedReady && concurrency <= 0 {
    break
  }
  if isOrderedReady && !isRunningAndReady(pod) {
    tree.EventRecorder.Eventf(its, corev1.EventTypeWarning, "InstanceSet %s/%s is waiting for Pod %s to be Running and Ready",
      its.Namespace,
      its.Name,
      pod.Name)
  }
  if err := tree.Delete(pod); err != nil {
    return kubebuilderx.Continue, err
  }
```

主要逻辑

1. **获取实例模板**：从 `InstanceTemplate` 中获取 Pod 的信息以及 Pod 的分配范围 `Ordinals`。`Ordinals` 表示 Pod 的分配是不连续的，且可以通过不同的 `InstanceTemplate` 支持异构的 Pod，即一个 `InstanceSet` 下可以有不同模板创建的 Pod。
2. **生成实例名称**：根据模板名称、副本数、离线实例等信息，为每个实例生成唯一的名称。
3. **查找和计算需要创建和删除的 Pod**：通过对比新旧实例名称集合，计算需要创建和删除的 Pod。
4. **并发控制**：根据 `InstanceSet` 的 `ParallelPodManagementConcurrency` 配置，控制 Pod 的并发创建和删除操作。
5. **创建和删除 Pod**：根据计算结果，调用 `tree.Add` 和 `tree.Delete` 方法进行 Pod 的创建和删除操作。

# updateReconciler

> handles the updates of instances based on the UpdateStrategy.
> Currently, two update strategies are supported: 'OnDelete' and 'RollingUpdate'.

如果说上面的instanceAlignmentReconciler是管理实例的数量，那么这里就是管理pod的更新

`updateReconciler` 是 InstanceSet 中负责处理 Pod 更新的核心组件，支持 `OnDelete` 和 `RollingUpdate` 两种更新策略。其主要功能包括：

1. **更新策略支持**：支持 `OnDelete` 和 `RollingUpdate` 两种更新策略。
2. **滚动更新控制**：通过 `Partition` 和 `MaxUnavailable` 参数控制滚动更新的速度和并发度。
3. **角色感知更新**：对于带有 `Roles` 配置的 InstanceSet，根据 `MemberUpdateStrategy` 控制更新顺序。
4. **更新策略检查**：根据 Pod 的健康状态、可用性以及角色状态，决定是否进行更新。
5. **原地更新与重建**：支持原地更新和重建两种更新方式，并根据 `PodUpdatePolicy` 进行策略选择。



### 1.验证更新集合

首先通过集合运算确保新旧实例集合已对齐，避免在缩扩容未完成时触发更新。

```
newNameSet := sets.New[string]()
for name := range nameToTemplateMap {
    newNameSet.Insert(name)
}
oldNameSet := sets.New[string]()
oldInstanceMap := make(map[string]*corev1.Pod)
var oldPodList []*corev1.Pod
for _, object := range tree.List(&corev1.Pod{}) {
    oldNameSet.Insert(object.GetName())
    pod, _ := object.(*corev1.Pod)
    oldInstanceMap[object.GetName()] = pod
    oldPodList = append(oldPodList, pod)
}
updateNameSet := oldNameSet.Intersection(newNameSet)

// 当新老实例数量不匹配时终止更新流程
if len(updateNameSet) != len(oldNameSet) || len(updateNameSet) != len(newNameSet) {
    tree.Logger.Info("instances not aligned")
    return kubebuilderx.Continue, nil
}
```



### 2.滚动更新

目前支持的更新策略

RollingUpdate：

	// RollingUpdateStatefulSetStrategyType 表示更新将根据 StatefulSet 的排序约束应用于 StatefulSet 中的所有 Pod。
	// 使用此策略执行扩缩操作时，新的 Pod 将从 StatefulSet 的 updateRevision 指定的规范版本创建。

OnDelete：

	// OnDeleteStatefulSetStrategyType 触发传统行为。版本跟踪和有序滚动重启被禁用。
	// 当 Pod 被手动删除时，它们会从 StatefulSetSpec 重新创建。
	// 使用此策略执行扩缩操作时，新的 Pod 将从 StatefulSet 的 currentRevision 指定的规范版本创建。

parsePartitionNMaxUnavailable参考了STS滚动更新的策略，

1. 计算

   - **Partition**：保留旧版本的最小实例数（类似金丝雀部署保护机制）

   - **MaxUnavailable**：最大允许不可用实例数（计算滚动更新batch size）

2. 计算当前不可用的Pod数量。
3. 根据角色（Roles）和更新策略计算可以更新的Pod数量。
   - BestEffortParallel
   - Serial
   - Parallel
4. 对Pod列表进行排序，优先更新高优先级的Pod。
5. 遍历Pod列表，根据条件判断是否可以更新Pod，并执行相应的更新操作。

```
if its.Spec.UpdateStrategy.Type == apps.OnDeleteStatefulSetStrategyType {
    // TODO: how to handle the OnDelete type?
    return kubebuilderx.Continue, nil
}

// 处理滚动更新策略
partition, maxUnavailable, _ := parsePartitionNMaxUnavailable(
    its.Spec.UpdateStrategy.RollingUpdate, 
    len(oldPodList)
)

// 计算当前不可用实例数
currentUnavailable := 0
for _, pod := range oldPodList {
    if !isHealthy(pod) {
        currentUnavailable++
    }
}
unavailable := maxUnavailable - currentUnavailable  // 剩余可更新配额

// 生成基于角色的更新计划
if len(its.Spec.Roles) > 0 {
    plan := NewUpdatePlan(*itsForPlan, oldPodList, IsPodUpdated)
    podsToBeUpdated, _ := plan.Execute()
    updateCount = len(podsToBeUpdated)  // 获取可安全更新的实例数
}
```

基于角色的策略就在生成InstanceSet时确定角色的更新的优先级

```
rolePriorityMap := ComposeRolePriorityMap(p.its.Spec.Roles)
SortPods(p.pods, rolePriorityMap, false)

// generate plan by MemberUpdateStrategy
switch *p.its.Spec.MemberUpdateStrategy {
case workloads.SerialUpdateStrategy:
    p.buildSerialUpdatePlan()
case workloads.ParallelUpdateStrategy:
    p.buildParallelUpdatePlan()
case workloads.BestEffortParallelUpdateStrategy:
    p.buildBestEffortParallelUpdatePlan(rolePriorityMap)
}
```

不同的角色更新策略会生成不同的DAG，遍历这个生成的DAG就是预期的角色更新顺序

ParallelUpdate和SerialUpdate不会考虑角色

```
// update according to role update priority
func (p *realUpdatePlan) buildSerialUpdatePlan() {
    preVertex, _ := model.FindRootVertex(p.dag)
    for i := range p.pods {
       vertex := &model.ObjectVertex{Obj: &p.pods[i]}
       p.dag.AddConnect(preVertex, vertex)
       preVertex = vertex
    }
}

func (p *realUpdatePlan) buildParallelUpdatePlan() {
	root, _ := model.FindRootVertex(p.dag)
	for i := range p.pods {
		vertex := &model.ObjectVertex{Obj: &p.pods[i]}
		p.dag.AddConnect(root, vertex)
	}
}
```

BestEffortParallelUpdate更加复杂一些，这里需要结合Kubeblocks对于角色的抽象来理解

以一个Leader、Follower、Learner的经典角色划分举例，参与仲裁就是是否有选主投票权。所以更新的逻辑是

1. 先更新所有的leaner
2. 之后更新半数以下的follower
3. 更新剩下的Follower
4. 最后FAILOVER并更新FAILOVER之前的leader

```
roles:                                                                                                                                                                                                                                                                    
  - name: leader                                                                                                                                                                                                                                                            
    participatesInQuorum: true                                                                                                                                                                                                                                              
    updatePriority: 3                                                                                                                                                                                                                                                   
  - name: follower                                                                                                                                                                                                                                                          
    participatesInQuorum: true                                                                                                                                                                                                                                              
    updatePriority: 2
  - name: leaner                                                                                                                                                                                                                                                          
    participatesInQuorum: false                                                                                                                                                                                                                                              
    updatePriority: 1
```



具体逻辑：

1. **查找根节点**：首先，通过 `model.FindRootVertex(p.dag)` 方法找到有向无环图（DAG）的根节点 `currentVertex`。
2. **确定优先级**：
   - 初始化 `quorumPriority` 为最大整数，`leaderPriority` 为 0。
   - 遍历 `p.its.Spec.Roles` 中的每个角色，更新 `leaderPriority` 和 `quorumPriority`。`leaderPriority` 是所有角色中优先级最高的，而 `quorumPriority` 是参与仲裁（quorum）的角色中优先级最低的。
3. **添加非仲裁节点**：
   - 遍历 `p.pods` 列表，将优先级低于 `quorumPriority` 的节点添加到 DAG 中，并连接到前一个节点 `preVertex`。
4. **添加一半的跟随者节点**：
   - 统计优先级低于 `leaderPriority` 的跟随者节点数量 `followerCount`。
   - 将跟随者节点的前半部分添加到 DAG 中，并连接到前一个节点。
5. **添加另一半的跟随者节点**：
   - 将跟随者节点的后半部分添加到 DAG 中，并连接到前一个节点。
6. **添加领导者节点**：
   - 将剩余的节点（即领导者节点）添加到 DAG 中，并连接到前一个节点。

```
updatePolicy, err := getPodUpdatePolicy(its, pod)
if err != nil {
    return kubebuilderx.Continue, err
}
if its.Spec.PodUpdatePolicy == workloads.StrictInPlacePodUpdatePolicyType && updatePolicy == RecreatePolicy {
    message := fmt.Sprintf("InstanceSet %s/%s blocks on update as the PodUpdatePolicy is %s and the pod %s can not inplace update",
       its.Namespace, its.Name, workloads.StrictInPlacePodUpdatePolicyType, pod.Name)
    if tree != nil && tree.EventRecorder != nil {
       tree.EventRecorder.Eventf(its, corev1.EventTypeWarning, EventReasonStrictInPlace, message)
    }
    meta.SetStatusCondition(&its.Status.Conditions, *buildBlockedCondition(its, message))
    isBlocked = true
    break
}
if updatePolicy == InPlaceUpdatePolicy {
    newInstance, err := buildInstanceByTemplate(pod.Name, nameToTemplateMap[pod.Name], its, getPodRevision(pod))
    if err != nil {
       return kubebuilderx.Continue, err
    }
    newPod := copyAndMerge(pod, newInstance.pod)
    if err = tree.Update(newPod); err != nil {
       return kubebuilderx.Continue, err
    }
    updatingPods++
} else if updatePolicy == RecreatePolicy {
    if !isTerminating(pod) {
       if err = tree.Delete(pod); err != nil {
          return kubebuilderx.Continue, err
       }
    }
    updatingPods++
}
```

最后返回一个podsToBeUpdated []*corev1.Pod，其顺序就是Pod更新的顺序

### 滚动升级

#### 初始化变量

- `updatingPods` 和 `updatedPods` 分别记录当前正在更新和已经更新的 Pod 数量。
- `priorities` 通过 `ComposeRolePriorityMap` 函数根据角色（Roles）生成优先级映射。
- `isBlocked` 和 `needRetry` 用于标记更新过程是否被阻塞以及是否需要重试。

```
updatingPods := 0
updatedPods := 0
priorities := ComposeRolePriorityMap(its.Spec.Roles)
isBlocked := false
needRetry := false
sortObjects(oldPodList, priorities, false)
```

#### 计算变量、检查 Pod 状态

```
for _, pod := range oldPodList {
  if updatingPods >= updateCount || updatingPods >= unavailable {
    break
  }
  if updatedPods >= partition {
    break
  }

  if !isContainersReady(pod) {
    tree.Logger.Info(fmt.Sprintf("InstanceSet %s/%s blocks on update as some the container(s) of pod %s are not ready", its.Namespace, its.Name, pod.Name))
    // as no further event triggers the next reconciliation, we need a retry
    needRetry = true
    break
  }
  if !isHealthy(pod) {
    tree.Logger.Info(fmt.Sprintf("InstanceSet %s/%s blocks on update as the pod %s is not healthy", its.Namespace, its.Name, pod.Name))
    break
  }
  if !isRunningAndAvailable(pod, its.Spec.MinReadySeconds) {
    tree.Logger.Info(fmt.Sprintf("InstanceSet %s/%s blocks on update as the pod %s is not available", its.Namespace, its.Name, pod.Name))
    break
  }
  if !isRoleReady(pod, its.Spec.Roles) {
    tree.Logger.Info(fmt.Sprintf("InstanceSet %s/%s blocks on update as the role of pod %s is not ready", its.Namespace, its.Name, pod.Name))
    break
  }

```

#### 处理不同的更新策略

- 如果策略是严格就地更新且 Pod 不能就地更新，则阻塞更新。
- 如果是就地更新，则根据模板构建新的实例，并更新 Pod。
- 如果是重建策略，则删除旧的 Pod 并增加正在更新的 Pod 计数。

并且对于每个Pod执行SwitchOver的策略

```
  updatePolicy, err := getPodUpdatePolicy(its, pod)
  if err != nil {
    return kubebuilderx.Continue, err
  }
  if its.Spec.PodUpdatePolicy == workloads.StrictInPlacePodUpdatePolicyType && updatePolicy == RecreatePolicy {
    message := fmt.Sprintf("InstanceSet %s/%s blocks on update as the PodUpdatePolicy is %s and the pod %s can not inplace update",
      its.Namespace, its.Name, workloads.StrictInPlacePodUpdatePolicyType, pod.Name)
    if tree != nil && tree.EventRecorder != nil {
      tree.EventRecorder.Eventf(its, corev1.EventTypeWarning, EventReasonStrictInPlace, message)
    }
    meta.SetStatusCondition(&its.Status.Conditions, *buildBlockedCondition(its, message))
    isBlocked = true
    break
  }
  if updatePolicy == InPlaceUpdatePolicy {
    newInstance, err := buildInstanceByTemplate(pod.Name, nameToTemplateMap[pod.Name], its, getPodRevision(pod))
    if err != nil {
      return kubebuilderx.Continue, err
    }
    newPod := copyAndMerge(pod, newInstance.pod)
    if err = r.switchover(tree, its, newPod.(*corev1.Pod)); err != nil {
      return kubebuilderx.Continue, err
    }
    if err = tree.Update(newPod); err != nil {
      return kubebuilderx.Continue, err
    }
    updatingPods++
  } else if updatePolicy == RecreatePolicy {
    if !isTerminating(pod) {
      if err = r.switchover(tree, its, pod); err != nil {
        return kubebuilderx.Continue, err
      }
      if err = tree.Delete(pod); err != nil {
        return kubebuilderx.Continue, err
      }
    }
    updatingPods++
  }
  updatedPods++
}
if !isBlocked {
  meta.RemoveStatusCondition(&its.Status.Conditions, string(workloads.InstanceUpdateRestricted))
}
if needRetry {
  return kubebuilderx.RetryAfter(2 * time.Second), nil
}
```



# Commit

流式编程的最后一步就是执行Commit，具体内容如下所示。这里之前提到的Transformer机制的plan几乎一致，都是先生成计划，之后再执行计划。

func (c *controller) Commit() (ctrl.Result, error) {
    defer c.emitFailureEvent()

​    if c.err != nil {
​       return ctrl.Result{}, c.err
​    }
​    if c.oldTree.GetRoot() == nil {
​       return ctrl.Result{}, nil
​    }
​    builder := NewPlanBuilder(c.ctx, c.cli, c.oldTree, c.tree, c.recorder, c.logger)
​    if c.err = builder.Init(); c.err != nil {
​       return ctrl.Result{}, c.err
​    }
​    var plan graph.Plan
​    plan, c.err = builder.Build()
​    if c.err != nil {
​       return ctrl.Result{}, c.err
​    }
​    if c.err = plan.Execute(); c.err != nil {
​       if apierrors.IsConflict(c.err) {
​          return ctrl.Result{Requeue: true}, nil
​       }
​       return ctrl.Result{}, c.err
​    }
​    if c.res.Next == rtry {
​       return ctrl.Result{Requeue: true, RequeueAfter: c.res.RetryAfter}, nil
​    }
​    return ctrl.Result{}, nil
}
