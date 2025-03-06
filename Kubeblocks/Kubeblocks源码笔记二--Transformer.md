# Kubeblocks源码笔记二--Transformer For Cluster

上一章分析了初始的dag是通过各种Transformer来形成最终的DAG的，这里就来解析一下主要Transformer的处理逻辑。

最初的版本采用了每种K8s资源对应一个Controller方式（包括CRD），每种资源在各自的Controller中进行处理。随着开发进度不断推进，这样的架构的弊端逐渐显现出来。

1. 不利于信息共享。由于每个资源会根据各自接受到Request来进行调谐，没有统一的加，往往会重复获取资源。各自定义的结构体也各种各样，无法合理复用
2. 添加一个独立的功能往往涉及到多个Controller，随着功能开发难免遇到多个Controller耦合的问题，这时就需要对大多数资源的处理比较了解，才能保证新功能的开发
3. 排查问题困难，多个Controller耦合在一起就会导致难以定位问题
4. 不同Controller之间的耦合可能会产生大量的资源修改冲突，耗费时间和计算资源
5. ......



Transform以功能为维度抽象出多个Reconciler，不在和K8s资源绑定。



Transform接受TransformContext和初始化的dag作为参数，主要是修改dag的结构和状态。

```
// Transformer transforms a DAG to a new version
type Transformer interface {
	Transform(ctx TransformContext, dag *DAG) error
}
```

获取对象一般使用从TransformContext反序列化出来的graphCli

clusterTransformContext是当前Cluster在本次Reconcile所需要的上下文信息，会在Transformers之间一直传递。

graphCli则用来操作DAG

```
transCtx, _ := ctx.(*clusterTransformContext)
graphCli, _ := transCtx.Client.(model.GraphClient)
```

clusterTransformContext的结构体定义如下

```
// clusterTransformContext a graph.TransformContext implementation for Cluster reconciliation
type clusterTransformContext struct {
    context.Context
    Client client.Reader
    record.EventRecorder
    logr.Logger

    Cluster     *appsv1.Cluster
    OrigCluster *appsv1.Cluster

    clusterDef    *appsv1.ClusterDefinition
    shardingDefs  map[string]*appsv1.ShardingDefinition
    componentDefs map[string]*appsv1.ComponentDefinition

    // consolidated components and shardings from topology and/or user-specified
    components []*appsv1.ClusterComponentSpec
    shardings  []*appsv1.ClusterSharding

    shardingComps map[string][]*appsv1.ClusterComponentSpec // comp specs for each sharding

    // TODO: remove this, annotations to be added to components for sharding, mapping with @allComps.
    annotations map[string]map[string]string
}
```

# clusterDeletionTransformer

主要是处理集群删除时候的逻辑，如果Cluster状态不是deleting就会跳过这一处理逻辑。

## 调用栈

```
|- switch cluster.Spec.TerminationPolicy
|- deleteSet := deleteCompNShardingInOrder4Terminate
|- ml := getAppInstanceML(*cluster)
|- namespacedObjs := getOwningNamespacedObjects
|- delObjs := toDeleteObjs(namespacedObjs)
|- delObjs.append getOwningNonNamespacedObjects
|- for o in delObjs
|  |- graphCli.Delete
```

会根据Cluster的TerminationPolicy来确定处理方式

- DoNotTerminate（禁止终止）阻止删除集群。此策略确保所有资源保持完整。 
- Delete（删除）删除集群资源，如 Pods、Services 和 Persistent Volume Claims（PVCs），从而实现彻底清理并移除所有持久化数据。
- WipeOut（彻底清除）是一种激进的策略，它会删除所有集群资源，包括外部存储

```go
// list all kinds to be deleted based on v1alpha1.TerminationPolicyType
var toDeleteNamespacedKinds, toDeleteNonNamespacedKinds []client.ObjectList
switch cluster.Spec.TerminationPolicy {
case kbappsv1.DoNotTerminate:
  transCtx.EventRecorder.Eventf(cluster, corev1.EventTypeWarning, "DoNotTerminate",
    "spec.terminationPolicy %s is preventing deletion.", cluster.Spec.TerminationPolicy)
  return graph.ErrPrematureStop
case kbappsv1.Delete:
  toDeleteNamespacedKinds, toDeleteNonNamespacedKinds = kindsForDelete()
case kbappsv1.WipeOut:
  toDeleteNamespacedKinds, toDeleteNonNamespacedKinds = kindsForWipeOut()
}
```

负责处理具体的删除逻辑，会通过Labels列举出所有需要删除的资源，并通过graphCli.Delete标记为删除。并等待plan.execute()时实际删除这些资源。

```
// firstly, delete components and shardings in the order that topology defined.
deleteSet, err := deleteCompNShardingInOrder4Terminate(transCtx, dag)

ml := getAppInstanceML(*cluster)
toDeleteObjs := func(objs owningObjects) []client.Object {
  var delObjs []client.Object
  for _, obj := range objs {
    if obj.GetObjectKind().GroupVersionKind().Kind == dptypes.BackupKind {
      backupObj := obj.(*dpv1alpha1.Backup)
      // retain backup for data protection even if the cluster is wiped out.
      if backupObj.Spec.DeletionPolicy == dpv1alpha1.BackupDeletionPolicyRetain {
        continue
      }
    }
    delObjs = append(delObjs, obj)
  }
  return delObjs
}

// add namespaced objects deletion vertex
namespacedObjs, err := getOwningNamespacedObjects(transCtx.Context, transCtx.Client, cluster.Namespace, ml, toDeleteNamespacedKinds)
delObjs := toDeleteObjs(namespacedObjs)

for _, o := range delObjs {
  // skip the objects owned by the component and InstanceSet controller
  if isOwnedByComp(o) || appsutil.IsOwnedByInstanceSet(o) {
    continue
  }
  graphCli.Delete(dag, o, appsutil.InUniversalContext4G())
  delKindMap[o.GetObjectKind().GroupVersionKind().Kind] = sets.Empty{}
}
```

# clusterAssureMetaTransformer

为Cluster添加Finalizer和一些标签

```
if !controllerutil.ContainsFinalizer(cluster, constant.DBClusterFinalizerName) {
    controllerutil.AddFinalizer(cluster, constant.DBClusterFinalizerName)
}

```

# clusterLoadRefResourcesTransformer

>  clusterValidationTransformer validates the cluster spec.

会根据Cluster Spec中**componentDef**， **serviceVersion**还有clusterDefinition，加载并验证当前cluster关联的ClusterDefinition，ComponentVersion还有ComponentDefinition是否存在，以及是否处于available状态。

这里的的字段可以使用正则的方式进行匹配验证，这样可以满足多镜像版本以及Sharding的需求

验证成功后Cluster会置为ProvisioningStarted状态

# clusterSharedAccountTransformer

> clusterShardingAccountTransformer handles shared system accounts for sharding.

处理System Account，如果Sharding中某些SystemAccounts为Shared，则重写SystemAccount。

```
func (t *clusterShardingAccountTransformer) reconcileShardingAccounts(transCtx *clusterTransformContext,
    graphCli model.GraphClient, dag *graph.DAG) error {
    for _, sharding := range transCtx.shardings {
       shardDef, ok := transCtx.shardingDefs[sharding.ShardingDef]
       if ok {
          for _, account := range shardDef.Spec.SystemAccounts {
             if account.Shared != nil && *account.Shared {
                if err := t.reconcileShardingAccount(transCtx, graphCli, dag, sharding, account.Name); err != nil {
                   return err
                }
             }
          }
       }
    }
    return nil
}
```

reconcileShardingAccount的处理逻辑

1. 获取账号相关的secret，不存在就创建
2. rewriteSystemAccount: 使用SecretRef指向新创建的Secret的SystemAccount替换之前的SystemAccount

# ClusterAPINormalizationTransformer

>  clusterNormalizationTransformer handles the cluster API conversion.

将ComponentDefinition和cluster转换到ctx中的ComponentSpecs字段

处理逻辑：

1. 根据cluster中的配置解析出Component或者Sharding
2. 解析Component和Sharding的Definition
3. 生成Sharding对应的Component
4. 校验Component和Sharding的唯一性、Sharding的数量限制等
5. 将解析后的配置写回Cluster Spec

```
// resolve all components and shardings from topology or specified
transCtx.components, transCtx.shardings, err = t.resolveCompsNShardings(transCtx)
if err != nil {
    return err
}

// resolve sharding and component definitions referenced for shardings
if err = t.resolveDefinitions4Shardings(transCtx); err != nil {
    return err
}

// resolve component definitions referenced for components
if err = t.resolveDefinitions4Components(transCtx); err != nil {
    return err
}

if err = t.checkNPatchCRDAPIVersionKey(transCtx); err != nil {
    return err
}

// build component specs for shardings after resolving definitions
transCtx.shardingComps, err = t.buildShardingComps(transCtx)
if err != nil {
    return err
}

if err = t.postcheck(transCtx); err != nil {
    return err
}

// write-back the resolved definitions and service versions to cluster spec.
t.writeBackCompNShardingSpecs(transCtx)
```

## resolveCompsNShardings

对于集群的拓扑结构有两种定义方式有两种定义方式，一种是通过指定ClusterDefinition来确定拓扑，另一种就是直接在CMPD中定义

```
func (t *clusterNormalizationTransformer) resolveCompsNShardings(transCtx *clusterTransformContext) ([]*appsv1.ClusterComponentSpec, []*appsv1.ClusterSharding, error) {
    var (
       cluster = transCtx.Cluster
    )
    if withClusterTopology(cluster) {
       return t.resolveCompsNShardingsFromTopology(transCtx.clusterDef, cluster)
    }
    if withClusterUserDefined(cluster) {
       return t.resolveCompsNShardingsFromSpecified(transCtx, cluster)
    }
    return nil, nil, nil
}
```

## resolveDefinitions4Shardings

Sharding是通过Component的方式来实现的，即不同的Sharding会成为不同的组件。这一步就是将Sharding转换为Component

```
func (t *clusterNormalizationTransformer) resolveShardingNCompDefinition(transCtx *clusterTransformContext,
	sharding *appsv1.ClusterSharding) (*appsv1.ShardingDefinition, *appsv1.ComponentDefinition, string, error) {
	comp, err := t.firstShardingComponent(transCtx, sharding)
	if err != nil {
		return nil, nil, "", err
	}

	var shardingDef *appsv1.ShardingDefinition
	shardingDefName := t.shardingDefinitionName(sharding, comp)
	if len(shardingDefName) > 0 {
		shardingDef, err = resolveShardingDefinition(transCtx.Context, transCtx.Client, shardingDefName)
		if err != nil {
			return nil, nil, "", err
		}
	}

	spec := sharding.Template
	compDef, serviceVersion, err := t.resolveCompDefinitionNServiceVersionWithComp(transCtx, &spec, comp)
	if err != nil {
		return nil, nil, "", err
	}

	return shardingDef, compDef, serviceVersion, err
}
```

# clusterPlacementTransformer(WIP)

多k8s集群架构下根据KBAppMultiClusterPlacementKey这个Anno确定cluster被显式分配的位置

这里和多Kubernetes集群部署模式有关，目前Kubeblocks采用的多Kubernetes方案为Cillium的cluster_mesh

```
func (t *clusterPlacementTransformer) Transform(ctx graph.TransformContext, dag *graph.DAG) error {
    transCtx, _ := ctx.(*clusterTransformContext)
    if model.IsObjectDeleting(transCtx.OrigCluster) {
       return nil
    }

    if t.multiClusterMgr == nil {
       return nil // do nothing
    }

    if t.assigned(transCtx) {
       transCtx.Context = appsutil.IntoContext(transCtx.Context, appsutil.Placement(transCtx.OrigCluster))
       return nil
    }

    p := t.assign(transCtx)

    cluster := transCtx.Cluster
    if cluster.Annotations == nil {
       cluster.Annotations = make(map[string]string)
    }
    cluster.Annotations[constant.KBAppMultiClusterPlacementKey] = strings.Join(p, ",")
    transCtx.Context = appsutil.IntoContext(transCtx.Context, appsutil.Placement(cluster))

    return nil
}
```



# clusterServiceTransformer

处理cluster维度的Services

首先通过Labels 来list所有属于当前Cluster的Service，并且根据Cluster中的Service来创建期望的Service。

之后通过比较二者差别增删改Service

```go
services, err := t.listOwnedClusterServices(transCtx, cluster)
if err != nil {
    return err
}

protoServices, err := t.buildClusterServices(transCtx, cluster)
if err != nil {
    return err
}

toCreateServices, toDeleteServices, toUpdateServices := mapDiff(services, protoServices)

for svc := range toCreateServices {
    graphCli.Create(dag, protoServices[svc], inDataContext4G())
}
for svc := range toUpdateServices {
    t.updateService(dag, graphCli, services[svc], protoServices[svc])
}
for svc := range toDeleteServices {
    graphCli.Delete(dag, services[svc], inDataContext4G())
```



# clusterRestoreTransformer（WIP）

处理备份恢复时，sharding状态下恢复流程的某些逻辑

如果Cluster是从备份中恢复的话， 会进入该Transformer的处理逻辑

备份的集群数据以json的形式保存在kubeblocks.io/restore-from-backup的Anno当中

结构为map[CompName]map[name && namespace]Backupname

即通过CompName可以获取到backuName和namespace信息，这样就可以获取到Backup的实例



对于Sharding来说



如果该Component需要执行post ready restore，则在Component中添加Anno

# clusterComponentTransformer

> clusterComponentTransformer transforms components and shardings to mapping Component objects

根据cluster的ComponentSpecs增删改component CR

```
func (t *clusterComponentTransformer) Transform(ctx graph.TransformContext, dag *graph.DAG) error {
    updateToDate, err := checkAllCompsUpToDate(transCtx, transCtx.Cluster)

    // if the cluster is not updating and all components are up-to-date, skip the reconciliation
    if !transCtx.OrigCluster.IsUpdating() && updateToDate {
       return nil
    }

    return t.transform(transCtx, dag)
}
```

这里Sharding和Component都会被当做Component来处理，创建出具体的Component CR，之后的逻辑就将交给Component的Reconcile过程来完成

```
func (t *clusterComponentTransformer) transform(transCtx *clusterTransformContext, dag *graph.DAG) error {
	runningSet, err := t.runningSet(transCtx)
	if err != nil {
		return err
	}
	protoSet := t.protoSet(transCtx)

	createSet, deleteSet, updateSet := setDiff(runningSet, protoSet)

	if err := deleteCompNShardingInOrder(transCtx, dag, deleteSet, pointer.Bool(true)); err != nil {
		return err
	}

	var delayedErr error
	if err := t.handleUpdate(transCtx, dag, updateSet); err != nil {
		if !ictrlutil.IsDelayedRequeueError(err) {
			return err
		}
		delayedErr = err
	}

	if err := t.handleCreate(transCtx, dag, createSet); err != nil {
		return err
	}

	return delayedErr
}
```



# clusterComponentStatusTransformer

处理cluster的status中所有Component状态，并更新到Cluster的Status.Components中

```
func (t *clusterComponentStatusTransformer) transform(transCtx *clusterTransformContext) error {
    comps, shardingComps, err := t.listClusterComponents(transCtx)
    if err != nil {
       return err
    }

    t.transformCompStatus(transCtx, comps)
    t.transformShardingStatus(transCtx, shardingComps)

    return nil
}
```

# clusterBackupPolicyTransformer

将backup policy template转换为backup policy 和 backup schedule

```
transformBackupPolicy := func(bpBuilder *backupPolicyBuilder) *dpv1alpha1.BackupPolicy {
    // build the data protection backup policy from the template.
    oldBackupPolicy, newBackupPolicy := bpBuilder.transformBackupPolicy()
    if newBackupPolicy == nil {
       return nil
    }
    if oldBackupPolicy == nil {
       graphCli.Create(dag, newBackupPolicy)
    } else {
       graphCli.Patch(dag, oldBackupPolicy, newBackupPolicy)
    }
    return newBackupPolicy
}

transformBackupSchedule := func(bpBuilder *backupPolicyBuilder, backupPolicy *dpv1alpha1.BackupPolicy) {
    // if backup policy is nil, it means that the backup policy template
    // is invalid, backup schedule depends on backup policy, so we do
    // not need to transform backup schedule.
    if backupPolicy == nil {
       return
    }
    // build the data protection backup schedule from the template.
    oldBackupSchedule, newBackupSchedule := bpBuilder.transformBackupSchedule(backupPolicy)
    // merge cluster backup configuration into the backup schedule.
    // If the backup schedule is nil, create a new backup schedule
    // based on the cluster backup configuration.
    // For a cluster, the default backup schedule is created by backup
    // policy template, user can also configure cluster backup in the
    // cluster custom object, such as enable cluster backup, set backup
    // schedule, etc.
    // We always prioritize the cluster backup configuration in the
    // cluster object, so we need to merge the cluster backup configuration
    // into the default backup schedule created by backup policy template
    // if it exists.
    newBackupSchedule = bpBuilder.mergeClusterBackup(backupPolicy, newBackupSchedule)
    if newBackupSchedule == nil {
       return
    }
    if oldBackupSchedule == nil {
       graphCli.Create(dag, newBackupSchedule)
    } else {
       graphCli.Patch(dag, oldBackupSchedule, newBackupSchedule)
    }
    graphCli.DependOn(dag, backupPolicy, newBackupSchedule)
    comps := graphCli.FindAll(dag, &appsv1.Component{})
    graphCli.DependOn(dag, backupPolicy, comps...)
}
```

# clusterOwnershipTransformer

通过graphCli为DAG中所有cluster关联的对象添加finalizer

```
objects := graphCli.FindAll(dag, &appsv1.Cluster{}, &model.HaveDifferentTypeWithOption{})

controllerutil.AddFinalizer(cluster, constant.DBClusterFinalizerName)
for _, object := range objects {
    if err := intctrlutil.SetOwnership(cluster, object, model.GetScheme(), constant.DBClusterFinalizerName); err != nil {
       if _, ok := err.(*controllerutil.AlreadyOwnedError); ok {
          continue
       }
       return err
    }
}
```

# clusterStatusTransforme

调谐cluster的Status

```
switch {
case origCluster.IsUpdating():
    transCtx.Logger.Info(fmt.Sprintf("update cluster status after applying resources, generation: %d", cluster.Generation))
    cluster.Status.ObservedGeneration = cluster.Generation
    t.markClusterDagStatusAction(graphCli, dag, origCluster, cluster)
case origCluster.IsStatusUpdating():
    defer func() { t.markClusterDagStatusAction(graphCli, dag, origCluster, cluster) }()
    // reconcile the phase and conditions of the cluster.status
    if err := t.reconcileClusterStatus(transCtx, cluster); err != nil {
       return err
    }
case origCluster.IsDeleting():
    return fmt.Errorf("unexpected cluster status: %s", origCluster.Status.Phase)
default:
    panic(fmt.Sprintf("runtime error - unknown cluster status: %+v", origCluster))
}
```