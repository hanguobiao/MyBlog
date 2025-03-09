备份恢复是数据的的重要功能，也是数据安全的重要保障。备份恢复和配置类似，属于一个相对独立的模块。用户通过声明CRD（backupolicy、backup等）定义一个期望的备份状态，之后由相应的Operator来完成调谐过程。

支持多种存储后端（如S3、NFS、PV等），通过统一接口适配不同存储方案。

# API设计

#### **1. `BackupPolicy`（备份策略）**

**功能**：定义如何执行备份（备份方法、存储位置、保留策略等）。
 **核心字段结构**：

```
apiVersion: kubeblocks.io/v1alpha1
kind: BackupPolicy
metadata:
  name: mysql-backup-policy
spec:
  # 关联的数据库集群
  clusterRef:
    name: mysql-cluster
    namespace: default
  
  # 备份方法（物理备份/逻辑备份）
  method: physical
  
  # 存储配置
  storage:
    provider: s3  # 支持s3、nfs、pv等
    bucket: my-backup-bucket
    region: us-west-1
    secretRef: s3-credentials  # 存储访问凭证
  
  # 保留策略
  retention:
    maxRetentionDays: 30
    maxRetentionCount: 10
  
  # 备份一致性配置
  consistency:
    snapshotBeforeBackup: true  # 是否创建快照
    lockTables: true  # 是否锁定表（逻辑备份）
  
  # 加密配置
  encryption:
    enabled: true
    keyRef: encryption-key
```

**设计思路**：

- **多存储适配**：通过`storage.provider`字段抽象存储后端，支持扩展。
- **策略与执行分离**：`BackupPolicy`仅定义策略，具体备份实例由`Backup`资源描述。
- **数据库引擎感知**：根据`clusterRef`自动识别数据库类型，选择合适备份工具（如`mysqldump`、`pg_basebackup`）。

------

#### **2. `BackupSchedule`（备份计划）**

**功能**：定义定时备份规则（类似CronJob）。
 **结构示例**：

```
apiVersion: kubeblocks.io/v1alpha1
kind: BackupSchedule
metadata:
  name: daily-backup
spec:
  schedule: "0 2 * * *"  # 每天凌晨2点执行
  backupPolicyTemplateRef: mysql-backup-policy  # 引用的BackupPolicy
  successfulJobsHistoryLimit: 5  # 保留的备份记录数
```

**设计思路**：

- **解耦策略与调度**：通过引用`BackupPolicy`实现策略复用。
- **历史记录管理**：自动清理旧备份，避免存储浪费。

------

#### **3. `Backup`（备份实例）**

**功能**：描述一次具体的备份操作，通常由`BackupSchedule`或手动触发生成。
 **结构示例**：

```
apiVersion: kubeblocks.io/v1alpha1
kind: Backup
metadata:
  name: mysql-backup-20231001
spec:
  backupPolicyRef: mysql-backup-policy
  # 可选覆盖策略中的参数（如临时修改存储位置）
  storage:
    bucket: temporary-bucket
status:
  phase: Completed  # 状态（Pending/Running/Completed/Failed）
  startTime: "2023-10-01T02:00:00Z"
  completionTime: "2023-10-01T02:15:00Z"
  size: 5GiB
  location: s3://my-backup-bucket/mysql-20231001.tar
  snapshotName: mysql-snapshot-123  # 关联的VolumeSnapshot（如有）
```

**设计思路**：

- **生命周期管理**：通过`status.phase`跟踪备份状态，支持重试机制。
- **可观测性**：记录备份大小、耗时、存储路径等元数据。
- **临时覆盖**：允许在单个备份实例中覆盖策略参数，提供灵活性。

------

#### **4. `Restore`（恢复操作）**

**功能**：从备份中恢复数据库集群。
 **结构示例**：

```
apiVersion: kubeblocks.io/v1alpha1
kind: Restore
metadata:
  name: mysql-restore-20231001
spec:
  backupRef: mysql-backup-20231001  # 引用的Backup资源
  clusterRef:
    name: mysql-cluster-new  # 恢复到新集群
  # 恢复参数（如时间点恢复）
  pitr:
    targetTime: "2023-10-01T02:10:00Z"
  # 冲突解决策略
  conflictPolicy: Replace  # 替换现有数据
```

**设计思路**：

- **跨集群恢复**：支持恢复到新集群，实现灾备。
- **时间点恢复（PITR）**：结合WAL日志实现细粒度恢复。
- **原子性操作**：确保恢复过程事务化，失败时自动回滚。

# 流程

1. 创建BackupRepo，一般是以S3为后端，用来存储备份的文件，通过StorageProvider指定存储后端以及交互参数
2. 为Component配置BackupPolicy、BackupPolicyTemplate、BackupSchedule、ActionSet等备份相关的CR
3. 等到Component创建完毕，创建Backup CR开始实际的备份liuch
4. 等到手动触发或者自动备份的Backup完成，在需要的时候通过restore CR开始恢复工作，创建一个新的集群并恢复数据

# Dataprotection

Dataprotection和Kubeblocks一样属于多个 CRD Controller的集合，但是通过不同的Deployment部署，所以你甚至可以卸载Kubeblocks，单独保留Dataprotection，避免已经完成的备份被删除

正如其名，Dataprotection起到了备份恢复的作用

```
if err = (&dpcontrollers.ActionSetReconciler{
    Client:   mgr.GetClient(),
    Scheme:   mgr.GetScheme(),
    Recorder: mgr.GetEventRecorderFor("actionset-controller"),
}).SetupWithManager(mgr); err != nil {
    setupLog.Error(err, "unable to create controller", "controller", "ActionSet")
    os.Exit(1)
}

if err = (&dpcontrollers.BackupReconciler{
    Client:     mgr.GetClient(),
    Scheme:     mgr.GetScheme(),
    Recorder:   mgr.GetEventRecorderFor("backup-controller"),
    RestConfig: mgr.GetConfig(),
}).SetupWithManager(mgr); err != nil {
    setupLog.Error(err, "unable to create controller", "controller", "Backup")
    os.Exit(1)
}

if err = (&dpcontrollers.RestoreReconciler{
    Client:   mgr.GetClient(),
    Scheme:   mgr.GetScheme(),
    Recorder: mgr.GetEventRecorderFor("restore-controller"),
}).SetupWithManager(mgr); err != nil {
    setupLog.Error(err, "unable to create controller", "controller", "Restore")
    os.Exit(1)
}

if err = (&dpcontrollers.VolumePopulatorReconciler{
    Client:   mgr.GetClient(),
    Scheme:   mgr.GetScheme(),
    Recorder: mgr.GetEventRecorderFor("volume-populator-controller"),
}).SetupWithManager(mgr); err != nil {
    setupLog.Error(err, "unable to create controller", "controller", "VolumePopulator")
    os.Exit(1)
}

if err = (&dpcontrollers.BackupPolicyReconciler{
    Client:   mgr.GetClient(),
    Scheme:   mgr.GetScheme(),
    Recorder: mgr.GetEventRecorderFor("backup-policy-controller"),
}).SetupWithManager(mgr); err != nil {
    setupLog.Error(err, "unable to create controller", "controller", "BackupPolicy")
    os.Exit(1)
}

if err = (&dpcontrollers.BackupScheduleReconciler{
    Client:   dputils.NewCompatClient(mgr.GetClient()),
    Scheme:   mgr.GetScheme(),
    Recorder: mgr.GetEventRecorderFor("backup-schedule-controller"),
}).SetupWithManager(mgr); err != nil {
    setupLog.Error(err, "unable to create controller", "controller", "BackupSchedule")
    os.Exit(1)
}

if err = (&dpcontrollers.BackupPolicyTemplateReconciler{
    Client:   mgr.GetClient(),
    Scheme:   mgr.GetScheme(),
    Recorder: mgr.GetEventRecorderFor("backup-policy-template-controller"),
}).SetupWithManager(mgr); err != nil {
    setupLog.Error(err, "unable to create controller", "controller", "BackupPolicyTemplate")
    os.Exit(1)
}

if err = (&dpcontrollers.BackupRepoReconciler{
    Client:          client,
    Scheme:          mgr.GetScheme(),
    Recorder:        mgr.GetEventRecorderFor("backup-repo-controller"),
    RestConfig:      mgr.GetConfig(),
    MultiClusterMgr: multiClusterMgr,
}).SetupWithManager(mgr); err != nil {
    setupLog.Error(err, "unable to create controller", "controller", "BackupRepo")
    os.Exit(1)
}

if err = (&dpcontrollers.StorageProviderReconciler{
    Client:          client,
    Scheme:          mgr.GetScheme(),
    Recorder:        mgr.GetEventRecorderFor("storage-provider-controller"),
    MultiClusterMgr: multiClusterMgr,
}).SetupWithManager(mgr); err != nil {
    setupLog.Error(err, "unable to create controller", "controller", "StorageProvider")
    os.Exit(1)
}

if err = (&dpcontrollers.LogCollectionReconciler{
    Client:     mgr.GetClient(),
    Scheme:     mgr.GetScheme(),
    Recorder:   mgr.GetEventRecorderFor("log-collection-controller"),
    RestConfig: mgr.GetConfig(),
}).SetupWithManager(mgr); err != nil {
    setupLog.Error(err, "unable to create controller", "controller", "logCollectionController")
    os.Exit(1)
}

if err = dpcontrollers.NewGCReconciler(mgr).SetupWithManager(mgr); err != nil {
    setupLog.Error(err, "unable to create controller", "controller", "GarbageCollection")
    os.Exit(1)
}
```

# 实现逻辑

## BackupRepo

BackupRepo是备份仓库的抽象，

### 1.处理BackupRepo CR

获取BackupRepo，添加finalizer，添加references

```
r.providerRefMapper.setRef(repo, types.NamespacedName{Name: repo.Spec.StorageProviderRef})
```

```
// refObjectMapper is a helper struct that maintains the mapping between referent objects and referenced objects.
// A referent object is an object that has a reference to another object in its spec.
// A referenced object is an object that is referred by one or more referent objects.
// It is mainly used in the controller Watcher() to trigger the reconciliation of the
// objects that have references to other objects when those objects change.
// For example, if object A has a reference to object B, and object B changes,
// the refObjectMapper can generate a request for object A to be reconciled.
type refObjectMapper struct {
    mu     sync.Mutex
    once   sync.Once
    ref    map[string]string   // key is the referent, value is the referenced object.
    invert map[string][]string // invert map, key is the referenced object, value is the list of referent.
}
```

### 2.创建备份的Provider

Provider就是和具体的备份存储后端如何交互的模版，以S3为例，就是定义了需要哪些参数来和S3交互，以及一些校验

```
provider, err := r.checkStorageProvider(reqCtx, repo)
if err != nil {
    _ = r.updateStatus(reqCtx, repo)
    return checkedRequeueWithError(err, reqCtx.Log, "check storage provider status failed")
}

// check parameters for rendering templates
parameters, err := r.checkParameters(reqCtx, repo, provider)
if err != nil {
    _ = r.updateStatus(reqCtx, repo)
    return checkedRequeueWithError(err, reqCtx.Log, "check parameters failed")
}
```

### 3.相关Object处理和连接验证

**初始化 `reconcileContext` 结构体**：

**创建sc和secret**：

**检查 PVC 模板**

**预检查仓库**

```
// create StorageClass and Secret for the CSI driver
err = r.createStorageClassAndSecret(reconCtx)
if err != nil {
    _ = r.updateStatus(reqCtx, repo)
    return checkedRequeueWithError(err, reqCtx.Log,
       "failed to create storage class and secret")
}

// check PVC template
err = r.checkPVCTemplate(reconCtx)
if err != nil {
    _ = r.updateStatus(reqCtx, repo)
    return checkedRequeueWithError(err, reqCtx.Log,
       "failed to check PVC template")
}

// pre-check the repo by running a real job
if repo.Status.Phase != dpv1alpha1.BackupRepoDeleting {
    err = r.preCheckRepo(reconCtx)
    if err != nil {
       _ = r.updateStatus(reqCtx, repo)
       return checkedRequeueWithError(err, reqCtx.Log, "failed to pre-check")
    }
}

// update status phase to ready if all conditions are met
if err = r.updateStatus(reqCtx, repo); err != nil {
    return checkedRequeueWithError(err, reqCtx.Log,
       "failed to update BackupRepo status")
}

if reconCtx.preCheckFinished() {
    // clear pre-check resources
    if err := r.removePreCheckResources(reconCtx); err != nil {
       return checkedRequeueWithError(err, reqCtx.Log,
          "failed to remove pre-check resources")
    }
}

if repo.Status.Phase == dpv1alpha1.BackupRepoReady {
    // update tool config if needed
    err = r.updateToolConfigSecrets(reconCtx)
    if err != nil {
       return checkedRequeueWithError(err, reqCtx.Log,
          "failed to update tool config secrets")
    }

    // check associated backups, to create PVC in their namespaces
    if err = r.prepareForAssociatedBackups(reconCtx); err != nil {
       return checkedRequeueWithError(err, reqCtx.Log,
          "check associated backups failed")
    }

    // check associated restores, to create PVC in their namespaces
    if err = r.prepareForAssociatedRestores(reconCtx); err != nil {
       return checkedRequeueWithError(err, reqCtx.Log,
          "check associated restores failed")
    }
}
```

## 备份配置

这部分的Controller主要是验证CR的合法性，不再赘述

## Backup

正确创建一个Backup就一意味着备份流程正式开始

核心流程就是根据backup.Status.Phase做不同处理，并修改其状态（这也是之前版本的Kubeblocks最常用的办法）

```
switch backup.Status.Phase {
case "", dpv1alpha1.BackupPhaseNew:
    return r.handleNewPhase(reqCtx, backup)
case dpv1alpha1.BackupPhaseRunning:
    return r.handleRunningPhase(reqCtx, backup)
case dpv1alpha1.BackupPhaseCompleted:
    return r.handleCompletedPhase(reqCtx, backup)
case dpv1alpha1.BackupPhaseDeleting:
    return r.handleDeletingPhase(reqCtx, backup)
case dpv1alpha1.BackupPhaseFailed:
    if backup.Labels[dptypes.BackupTypeLabelKey] == string(dpv1alpha1.BackupTypeContinuous) {
       if backup.Status.StartTimestamp.IsZero() {
          // if the backup fails in the 'New' phase, reconcile it from 'New' phase handler.
          return r.handleNewPhase(reqCtx, backup)
       }
       return r.handleRunningPhase(reqCtx, backup)
    }
    return intctrlutil.Reconciled()
default:
    return intctrlutil.Reconciled()
}
```

### ""，BackupPhaseNew -> handleNewPhase

#### 初始化备份请求

```
request, err := r.prepareBackupRequest(reqCtx, backup)
```

```
type Request struct {
    *dpv1alpha1.Backup
    intctrlutil.RequestCtx

    Client               client.Client
    BackupPolicy         *dpv1alpha1.BackupPolicy
    BackupMethod         *dpv1alpha1.BackupMethod
    ActionSet            *dpv1alpha1.ActionSet
    TargetPods           []*corev1.Pod
    BackupRepoPVC        *corev1.PersistentVolumeClaim
    BackupRepo           *dpv1alpha1.BackupRepo
    ToolConfigSecret     *corev1.Secret
    WorkerServiceAccount string
    SnapshotVolumes      bool
    Target               *dpv1alpha1.BackupTarget
    ParentBackup         *dpv1alpha1.Backup
    BaseBackup           *dpv1alpha1.Backup
}
```

#### 持久化备份信息

将需要备份的信息持久化到status.target，包含了

status.target 的示例如下

```
 target:
    connectionCredential:
      passwordKey: password
      secretName: mongo-friety-mongodb-account-root
      usernameKey: username
    podSelector:
      fallbackLabelSelector:
        matchLabels:
          app.kubernetes.io/instance: mongo-friety
          app.kubernetes.io/managed-by: kubeblocks
          apps.kubeblocks.io/component-name: mongodb
          kubeblocks.io/role: primary
      matchLabels:
        app.kubernetes.io/instance: mongo-friety
        app.kubernetes.io/managed-by: kubeblocks
        apps.kubeblocks.io/component-name: mongodb
        kubeblocks.io/role: secondary
      strategy: Any
    selectedTargetPods:
    - mongo-friety-mongodb-1
```

#### 元数据处理

为backup添加labels, annotations and finalizers

如果Backup被修改，则通过patch修改

```
// PatchBackupObjectMeta patches backup object metaObject include cluster snapshot.
func PatchBackupObjectMeta(
    original *dpv1alpha1.Backup,
    request *dpbackup.Request) (bool, error) {
    targetPod := request.TargetPods[0]

    // get KubeBlocks cluster and set labels and annotations for backup
    // TODO(ldm): we should remove this dependency of cluster in the future
    cluster := getCluster(request.Ctx, request.Client, targetPod)
    if cluster != nil {
       if err := setClusterSnapshotAnnotation(request, cluster); err != nil {
          return false, err
       }
       if err := setEncryptedSystemAccountsAnnotation(request, cluster); err != nil {
          return false, err
       }
       request.Labels[dptypes.ClusterUIDLabelKey] = string(cluster.UID)
    }

    for _, v := range getClusterLabelKeys() {
       if labelValue, ok := targetPod.Labels[v]; ok {
          request.Labels[v] = labelValue
       }
    }

    if _, ok := request.Labels[constant.AppManagedByLabelKey]; !ok {
       request.Labels[constant.AppManagedByLabelKey] = dptypes.AppName
    }
    request.Labels[dptypes.BackupTypeLabelKey] = request.GetBackupType()
    request.Labels[dptypes.BackupPolicyLabelKey] = request.Spec.BackupPolicyName
    // wait for the backup repo controller to prepare the essential resource.
    wait := false
    if request.BackupRepo != nil {
       request.Labels[dataProtectionBackupRepoKey] = request.BackupRepo.Name
       if (request.BackupRepo.AccessByMount() && request.BackupRepoPVC == nil) ||
          (request.BackupRepo.AccessByTool() && request.ToolConfigSecret == nil) {
          request.Labels[dataProtectionWaitRepoPreparationKey] = trueVal
          wait = true
       }
    }

    // set finalizer
    controllerutil.AddFinalizer(request.Backup, dptypes.DataProtectionFinalizerName)

    if reflect.DeepEqual(original.ObjectMeta, request.ObjectMeta) {
       return wait, nil
    }

    return wait, request.Client.Patch(request.Ctx, request.Backup, client.MergeFrom(original))
}
```

#### 修改Status

将其他备份需要的信息持久化到Status当中，包括备份时的具体行为--actionSet

修改Status.Phase为running

```
func (r *BackupReconciler) patchBackupStatus(
    original *dpv1alpha1.Backup,
    request *dpbackup.Request) error {
    request.Status.FormatVersion = dpbackup.FormatVersion
    if !request.SnapshotVolumes {
       request.Status.Path = dpbackup.BuildBaseBackupPath(
          request.Backup, request.BackupRepo.Spec.PathPrefix, request.BackupPolicy.Spec.PathPrefix)
    }
    request.Status.BackupMethod = request.BackupMethod
    if request.BackupRepo != nil {
       request.Status.BackupRepoName = request.BackupRepo.Name
    }
    if request.BackupRepoPVC != nil {
       request.Status.PersistentVolumeClaimName = request.BackupRepoPVC.Name
    }
    if !request.SnapshotVolumes && request.BackupPolicy.Spec.UseKopia {
       request.Status.KopiaRepoPath = dpbackup.BuildKopiaRepoPath(
          request.Backup, request.BackupRepo.Spec.PathPrefix, request.BackupPolicy.Spec.PathPrefix)
    }
    if request.BackupPolicy.Spec.EncryptionConfig != nil {
       request.Status.EncryptionConfig = request.BackupPolicy.Spec.EncryptionConfig
    }
    // init action status
    actions, err := request.BuildActions()
    if err != nil {
       return err
    }
    for targetPodName, acts := range actions {
       for _, act := range acts {
          request.Status.Actions = append(request.Status.Actions, dpv1alpha1.ActionStatus{
             Name:          act.GetName(),
             TargetPodName: targetPodName,
             Phase:         dpv1alpha1.ActionPhaseNew,
             ActionType:    act.Type(),
          })
       }
    }

    // update phase to running
    request.Status.Phase = dpv1alpha1.BackupPhaseRunning
    request.Status.StartTimestamp = &metav1.Time{Time: r.clock.Now().UTC()}

    // set status parent backup and base backup name
    if request.ParentBackup != nil {
       request.Status.ParentBackupName = request.ParentBackup.Name
    }
    if request.BaseBackup != nil {
       request.Status.BaseBackupName = request.BaseBackup.Name
    }

    if err = dpbackup.SetExpirationByCreationTime(request.Backup); err != nil {
       return err
    }
    return r.Client.Status().Patch(request.Ctx, request.Backup, client.MergeFrom(original))
}
```

### BackupPhaseRunning -> handleRunningPhase

#### 初始化所需信息

```
request, err := r.prepareBackupRequest(reqCtx, backup)
```

#### 执行ActionSet

根据之前持久化的Backup状态来实际执行备份操作

根据每个actionSet的执行情况修改actionSet的Status

```go
for i := range targets {
    if err = r.prepareRequestTargetInfo(reqCtx, request, &targets[i]); err != nil {
       return r.updateStatusIfFailed(reqCtx, backup, request.Backup, err)
    }
    // there are actions not completed, continue to handle following actions
    actions, err := request.BuildActions()
    if err != nil {
       return r.updateStatusIfFailed(reqCtx, backup, request.Backup, err)
    }
    // check all actions status, if any action failed, update backup status to failed
    // if all actions completed, update backup status to completed, otherwise,
    // continue to handle following actions.
    for targetPodName, acts := range actions {
    actions:
       for _, act := range acts {
          status, err := act.Execute(actionCtx)
          if err != nil {
             return r.updateStatusIfFailed(reqCtx, backup, request.Backup, err)
          }
          status.TargetPodName = targetPodName
          mergeActionStatus(request, status)
          switch status.Phase {
          case dpv1alpha1.ActionPhaseCompleted:
             updateBackupStatusByActionStatus(&request.Status)
             continue
          case dpv1alpha1.ActionPhaseFailed:
             existFailedAction = true
             break actions
          case dpv1alpha1.ActionPhaseRunning:
             // update status
             if err = r.Client.Status().Patch(reqCtx.Ctx, request.Backup, client.MergeFrom(backup)); err != nil {
                return intctrlutil.CheckedRequeueWithError(err, reqCtx.Log, "")
             }
             waiting = true
             break actions
          }
       }
    }
}
```

#### 执行备份

这里具体执行的action结构定义如下

```
type Action interface {
    // Execute executes the action.
    Execute(actCtx ActionContext) (*dpv1alpha1.ActionStatus, error)

    // GetName returns the Name of the action.
    GetName() string

    // Type returns the type of the action.
    Type() dpv1alpha1.ActionType
}
```

支持四种备份方式

- CreateVolumeSnapshotAction
- ExecAction
- JobAction
- StatefulSetAction

##### CreateVolumeSnapshotAction

通过K8s的VolumeSnapshot机制备份整个Volume的方式备份数据

VolumeSnapshot：https://kubernetes.io/zh-cn/docs/concepts/storage/volume-snapshots/

```
for _, w := range c.PersistentVolumeClaimWrappers {
		err = c.createVolumeSnapshotIfNotExist(actCtx, &w.PersistentVolumeClaim, key);
		ok, snap, err = ensureVolumeSnapshotReady(actCtx.Ctx, actCtx.Client, key)
}
```

createVolumeSnapshotIfNotExist通过指定pvc的name来发起对应PV的快照

```
snap := &vsv1.VolumeSnapshot{}
exists, err := intctrlutil.CheckResourceExists(ctx.Ctx, ctx.Client, key, snap)

// create volume snapshot
snap = &vsv1.VolumeSnapshot{
  ObjectMeta: c.ObjectMeta,
  Spec: vsv1.VolumeSnapshotSpec{
    Source: vsv1.VolumeSnapshotSource{
      PersistentVolumeClaimName: &pvc.Name,
    },
  },
}

if err = ctx.Client.Create(ctx.Ctx, snap); err != nil {
  return err
}
```

##### ExecAction

通过Job的方式执行备份，构建一个image为Kubeblocks-tools的PodSpec，并据此创建Job

```
if err := e.validate(); err != nil {
    return nil, err
}
e.JobAction.PodSpec = e.buildPodSpec()
return e.JobAction.Execute(ctx)
```

Job执行的指令为通过Kubectl在对应的Pod中执行actionSet中的命令，这样就实际上等价于在目标Pod中执行命令

```
container := &corev1.Container{
    Name:            e.Name,
    Image:           viper.GetString(constant.KBToolsImage),
    ImagePullPolicy: corev1.PullPolicy(viper.GetString(constant.KBImagePullPolicy)),
    Command:         []string{"kubectl"},
    Args: append([]string{
       "-n",
       e.Namespace,
       "exec",
       e.PodName,
       "-c",
       e.Container,
       "--",
    }, e.Command...),
}
```

JobAction.Execute会生成Job并Create。如果已经存在，就根据Job的状态确定actionSet的状态

```
original := batchv1.Job{}
exists, err := ctrlutil.CheckResourceExists(actCtx.Ctx, actCtx.Client, key, &original)
if err != nil {
    return handleErr(err)
}

// job exists, check job status and set action status accordingly
if exists {
    objRef, _ := ref.GetReference(actCtx.Scheme, &original)
    sb = sb.startTimestamp(&original.CreationTimestamp).objectRef(objRef)
    _, finishedType, msg := utils.IsJobFinished(&original)
    switch finishedType {
    case batchv1.JobComplete:
       return sb.phase(dpv1alpha1.ActionPhaseCompleted).
          completionTimestamp(nil).
          build(), nil
    case batchv1.JobFailed:
       return sb.phase(dpv1alpha1.ActionPhaseFailed).
          completionTimestamp(nil).
          reason(msg).
          build(), nil
    }
    // job is running
    return handleErr(nil)
}

// job doesn't exist, create it
job := &batchv1.Job{
    ObjectMeta: j.ObjectMeta,
    Spec: batchv1.JobSpec{
       Template: corev1.PodTemplateSpec{
          ObjectMeta: j.ObjectMeta,
          Spec:       *j.PodSpec,
       },
       BackoffLimit: j.BackOffLimit,
    },
}

controllerutil.AddFinalizer(job, types.DataProtectionFinalizerName)
if job.Namespace == j.Owner.GetNamespace() {
    if err = utils.SetControllerReference(j.Owner, job, actCtx.Scheme); err != nil {
       return handleErr(err)
    }
}
msg := fmt.Sprintf("creating job %s/%s", job.Namespace, job.Name)
actCtx.Recorder.Event(j.Owner, corev1.EventTypeNormal, "CreatingJob", msg)
return handleErr(client.IgnoreAlreadyExists(actCtx.Client.Create(actCtx.Ctx, job)))
```

##### JobAction

ExecAction调用的就是JobAction

##### StatefulSetAction

与Job类似，创建StatusfulSet来处理备份逻辑。Job一般用于处理单次备份，而Statefulset可以处理持续备份的情况，类似于增量备份。

#### 更新Status

根据所有actionSet是否成功来更新状态到completed或者failed



### BackupPhaseCompleted -> handleCompletedPhase

清理用不到的相关Object。包括执行actionSet时生成的Jobs和Statefulset，通过Labels匹配并删除

```
err := r.deleteExternalResources(reqCtx, backup)
```

```
func (r *BackupReconciler) deleteExternalResources(
    reqCtx intctrlutil.RequestCtx, backup *dpv1alpha1.Backup) error {
    labels := dpbackup.BuildBackupWorkloadLabels(backup)

    // use map to avoid duplicate deletion of the same namespace.
    namespaces := map[string]sets.Empty{
       backup.Namespace: {},
       viper.GetString(constant.CfgKeyCtrlrMgrNS): {},
    }

    // delete the external jobs.
    if err := deleteRelatedObjectList(reqCtx, r.Client, &batchv1.JobList{}, namespaces, labels); err != nil {
       return err
    }

    // delete the external statefulSets.
    return deleteRelatedObjectList(reqCtx, r.Client, &appsv1.StatefulSetList{}, namespaces, labels)
}
```

### BackupPhaseDeleting -> handleDeletingPhase

删除所有相关Backups，清理用不到的相关Object

删除deleteVolumeSnapshots

删除备份文件

### BackupPhaseFailed

根据失败是是否已经初始化来决定从哪里开始重试

```
if backup.Labels[dptypes.BackupTypeLabelKey] == string(dpv1alpha1.BackupTypeContinuous) {
    if backup.Status.StartTimestamp.IsZero() {
       // if the backup fails in the 'New' phase, reconcile it from 'New' phase handler.
       return r.handleNewPhase(reqCtx, backup)
    }
    return r.handleRunningPhase(reqCtx, backup)
}
```

## Restore

同理

```
switch restore.Status.Phase {
case "":
    return r.newAction(reqCtx, restore)
case dpv1alpha1.RestorePhaseRunning:
    return r.handleRunningPhase(reqCtx, restore)
case dpv1alpha1.RestorePhaseCompleted:
    if err = r.deleteExternalResources(reqCtx, restore); err != nil {
       return intctrlutil.RequeueWithError(err, reqCtx.Log, "")
    }
}
```

### newAction

验证BackupRepo

```
repoName, err := CheckBackupRepoForRestore(reqCtx, r.Client, restore)
```

验证资源并修改状态



### handleRunningPhase

恢复中定义的RestoreManager结构如下，包含了Restore对象以及一些actionSet操作

```
type RestoreManager struct {
    OriginalRestore       *dpv1alpha1.Restore
    Restore               *dpv1alpha1.Restore
    PrepareDataBackupSets []BackupActionSet
    PostReadyBackupSets   []BackupActionSet
    Schema                *runtime.Scheme
    Recorder              record.EventRecorder
    WorkerServiceAccount  string
}
```

HandleRestoreActions为具体执行恢复操作的地方

```
func (r *RestoreReconciler) HandleRestoreActions(reqCtx intctrlutil.RequestCtx, restoreMgr *dprestore.RestoreManager) error {
    reqCtx.Log.V(1).Info("start to prepare data", "restore", reqCtx.Req.NamespacedName)
    // 1. handle the prepareData stage.
    isCompleted, err := r.prepareData(reqCtx, restoreMgr)
    if err != nil {
       return err
    }
    // if prepareData is not completed, return
    if !isCompleted {
       return nil
    }
    reqCtx.Log.V(1).Info("start to restore data after ready", "restore", reqCtx.Req.NamespacedName)
    // 2. handle the postReady stage.
    isCompleted, err = r.postReady(reqCtx, restoreMgr)
    if err != nil {
       return err
    }
    if isCompleted {
       restoreMgr.Restore.Status.Phase = dpv1alpha1.RestorePhaseCompleted
       restoreMgr.Restore.Status.CompletionTimestamp = &metav1.Time{Time: time.Now()}
       restoreMgr.Restore.Status.Duration = dprestore.GetRestoreDuration(restoreMgr.Restore.Status)
       r.Recorder.Event(restoreMgr.Restore, corev1.EventTypeNormal, dprestore.ReasonRestoreCompleted, "restore completed.")
    }
    return nil
}
```





### deleteExternalResources

这里是通过Labels匹配所有子资源

```
func deleteRelatedObjectList[T objectList](reqCtx intctrlutil.RequestCtx, cli client.Client, list T, namespaces map[string]sets.Empty, labels map[string]string) error {
    if labels == nil || len(namespaces) == 0 {
       return nil
    }

    for ns := range namespaces {
       if err := cli.List(reqCtx.Ctx, list, client.InNamespace(ns),
          client.MatchingLabels(labels)); err != nil {
          return client.IgnoreNotFound(err)
       }
       objs := reflect.ValueOf(list).Elem().FieldByName("Items")
       if !objs.IsZero() {
          for i := 0; i < objs.Len(); i++ {
             obj := objs.Index(i).Addr().Interface().(client.Object)
             if err := dputils.RemoveDataProtectionFinalizer(reqCtx.Ctx, cli, obj); err != nil {
                return err
             }
             if err := intctrlutil.BackgroundDeleteObject(cli, reqCtx.Ctx, obj); err != nil {
                return err
             }
          }
       }
    }

    return nil
}
```

## GC

用户并不需要把每次备份都保留下来，尤其是通过定时备份产生的备份文件。把清理工作留给用户也并不现实，这就需要一个GC_Controller

GCReconciler接受Backup的调谐请求，并且根据backup.Status.Expiration确定是否进行清理工作

```
now := r.clock.Now()
if backup.Status.Expiration == nil || backup.Status.Expiration.After(now) {
    reqCtx.Log.V(1).Info("backup is not expired yet, skipping")
    return intctrlutil.Reconciled()
}

reqCtx.Log.Info("backup has expired, delete it", "backup", req.String())
if err := intctrlutil.BackgroundDeleteObject(r.Client, reqCtx.Ctx, backup); err != nil {
    reqCtx.Log.Error(err, "failed to delete backup")
    r.Recorder.Event(backup, corev1.EventTypeWarning, "RemoveExpiredBackupsFailed", err.Error())
    return intctrlutil.CheckedRequeueWithError(err, reqCtx.Log, "")
}
```

这之后就会进入Backup的删除逻辑中

```
func BackgroundDeleteObject(cli client.Client, ctx context.Context, obj client.Object, opts ...client.DeleteOption) error {
    deletePropagation := metav1.DeletePropagationBackground
    deleteOptions := &client.DeleteOptions{
       PropagationPolicy: &deletePropagation,
    }

    if err := cli.Delete(ctx, obj, append([]client.DeleteOption{deleteOptions}, opts...)...); err != nil {
       return client.IgnoreNotFound(err)
    }
    return nil
}
```

