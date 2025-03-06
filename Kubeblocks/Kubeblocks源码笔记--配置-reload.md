# Overview

上一节讲到，如果需要配置动态变更，就会注入一个configManager来完成该功能。这里就来介绍一下Config-Manager以及和它相关的reconfiguration CR

Config-Manger通过gRPC与Kubeblocks进行通信

先看一下注入的ConfigManager的PodSpec

```
containers:
  - args:
    - PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$(TOOLS_PATH)
    - /bin/reloader
    - --log-level
    - info
    - --operator-update-enable
    - --tcp
    - "9901"
    - --config
    - /opt/config-manager/config-manager.yaml
    command:
    - env
    env:
    - name: ORC_TOPOLOGY_USER
      valueFrom:
        secretKeyRef:
          key: username
          name: orc-raft-orchestrator-account-orchestrator
    - name: ORC_TOPOLOGY_PASSWORD
      valueFrom:
        secretKeyRef:
          key: password
          name: orc-raft-orchestrator-account-orchestrator
    - name: MYSQL_ROOT_USER
      valueFrom:
        secretKeyRef:
          key: username
          name: asmysql-evhxjd-mysql-account-root
    - name: MYSQL_ROOT_PASSWORD
      valueFrom:
        secretKeyRef:
          key: password
          name: asmysql-evhxjd-mysql-account-root
    - name: CONFIG_MANAGER_POD_IP
      valueFrom:
        fieldRef:
          apiVersion: v1
          fieldPath: status.podIP
    - name: TOOLS_PATH
      value: /opt/kb-tools/reload/mysql-replication-config:/opt/config-manager
    envFrom:
    - configMapRef:
        name: asmysql-evhxjd-mysql-env
        optional: false
    image: docker.io/apecloud/kubeblocks-tools:1.0.0-beta.28
    imagePullPolicy: IfNotPresent
    name: config-manager
    ports:
    - containerPort: 9901
      name: config-manager
      protocol: TCP
    resources:
      limits:
        cpu: "0"
        memory: "0"
    volumeMounts:
    - mountPath: /etc/mysql/conf.d
      name: mysql-config
    - mountPath: /opt/kb-tools/reload/mysql-replication-config
      name: cm-script-mysql-replication-config
    - mountPath: /opt/config-manager
      name: config-manager-config
```

启动需要的配置文件就是ComponentDefinition中的ConfigSpec字段，通过volumeMounts挂载到相应的目录

```
/opt/config-manager $ cat config-manager.yaml 
- configSpec:
    constraintRef: mysql-8.0-config-constraints
    name: mysql-replication-config
    namespace: kb-system
    reRenderResourceTypes:
    - vscale
    templateRef: mysql-8.0-config-template
    volumeName: mysql-config
  downwardAPIOptions: null
  formatterConfig:
    format: ini
    iniConfig:
      sectionName: mysqld
  mountPoint: /etc/mysql/conf.d
  reloadType: tpl
  tplConfig: /opt/kb-tools/reload/mysql-replication-config/reload.yaml
  tplScriptTrigger:
    namespace: kb-system
    scriptConfigMapRef: mysql8.0-reload-script
    sync: true
```



# 启动

## 调用栈

config-manager的启动命令为/bin/reloader 位于cmd/reloader中

```
main -> NewConfigManagerCommand -> runConfigManagerCommand -> run(ctx, opt)
```

```
run
|- CreateCombinedHandler
|- startVolumeWatcher
|- checkAndCreateService
|- <-ctx.Done()
```

```
func run(ctx context.Context, opt *VolumeWatcherOpts) error {

    if configHandler, err = cfgcore.CreateCombinedHandler(opt.CombConfig, opt.BackupPath); err != nil {
       return err
    }

    if len(opt.VolumeDirs) > 0 {
       if volumeWatcher, err = startVolumeWatcher(ctx, opt, configHandler); err != nil {
          return err
       }
       defer volumeWatcher.Close()
    }

    if err = checkAndCreateService(ctx, opt, configHandler); err != nil {
       return err
    }

    logger.Info("config manager started.")
    <-ctx.Done()
    logger.Info("config manager shutdown.")
    return nil
}
```

## CreateCombinedHandler

目前已经实现reloader的处理方式包括signal、exec、tpl、auto

```
const (
    UnixSignalType DynamicReloadType = "signal"
    SQLType        DynamicReloadType = "sql"
    ShellType      DynamicReloadType = "exec"
    HTTPType       DynamicReloadType = "http"
    TPLScriptType  DynamicReloadType = "tpl"
    AutoType       DynamicReloadType = "auto"
)
```

Config与Handler的对应关系保存在multiHandler中

```
type multiHandler struct {
    handlers map[string]ConfigHandler
}
```

### CreateExecHandler 



### CreateSignalHandler 



### CreateTPLScriptHandler



## startVolumeWatcher

```
volumeWatcher := cfgcore.NewVolumeWatcher(opt.VolumeDirs, ctx, logger)
err := volumeWatcher.AddHandler(eventHandler).Run()
```



## checkAndCreateService

注册路由

```
func RegisterReconfigureServer(s grpc.ServiceRegistrar, srv ReconfigureServer) {
	s.RegisterService(&Reconfigure_ServiceDesc, srv)
}


// Reconfigure_ServiceDesc is the grpc.ServiceDesc for Reconfigure service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Reconfigure_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "proto.Reconfigure",
	HandlerType: (*ReconfigureServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "StopContainer",
			Handler:    _Reconfigure_StopContainer_Handler,
		},
		{
			MethodName: "OnlineUpgradeParams",
			Handler:    _Reconfigure_OnlineUpgradeParams_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "reconfigure.proto",
}

```

最后会启动一个gRPC Server来处理Kubeblocks Controller发出的gRPC请求

```
func startGRPCService(opt *VolumeWatcherOpts, ctx context.Context, handler cfgcore.ConfigHandler) error {
    var (
       server *grpc.Server
       proxy  = &reconfigureProxy{opt: opt.ServiceOpt, ctx: ctx, logger: logger.Named("grpcProxy")}
    )

    if err := proxy.Init(handler); err != nil {
       return err
    }

    server = grpc.NewServer(grpc.UnaryInterceptor(logUnaryServerInterceptor))
    cfgproto.RegisterReconfigureServer(server, proxy)

    go func() {
       if err := server.Serve(listener); err != nil {
          logger.Error(err, "failed to serve connections from cri")
          os.Exit(1)
       }
    }()

}
```

Server的定义如下所示，可以看到Server需要利用不同Handler处理StopContainer和OnlineUpgradeParams两类请求

```
// ReconfigureServer is the server API for Reconfigure service.
// All implementations must embed UnimplementedReconfigureServer
// for forward compatibility
type ReconfigureServer interface {
    StopContainer(context.Context, *StopContainerRequest) (*StopContainerResponse, error)
    OnlineUpgradeParams(context.Context, *OnlineUpgradeParamsRequest) (*OnlineUpgradeParamsResponse, error)
    mustEmbedUnimplementedReconfigureServer()
}
```

### proxy.Init

OnlineUpdater就是调用handler.OnlineUpdate来处理配置动态更新

```
func (r *reconfigureProxy) Init(handler cfgcm.ConfigHandler) error {
    if err := r.initOnlineUpdater(handler); err != nil {
       r.logger.Errorf("init online updater failed: %+v", err)
       return err
    }
    if err := r.initContainerKiller(); err != nil {
       r.logger.Errorf("init container killer failed: %+v", err)
       return err
    }
    return nil
}

func (r *reconfigureProxy) initOnlineUpdater(handler cfgcm.ConfigHandler) error {
	if !r.opt.RemoteOnlineUpdateEnable {
		return nil
	}

	r.updater = func(ctx context.Context, name string, updatedParams map[string]string) error {
		return handler.OnlineUpdate(ctx, name, updatedParams)
	}
	return nil
}


```

而ContainerKiller是通用的，创建时会依次检查不同Runtime的运行时是否存在

1. 创建时会依次检查不同Runtime的运行时是否存在，来判断是处于containerd环境还是docker环境
2. init时会和Runtime Socket建立连接，并发送ping请求验证连接

```
func (r *reconfigureProxy) initContainerKiller() error {
	if !r.opt.ContainerRuntimeEnable {
		r.logger.Info("container killer is disabled.")
		return nil
	}

	killer, err := cfgutil.NewContainerKiller(r.opt.ContainerRuntime, r.opt.RuntimeEndpoint, r.logger)
	if err != nil {
		return cfgcore.WrapError(err, "failed to create container killer")
	}
	if err := killer.Init(r.ctx); err != nil {
		return cfgcore.WrapError(err, "failed to init killer")
	}
	r.killer = killer
	return nil
}

var defaultContainerdEndpoints = []string{
	"unix:///var/run/dockershim.sock",
	"unix:///run/containerd/containerd.sock",
	"unix:///run/crio/crio.sock",
	"unix:///var/run/cri-dockerd.sock",
}

func (c *containerdContainer) Init(ctx context.Context) error {

	if c.runtimeEndpoint != "" {
		endpoints = []string{formatSocketPath(c.runtimeEndpoint)}
	}

	for _, endpoint := range endpoints {
		conn, err = createGrpcConnection(ctx, endpoint)
		if err != nil {
			c.logger.Warnf("failed to connect containerd endpoint: %s, error : %v", endpoint, err)
		} else {
			c.backendRuntime = runtimeapi.NewRuntimeServiceClient(conn)
			if err = c.pingCRI(ctx, c.backendRuntime); err != nil {
				return nil
			}
		}
	}
	return err
}
```

### 创建 gRPC Server

```
listener, err := net.Listen("tcp", tcpSpec)
if err != nil {
  return cfgutil.WrapError(err, "failed to create listener: [%s]", tcpSpec)
}

server = grpc.NewServer(grpc.UnaryInterceptor(logUnaryServerInterceptor))
cfgproto.RegisterReconfigureServer(server, proxy)

go func() {
  if err := server.Serve(listener); err != nil {
    logger.Error(err, "failed to serve connections from cri")
    os.Exit(1)
  }
}()
```

# Server处理请求





## StopContainer

获取到请求中的ContainerID，并且向Containerd socket 发送kill 的 signal，触发容器重启，达到触发配置reload的作用

reference cri-api url: https://github.com/kubernetes/cri-api/blob/master/pkg/apis/runtime/v1/api.proto#L1108
reference containerd url: https://github.com/containerd/containerd/blob/main/pkg/cri/server/container_stop.go#L124

```
func (c *containerdContainer) Kill(ctx context.Context, containerIDs []string, signal string, timeout *time.Duration) error {
		for _, containerID := range containerIDs {
				......
				request.ContainerId = containerID
				_, err = c.backendRuntime.StopContainer(ctx, request)
		}
}
```

## OnlineUpgradeParams

通过调用初始化好的updater，来实现配置动态更新r.updater。目前实际起作用的动态变更方式只有shell和tpl

### shell

在配置变更后，Pod中的配置文件变为期望的状态，之后通过执行脚本来使配置生效

也就是在接到请求后根据每一条需要更新的参数，执行规定的命令

脚本格式为下面所示，通过接受参数来确定如何更新（注意：脚本在ConfigManager环境中执行）

```
#!/bin/sh
set -ex

CURRENT_PATH=$(cd $(dirname $0);pwd)
source ${CURRENT_PATH}/utils.sh

paramName="${1:?missing config}"
paramValue="${2:?missing value}"

$OB_CLI --host 127.0.0.1 -uroot -P ${OB_SERVICE_PORT} var-update --set ${paramName}=\'${paramValue}\' -p ${OB_ROOT_PASSWD} ||
$OB_CLI --host 127.0.0.1 -uroot -P ${OB_SERVICE_PORT} var-update --set ${paramName}=${paramValue} -p ${OB_ROOT_PASSWD}
```

代码实现

```
func (s *shellCommandHandler) OnlineUpdate(ctx context.Context, name string, updatedParams map[string]string) error {
    args := make([]string, len(s.arg))
    copy(args, s.arg)
    return s.execHandler(ctx, updatedParams, args...)
}

func (s *shellCommandHandler) execHandler(ctx context.Context, updatedParams map[string]string, args ...string) error {
	if s.isBatchReload && s.batchInputTemplate != "" {
		return doBatchReloadAction(ctx, updatedParams, nil, s.batchInputTemplate, s.command, args...)
	}
	return doReloadAction(ctx, updatedParams, nil, s.command, args...)
}
```

### tpl

tpl模版渲染为最终的命令，并通过text/template 的Execute方法执行

```
func (u *tplScriptHandler) OnlineUpdate(ctx context.Context, name string, updatedParams map[string]string) error {
    return wrapGoTemplateRun(ctx,
       u.tplScripts,
       u.tplContent,
       updatedParams,
       u.formatterConfig,
       u.engineType, u.dsn)
}
```



```
engine := gotemplate.NewTplEngine(&values, constructReloadBuiltinFuncs(ctx, commandChannel, formatConfig), tplScriptPath, nil, nil)
	_, err = engine.Render(tplContent)
```

```
func (t *TplEngine) Render(context string) (string, error) {
    var buf strings.Builder
    tpl, err := t.tpl.Parse(context)
    if err != nil {
       return "", err
    }
    if err := tpl.Execute(&buf, t.tplValues); err != nil {
       return "", err
    }
    return buf.String(), nil
}
```

# Controller触发请求

动态变更由Kubeblocks Controller触发。通过watch 配置相关的CM的变更，并在 Reconcile的过程中向ConfigManager发送gRPC请求

```
func (r *ReconfigureReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
		// 1.获取到本地Reconcile的ConfigMap，检查是否是配置相关的ConfigMap，是的话才进行后面处理, 并且会比较hash值
		
		// 2. 检查内容是否更新，通过annotations[constant.LastAppliedConfigAnnotationKey]保存上次的内容，来比较。
		
		// 3.获取关联的Configuration
		resources, err := prepareRelatedResource(reqCtx, r.Client, config)
		
		// 4.同步配置
		return r.sync(reqCtx, config, resources)
}
```

## 调用栈

```
sync
|- createConfigPatch 
|- reconcileContext := newConfigReconcileContext
|- reconcileContext.GetRelatedObjects
|- r.performUpgrade
```

### 1. 创建新旧配置差异的patch

```
// CreateConfigPatch creates a patch for configuration files with different version.
func CreateConfigPatch(oldVersion, newVersion map[string]string, format appsv1beta1.CfgFileFormat, keys []string, comparableAllFiles bool) (*ConfigPatchInfo, bool, error) {
    var hasFilesUpdated = false

    if comparableAllFiles && len(keys) > 0 {
       hasFilesUpdated = checkExcludeConfigDifference(oldVersion, newVersion, keys)
    }

    cmKeySet := FromCMKeysSelector(keys)
    patch, err := CreateMergePatch(
       FromConfigData(oldVersion, cmKeySet),
       FromConfigData(newVersion, cmKeySet),
       CfgOption{
          CfgType: format,
          Type:    CfgTplType,
          Log:     log.FromContext(context.TODO()),
       })
    return patch, hasFilesUpdated, err
}
```

### 2. 获取需要的CR

通过泛型和流式编程，获取所有需要的CR

```
func (c *ReconcileContext) GetRelatedObjects() error {
    return c.Cluster().
       ComponentAndComponentDef().
       ComponentSpec().
       Workload().
       SynthesizedComponent().
       Complete()
}
```

```
func (r *ResourceFetcher[T]) ComponentAndComponentDef() *T {
    componentKey := client.ObjectKey{
       Namespace: r.Namespace,
       Name:      constant.GenerateClusterComponentName(r.ClusterName, r.ComponentName),
    }
    return r.Wrap(func() error {
       r.ComponentObj = &appsv1.Component{}
       err := r.Client.Get(r.Context, componentKey, r.ComponentObj)
       if apierrors.IsNotFound(err) {
          return nil
       } else if err != nil {
          return err
       }

       if len(r.ComponentObj.Spec.CompDef) == 0 {
          return nil
       }

       compDefKey := types.NamespacedName{
          Name: r.ComponentObj.Spec.CompDef,
       }
       r.ComponentDefObj = &appsv1.ComponentDefinition{}
       if err := r.Client.Get(r.Context, compDefKey, r.ComponentDefObj); err != nil {
          return err
       }
       if r.ComponentDefObj.Status.Phase != appsv1.AvailablePhase {
          return fmt.Errorf("ComponentDefinition referenced is unavailable: %s", r.ComponentDefObj.Name)
       }
       return nil
    })
}
```

### 3. performUpgrade

#### 确定更新策略

NewReconfigurePolicy会根据配置的不同类型，生成不同的配置更新类型

```
NonePolicy                    UpgradePolicy = "none"       // 未指定
NormalPolicy                  UpgradePolicy = "simple"     //
RestartPolicy                 UpgradePolicy = "parallel"
RollingPolicy                 UpgradePolicy = "rolling"
AsyncDynamicReloadPolicy      UpgradePolicy = "autoReload" // Workload自身支持动态更新，这里只需要更改配置文件
SyncDynamicReloadPolicy       UpgradePolicy = "operatorSyncUpdate"
DynamicReloadAndRestartPolicy UpgradePolicy = "dynamicReloadBeginRestart"
```

每个Policy对应各自的reconfigurePolicy，也就是具体的Action。在每个reconfigurePolicy中通过func init在导入时完成注册

```
func init() {
    RegisterPolicy(appsv1alpha1.NormalPolicy, &simplePolicy{})
}
```

### policy.Upgrade()

不同的reconfigurePolicy的处理逻辑是不同的，接口设计如下所示：

```
type reconfigurePolicy interface {
    // Upgrade is to enable the configuration to take effect.
    Upgrade(params reconfigureParams) (ReturnedStatus, error)

    // GetPolicyName returns name of policy.
    GetPolicyName() string
}
```

同时提供了一些共用的函数，可以通过GetInstanceSetRollingUpgradeFuncs获取

```
func GetInstanceSetRollingUpgradeFuncs() RollingUpgradeFuncs {
    return RollingUpgradeFuncs{
       GetPodsFunc:          getPodsForOnlineUpdate,
       RestartContainerFunc: commonStopContainerWithPod,
       OnlineUpdatePodFunc:  commonOnlineUpdateWithPod,
       RestartComponent:     restartComponent,
    }
}
```

#### simplePolicy

策略是重启整个Component，也就是更新Component下所有InstanceSet。相当于把重建策略交给InstanceSet来处理

```
func (s *simplePolicy) Upgrade(params reconfigureParams) (ReturnedStatus, error) {
    params.Ctx.Log.V(1).Info("simple policy begin....")

    return restartAndCheckComponent(params, GetInstanceSetRollingUpgradeFuncs(), fromWorkloadObjects(params))
}
```

```
func restartAndCheckComponent(param reconfigureParams, funcs RollingUpgradeFuncs, objs []client.Object) (ReturnedStatus, error) {
    var (
       newVersion = param.getTargetVersionHash()
       configKey  = param.getConfigKey()

       retStatus = ESRetry
       progress  = core.NotStarted
    )

    obj, err := funcs.RestartComponent(param.Client, param.Ctx, configKey, newVersion, objs, recordEvent)

    pods, err := funcs.GetPodsFunc(param)
    if len(pods) == int(progress) {
       retStatus = ESNone
    }
    return makeReturnedStatus(retStatus, withExpected(int32(len(pods))), withSucceed(progress)), nil
}
```

这里用到了两个公共函数

- funcs.RestartComponent：对于所有InstanceSet（可以理解为有角色的Statefulset）会通过cli.Patch 整个InstanceSet.DeepCopy的方式触发InstanceSet的重建
- funcs.GetPodsFunc：通过Labels获取所有POd

#### syncPolicy

funcs.OnlineUpdatePodFunc：向每个Pod所在的ConfigManager发送gRPC请求` c.cc.Invoke(ctx, "/proto.Reconfigure/OnlineUpgradeParams", in, out, opts...)`

#### AutoReloadPolicy

什么都不做，在ConfigMap的内容更新到挂载的Pod中时，由数据库自己解决

```
func (receiver AutoReloadPolicy) Upgrade(params reconfigureParams) (ReturnedStatus, error) {
    _ = params
    return makeReturnedStatus(ESNone), nil
}
```

#### combineUpgradePolicy

依次执行syncPolicy、simplePolicy

```
func init() {
    RegisterPolicy(appsv1alpha1.DynamicReloadAndRestartPolicy, &combineUpgradePolicy{
       policyExecutors: []reconfigurePolicy{&syncPolicy{}, &simplePolicy{}},
    })
}

func (h *combineUpgradePolicy) GetPolicyName() string {
    return string(appsv1alpha1.DynamicReloadAndRestartPolicy)
}

func (h *combineUpgradePolicy) Upgrade(params reconfigureParams) (ReturnedStatus, error) {
    var ret ReturnedStatus
    for _, executor := range h.policyExecutors {
       retStatus, err := executor.Upgrade(params)
       if err != nil {
          return retStatus, err
       }
       ret = retStatus
    }
    return ret, nil
}
```

#### parallelUpgradePolicy

对每个Pod发送/proto.Reconfigure/StopContainer的gRPC请求

```
for _, pod := range pods {
    if podutil.IsMatchConfigVersion(&pod, configKey, configVersion) {
      continue
    }
    if err := funcs.RestartContainerFunc(&pod, params.Ctx.Ctx, params.ContainerNames, params.ReconfigureClientFactory); err != nil {
      return makeReturnedStatus(ESFailedAndRetry), err
    }
    if err := updatePodLabelsWithConfigVersion(&pod, configKey, configVersion, params.Client, params.Ctx.Ctx); err != nil {
      return makeReturnedStatus(ESFailedAndRetry), err
    }
}
```

funcs.RestartContainerFunc：通过参数中ContainerName得到ContainerID，向ConfigManager法发送stopContainer命令

#### rollingUpgradePolicy

滚动升级的版本

```
podWins := markDynamicCursor(pods, podStats, configKey, configVersion, rollingReplicas)
waitRollingPods := podWins.getWaitRollingPods()


for _, pod := range waitRollingPods {
  if podStats.isUpdating(&pod) {
    params.Ctx.Log.Info("pod is in rolling update.", "pod name", pod.Name)
    continue
  }
  if err := funcs.RestartContainerFunc(&pod, params.Ctx.Ctx, params.ContainerNames, params.ReconfigureClientFactory); err != nil {
    return makeReturnedStatus(ESFailedAndRetry), err
  }
  if err := updatePodLabelsWithConfigVersion(&pod, configKey, configVersion, params.Client, params.Ctx.Ctx); err != nil {
    return makeReturnedStatus(ESFailedAndRetry), err
  }
}
```