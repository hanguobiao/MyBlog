Reference:https://arthurchiao.art/blog/what-happens-when-k8s-creates-pods-1-zh/

# 0 K8s组件启动过程

## 0.1 kube-apiserver启动

### 调用栈

创建命令行（`kube-apiserver`）入口：

```
main                                         // cmd/kube-apiserver/apiserver.go
 |-cmd := app.NewAPIServerCommand()          // cmd/kube-apiserver/app/server.go
 |  |-RunE := func() {
 |      Complete()
 |        |-ApplyAuthorization(s.Authorization)
 |        |-if TLS:
 |            ServiceAccounts.KeyFiles = []string{CertKey.KeyFile}
 |      Validate()
 |      Run(completedOptions, handlers) // 核心逻辑
 |    }
 |-cmd.Execute()
```

`kube-apiserver` 启动后，会执行到其中的 `Run()` 方法：

```
Run()          // cmd/kube-apiserver/app/server.go
 |-server = CreateServerChain()
 |           |-CreateKubeAPIServerConfig()
 |           |   |-buildGenericConfig
 |           |   |   |-genericapiserver.NewConfig()     // staging/src/k8s.io/apiserver/pkg/server/config.go
 |           |   |   |  |-return &Config{
 |           |   |   |       Serializer:             codecs,
 |           |   |   |       BuildHandlerChainFunc:  DefaultBuildHandlerChain, // 注册 handler，例如 AuthN
 |           |   |   |    } 
 |           |   |   |
 |           |   |   |-OpenAPIConfig = DefaultOpenAPIConfig()  // OpenAPI schema
 |           |   |   |-kubeapiserver.NewStorageFactoryConfig() // etcd 相关配置
 |           |   |   |-APIResourceConfig = genericConfig.MergedResourceConfig
 |           |   |   |-storageFactoryConfig.Complete(s.Etcd)
 |           |   |   |-storageFactory = completedStorageFactoryConfig.New()
 |           |   |   |-s.Etcd.ApplyWithStorageFactoryTo(storageFactory, genericConfig)
 |           |   |   |-BuildAuthorizer(s, genericConfig.EgressSelector, versionedInformers)
 |           |   |   |-pluginInitializers, admissionPostStartHook = admissionConfig.New()
 |           |   |
 |           |   |-capabilities.Initialize
 |           |   |-controlplane.ServiceIPRange()
 |           |   |-config := &controlplane.Config{}
 |           |   |-AddPostStartHook("start-kube-apiserver-admission-initializer", admissionPostStartHook)
 |           |   |-ServiceAccountIssuerURL = s.Authentication.ServiceAccounts.Issuer
 |           |   |-ServiceAccountJWKSURI = s.Authentication.ServiceAccounts.JWKSURI
 |           |   |-ServiceAccountPublicKeys = pubKeys
 |           |
 |           |-createAPIExtensionsServer
 |           |-CreateKubeAPIServer
 |           |-createAggregatorServer    // cmd/kube-apiserver/app/aggregator.go
 |           |   |-aggregatorConfig.Complete().NewWithDelegate(delegateAPIServer)   // staging/src/k8s.io/kube-aggregator/pkg/apiserver/apiserver.go
 |           |   |  |-apiGroupInfo := NewRESTStorage()
 |           |   |  |-GenericAPIServer.InstallAPIGroup(&apiGroupInfo)
 |           |   |  |-InstallAPIGroups
 |           |   |  |-openAPIModels := s.getOpenAPIModels(APIGroupPrefix, apiGroupInfos...)
 |           |   |  |-for apiGroupInfo := range apiGroupInfos {
 |           |   |  |   s.installAPIResources(APIGroupPrefix, apiGroupInfo, openAPIModels)
 |           |   |  |   s.DiscoveryGroupManager.AddGroup(apiGroup)
 |           |   |  |   s.Handler.GoRestfulContainer.Add(discovery.NewAPIGroupHandler(s.Serializer, apiGroup).WebService())
 |           |   |  |
 |           |   |  |-GenericAPIServer.Handler.NonGoRestfulMux.Handle("/apis", apisHandler)
 |           |   |  |-GenericAPIServer.Handler.NonGoRestfulMux.UnlistedHandle("/apis/", apisHandler)
 |           |   |  |-
 |           |   |-
 |-prepared = server.PrepareRun()     // staging/src/k8s.io/kube-aggregator/pkg/apiserver/apiserver.go
 |            |-GenericAPIServer.AddPostStartHookOrDie
 |            |-GenericAPIServer.PrepareRun
 |            |  |-routes.OpenAPI{}.Install()
 |            |     |-registerResourceHandlers // staging/src/k8s.io/apiserver/pkg/endpoints/installer.go
 |            |         |-POST: XX
 |            |         |-GET: XX
 |            |
 |            |-openapiaggregator.BuildAndRegisterAggregator()
 |            |-openapiaggregator.NewAggregationController()
 |            |-preparedAPIAggregator{}
 |-prepared.Run() // staging/src/k8s.io/kube-aggregator/pkg/apiserver/apiserver.go
    |-s.runnable.Run()
```

一些重要步骤：

1. 注册命令行参数
2. **创建 server chain**。Server aggregation（聚合）是一种支持多 apiserver 的方式，其中 包括了一个 [generic apiserver](https://github.com/kubernetes/kubernetes/blob/v1.21.0/cmd/kube-apiserver/app/server.go#L219)，作为默认实现。
3. **生成 OpenAPI schema**，保存到 apiserver 的 [Config.OpenAPIConfig 字段](https://github.com/kubernetes/kubernetes/blob/v1.21.0/staging/src/k8s.io/apiserver/pkg/server/config.go#L167)。
4. 遍历 schema 中的所有 API group，为每个 API group 配置一个 [storage provider](https://github.com/kubernetes/kubernetes/blob/v1.21.0/staging/src/k8s.io/kube-aggregator/pkg/apiserver/apiserver.go#L204)， 这是一个通用 backend 存储抽象层。
5. 遍历每个 group 版本，为每个 HTTP route [配置 REST mappings](https://github.com/kubernetes/kubernetes/blob/v1.21.0/staging/src/k8s.io/apiserver/pkg/endpoints/groupversion.go#L92)。 稍后处理请求时，就能将 requests 匹配到合适的 handler。

### 注册命令行参数

K8s 支持多种认证方式，并且不同认证方式可以一起使用，这种情况下，任何一种方式认证成功就算成功。 因此，这些配置最终形成一个 authenticator list，例如，

- 如果指定了 `--service-account-key-file=/etc/kubernetes/pki/sa.pub`，就会将这个公钥加到这个列表；
- 如果指定了 `--client-ca-file`，就会将 x509 证书加到这个列表；
- 如果指定了 `--token-auth-file`，就会将 token 加到这个列表；

### 注册各种 handler

`NewConfig()` 里面会调用下面的方法注册认证、鉴权、审计等等各种 handler，例如 `WithAuthentication()` 注册成功之后，就会对客户端的每个请求执行认证。

## controller-manager 启动

### 调用栈

```
NewDeploymentController
NewReplicaSetController
```

## kubelet 启动

### 调用栈

```
main                                                                            // cmd/kubelet/kubelet.go
 |-NewKubeletCommand                                                            // cmd/kubelet/app/server.go
   |-Run                                                                        // cmd/kubelet/app/server.go
      |-initForOS                                                               // cmd/kubelet/app/server.go
      |-run                                                                     // cmd/kubelet/app/server.go
        |-initConfigz                                                           // cmd/kubelet/app/server.go
        |-InitCloudProvider
        |-NewContainerManager
        |-ApplyOOMScoreAdj
        |-PreInitRuntimeService
        |-RunKubelet                                                            // cmd/kubelet/app/server.go
        | |-k = createAndInitKubelet                                            // cmd/kubelet/app/server.go
        | |  |-NewMainKubelet
        | |  |  |-watch k8s Service
        | |  |  |-watch k8s Node
        | |  |  |-klet := &Kubelet{}
        | |  |  |-init klet fields
        | |  |
        | |  |-k.BirthCry()
        | |  |-k.StartGarbageCollection()
        | |
        | |-startKubelet(k)                                                     // cmd/kubelet/app/server.go
        |    |-go k.Run()                                                       // -> pkg/kubelet/kubelet.go
        |    |  |-go cloudResourceSyncManager.Run()
        |    |  |-initializeModules
        |    |  |-go volumeManager.Run()
        |    |  |-go nodeLeaseController.Run()
        |    |  |-initNetworkUtil() // setup iptables
        |    |  |-go Until(PerformPodKillingWork, 1*time.Second, neverStop)
        |    |  |-statusManager.Start()
        |    |  |-runtimeClassManager.Start
        |    |  |-pleg.Start()
        |    |  |-syncLoop(updates, kl)                                         // pkg/kubelet/kubelet.go
        |    |
        |    |-k.ListenAndServe
        |
        |-go http.ListenAndServe(healthz)
```

### `NewContainerManager()`

```
// cmd/kubelet/app/server.go

func run() {
        if s.CgroupsPerQOS && s.CgroupRoot == "" {
            s.CgroupRoot = "/" // if --cgroups-per-qos enabled but --cgroup-root not specified, default to /
        }
    ...
        kubeDeps.ContainerManager = cm.NewContainerManager(
            kubeDeps.Mounter,
            kubeDeps.CAdvisorInterface,
            cm.NodeConfig{
                RuntimeCgroupsName:    s.RuntimeCgroups,
                SystemCgroupsName:     s.SystemCgroups,
                KubeletCgroupsName:    s.KubeletCgroups,
                KubeletOOMScoreAdj:    s.OOMScoreAdj,
                CgroupsPerQOS:         s.CgroupsPerQOS,
                CgroupRoot:            s.CgroupRoot,
                CgroupDriver:          s.CgroupDriver,
                KubeletRootDir:        s.RootDirectory,
                ProtectKernelDefaults: s.ProtectKernelDefaults,
                NodeAllocatableConfig: cm.NodeAllocatableConfig{
                    KubeReservedCgroupName:   s.KubeReservedCgroup,
                    SystemReservedCgroupName: s.SystemReservedCgroup,
                    EnforceNodeAllocatable:   sets.NewString(s.EnforceNodeAllocatable...),
                    KubeReserved:             kubeReserved,
                    SystemReserved:           systemReserved,
                    ReservedSystemCPUs:       reservedSystemCPUs,
                    HardEvictionThresholds:   hardEvictionThresholds,
                },
                QOSReserved:                              *experimentalQOSReserved,
                CPUManagerPolicy:                         s.CPUManagerPolicy,
                CPUManagerPolicyOptions:                  cpuManagerPolicyOptions,
                CPUManagerReconcilePeriod:                s.CPUManagerReconcilePeriod.Duration,
                ExperimentalMemoryManagerPolicy:          s.MemoryManagerPolicy,
                ExperimentalMemoryManagerReservedMemory:  s.ReservedMemory,
                ExperimentalPodPidsLimit:                 s.PodPidsLimit,
                EnforceCPULimits:                         s.CPUCFSQuota,
                CPUCFSQuotaPeriod:                        s.CPUCFSQuotaPeriod.Duration,
                ExperimentalTopologyManagerPolicy:        s.TopologyManagerPolicy,
                ExperimentalTopologyManagerScope:         s.TopologyManagerScope,
                ExperimentalTopologyManagerPolicyOptions: topologyManagerPolicyOptions,
            },
            s.FailSwapOn,
            kubeDeps.Recorder,
            kubeDeps.KubeClient,
        )
}
// pkg/kubelet/cm/container_manager_linux.go

func NewContainerManager(mountUtil mount.Interface, cadvisorInterface cadvisor.Interface, nodeConfig NodeConfig, failSwapOn bool, recorder record.EventRecorder, kubeClient clientset.Interface) (ContainerManager, error) {
    subsystems := GetCgroupSubsystems()

    if failSwapOn { // Check whether swap is enabled. The Kubelet does not support running with swap enabled.
        swapFile := "/proc/swaps"
        swapData := os.ReadFile(swapFile)
        ...
    }

    machineInfo := cadvisorInterface.MachineInfo()
    capacity := cadvisor.CapacityFromMachineInfo(machineInfo)
    for k, v := range capacity {
        internalCapacity[k] = v
    }

    cgroupRoot    := ParseCgroupfsToCgroupName(nodeConfig.CgroupRoot)      // ""
    cgroupManager := NewCgroupManager(subsystems, nodeConfig.CgroupDriver) // "cgroupfs"

    if nodeConfig.CgroupsPerQOS { // true by default
        cgroupManager.Validate(cgroupRoot)
        cgroupRoot = NewCgroupName(cgroupRoot, defaultNodeAllocatableCgroupName) // -> "/kubepods"
    }
    Info("Creating Container Manager object based on Node Config", "nodeConfig", nodeConfig)

    qosContainerManager := NewQOSContainerManager(subsystems, cgroupRoot, nodeConfig, cgroupManager)

    cm := &containerManagerImpl{
        cadvisorInterface:   cadvisorInterface,
        mountUtil:           mountUtil,
        NodeConfig:          nodeConfig,
        subsystems:          subsystems,
        cgroupManager:       cgroupManager,
        capacity:            capacity,
        internalCapacity:    internalCapacity,
        cgroupRoot:          cgroupRoot,
        recorder:            recorder,
        qosContainerManager: qosContainerManager,
    }

    cm.topologyManager = topologymanager.NewManager()
    cm.deviceManager   = devicemanager.NewManagerImpl(machineInfo.Topology, cm.topologyManager)
    cm.draManager      = dra.NewManagerImpl(kubeClient) // initialize DRA manager
    cm.cpuManager      = cpumanager.NewManager() // Initialize CPU manager
    cm.memoryManager   = memorymanager.NewManager()

    return cm, nil
}
```

kubelet 要求必须关闭 swap，`cat /proc/swaps`。

# 1 kubectl（命令行客户端）

## 调用栈概览

```
NewKubectlCommand                                    // staging/src/k8s.io/kubectl/pkg/cmd/cmd.go
 |-matchVersionConfig = NewMatchVersionFlags()
 |-f = cmdutil.NewFactory(matchVersionConfig)
 |      |-clientGetter = matchVersionConfig
 |-NewCmdRun(f)                                      // staging/src/k8s.io/kubectl/pkg/cmd/run/run.go
 |  |-Complete                                       // staging/src/k8s.io/kubectl/pkg/cmd/run/run.go
 |  |-Run(f)                                         // staging/src/k8s.io/kubectl/pkg/cmd/run/run.go
 |    |-validate parameters
 |    |-generators = GeneratorFn("run")
 |    |-runObj = createGeneratedObject(generators)   // staging/src/k8s.io/kubectl/pkg/cmd/run/run.go
 |    |           |-obj = generator.Generate()       // -> staging/src/k8s.io/kubectl/pkg/generate/versioned/run.go
 |    |           |        |-get pod params
 |    |           |        |-pod = v1.Pod{params}
 |    |           |        |-return &pod
 |    |           |-mapper = f.ToRESTMapper()        // -> staging/src/k8s.io/cli-runtime/pkg/genericclioptions/config_flags.go
 |    |           |  |-f.clientGetter.ToRESTMapper() // -> staging/src/k8s.io/kubectl/pkg/cmd/util/factory_client_access.go
 |    |           |     |-f.Delegate.ToRESTMapper()  // -> staging/src/k8s.io/kubectl/pkg/cmd/util/kubectl_match_version.go
 |    |           |        |-ToRESTMapper            // -> staging/src/k8s.io/cli-runtime/pkg/resource/builder.go
 |    |           |        |-delegate()              //    staging/src/k8s.io/cli-runtime/pkg/resource/builder.go
 |    |           |--actualObj = resource.NewHelper(mapping).XX.Create(obj)
 |    |-PrintObj(runObj.Object)
 |
 |-NewCmdEdit(f)      // kubectl edit   命令
 |-NewCmdScale(f)     // kubectl scale  命令
 |-NewCmdCordon(f)    // kubectl cordon 命令
 |-NewCmdUncordon(f)
 |-NewCmdDrain(f)
 |-NewCmdTaint(f)
 |-NewCmdExecute(f)
 |-...
```

## 1.1 参数验证（validation）和资源对象生成器（generator）

### 参数验证

敲下 `kubectl` 命令后，它首先会做一些**客户端侧**的验证。 如果命令行参数有问题，例如，[镜像名为空或格式不对](https://github.com/kubernetes/kubernetes/blob/v1.21.0/staging/src/k8s.io/kubectl/pkg/cmd/run/run.go#L262)， 这里会直接报错，从而避免了将明显错误的请求发给 kube-apiserver，减轻了后者的压力。

此外，kubectl 还会检查其他一些配置，例如

- 是否需要记录（record）这条命令（用于 rollout 或审计）
- 是否是空跑（`--dry-run`）

### 创建 HTTP 请求

所有**查询或修改 K8s 资源的操作**都需要与 kube-apiserver 交互，后者会进一步和 etcd 通信。

因此，验证通过之后，kubectl 接下来会**创建发送给 kube-apiserver 的 HTTP 请求**。

## API group 和版本协商（version negotiation）

有了 runtime object 之后，kubectl 需要用合适的 API 将请求发送给 kube-apiserver。

### API Group

K8s 用 API group 来管理 resource API。 这是一种不同于 monolithic API（所有 API 扁平化）的 API 管理方式。

具体来说，**同一资源的不同版本的 API，会放到一个 group 里面**。 例如 Deployment 资源的 API group 名为 `apps`，最新的版本是 `v1`。这也是为什么 我们在创建 Deployment 时，需要在 yaml 中指定 `apiVersion: apps/v1` 的原因。

### 版本协商

生成 runtime object 之后，kubectl 就开始 [搜索合适的 API group 和版本](https://github.com/kubernetes/kubernetes/blob/v1.21.0/staging/src/k8s.io/kubectl/pkg/cmd/run/run.go#L610-L619)：

```
// staging/src/k8s.io/kubectl/pkg/cmd/run/run.go

    obj := generator.Generate(params) // 创建运行时对象
    mapper := f.ToRESTMapper()        // 寻找适合这个资源（对象）的 API group
```

然后[创建一个正确版本的客户端（versioned client）](https://github.com/kubernetes/kubernetes/blob/v1.21.0/staging/src/k8s.io/kubectl/pkg/cmd/run/run.go#L641)，

```
// staging/src/k8s.io/kubectl/pkg/cmd/run/run.go

    gvks, _ := scheme.Scheme.ObjectKinds(obj)
    mapping := mapper.RESTMapping(gvks[0].GroupKind(), gvks[0].Version)
```

这个客户端能感知资源的 REST 语义。

以上过程称为**版本协商**。在实现上，kubectl 会 **扫描 kube-apiserver 的 `/apis` 路径** （OpenAPI 格式的 schema 文档），获取所有的 API groups。

出于性能考虑，kubectl 会 [缓存这份 OpenAPI schema](https://github.com/kubernetes/kubernetes/blob/v1.14.0/staging/src/k8s.io/cli-runtime/pkg/genericclioptions/config_flags.go#L234)， 路径是 `~/.kube/cache/discovery`。**想查看这个 API discovery 过程，可以删除这个文件**， 然后随便执行一条 kubectl 命令，并指定足够大的日志级别（例如 `kubectl get ds -v 10`）。

### 发送 HTTP 请求

现在有了 runtime object，也找到了正确的 API，因此接下来就是 将请求真正[发送出去](https://github.com/kubernetes/kubernetes/blob/v1.21.0/staging/src/k8s.io/kubectl/pkg/cmd/run/run.go#L654)：

```
// staging/src/k8s.io/kubectl/pkg/cmd/cmd.go

        actualObj = resource.
            NewHelper(client, mapping).
            DryRun(o.DryRunStrategy == cmdutil.DryRunServer).
            WithFieldManager(o.fieldManager).
            Create(o.Namespace, false, obj)
```

发送成功后，会以恰当的格式打印返回的消息。

## 1.3 客户端认证（client auth）

前面其实有意漏掉了一步：客户端认证。它发生在发送 HTTP 请求之前。

**用户凭证（credentials）一般都放在 kubeconfig 文件中，但这个文件可以位于多个位置**， 优先级从高到低：

- 命令行 `--kubeconfig <file>`
- 环境变量 `$KUBECONFIG`
- 某些[预定义的路径](https://github.com/kubernetes/client-go/blob/v1.21.0/tools/clientcmd/loader.go#L52)，例如 `~/.kube`。

**这个文件中存储了集群、用户认证等信息**，如下面所示：

```
apiVersion: v1
clusters:
- cluster:
    certificate-authority: /etc/kubernetes/pki/ca.crt
    server: https://192.168.2.100:443
  name: k8s-cluster-1
contexts:
- context:
    cluster: k8s-cluster-1
    user: default-user
  name: default-context
current-context: default-context
kind: Config
preferences: {}
users:
- name: default-user
  user:
    client-certificate: /etc/kubernetes/pki/admin.crt
    client-key: /etc/kubernetes/pki/admin.key
```

有了这些信息之后，客户端就可以组装 HTTP 请求的认证头了。支持的认证方式有几种：

- **X509 证书**：放到 [TLS](https://github.com/kubernetes/client-go/blob/82aa063804cf055e16e8911250f888bc216e8b61/rest/transport.go#L80-L89) 中发送；
- **Bearer token**：放到 HTTP `"Authorization"` 头中 [发送](https://github.com/kubernetes/client-go/blob/c6f8cf2c47d21d55fa0df928291b2580544886c8/transport/round_trippers.go#L314)；
- **用户名密码**：放到 HTTP basic auth [发送](https://github.com/kubernetes/client-go/blob/c6f8cf2c47d21d55fa0df928291b2580544886c8/transport/round_trippers.go#L223)；
- **OpenID Connect (OIDC)** 认证（例如和外部的 Keystone、Google 账号打通）：需要先由用户手动处理，将其转成一个 token，然后和 bearer token 类似发送。

# 2 kube-apiserver

请求从客户端发出后，便来到服务端，也就是 kube-apiserver。

## 调用栈概览

```
// 启动时注册 AuthN/AuthZ/Audit 等等各种 request handler
buildGenericConfig
  |-genericConfig = genericapiserver.NewConfig(legacyscheme.Codecs)  // cmd/kube-apiserver/app/server.go

NewConfig       // staging/src/k8s.io/apiserver/pkg/server/config.go
 |-return &Config{
      Serializer:             codecs,
      BuildHandlerChainFunc:  DefaultBuildHandlerChain,
   }                          /
                            /
                          /
                        /
DefaultBuildHandlerChain       // staging/src/k8s.io/apiserver/pkg/server/config.go
 |-handler = genericapifilters.WithAuthorization(handler)
 |-handler = genericapifilters.WithAudit(handler)
 |-handler = genericapifilters.WithAuthentication(handler)
 |-handler = ...
 |-return handler


// 请求来了之后会依次执行相关 handler，其中之一就是 AuthN handler
WithAuthentication
 |-withAuthentication
    |-resp, ok := AuthenticateRequest(req)
    |  |-for h := range authHandler.Handlers {
    |      resp, ok := currAuthRequestHandler.AuthenticateRequest(req)
    |      if ok {
    |          return resp, ok, err
    |      }
    |    }
    |    return nil, false, utilerrors.NewAggregate(errlist)
    |
    |-audiencesAreAcceptable(apiAuds, resp.Audiences)
    |-req.Header.Del("Authorization")
    |-req = req.WithContext(WithUser(req.Context(), resp.User))
    |-return handler.ServeHTTP(w, req)
```

## 2.1 认证（Authentication）

kube-apiserver 首先会对请求进行**认证（authentication）**，以确保 用户身份是合法的。apiserver 启动时，会注册一些 AuthN 相关的配置项，用户可以配置多个 authenticator，不同 authenticator 做的事情有所不同：

- [x509 handler](https://github.com/kubernetes/kubernetes/blob/v1.21.0/staging/src/k8s.io/apiserver/pkg/authentication/request/x509/x509.go#L198) 验证该 HTTP 请求是用 TLS key 加密的，并且有 CA root 证书的签名。
- [bearer token handler](https://github.com/kubernetes/kubernetes/blob/v1.21.0/staging/src/k8s.io/apiserver/pkg/authentication/request/bearertoken/bearertoken.go#L38) 验证请求中带的 token（HTTP Authorization 头中），在 apiserver 的 auth file 中是存在的（`--token-auth-file`）。
- [basicauth handler](https://github.com/kubernetes/kubernetes/blob/v1.21.0/staging/src/k8s.io/apiserver/plugin/pkg/authenticator/request/basicauth/basicauth.go#L37) 对 basic auth 信息进行校验。

**如果认证成功，就会将 Authorization header 从请求中删除**，然后在上下文中 [加上用户信息](https://github.com/kubernetes/kubernetes/blob/v1.21.0/staging/src/k8s.io/apiserver/pkg/endpoints/filters/authentication.go#L71-L75)， 这使得后面的步骤（例如鉴权和 admission control）能用到这里已经识别出的用户身份信息。

## 2.2 鉴权（Authorization）

**发送者身份（认证）是一个问题，但他是否有权限执行这个操作（鉴权），是另一个问题**。 因此确认发送者身份之后，还需要进行鉴权。

鉴权的过程与认证非常相似，也是逐个匹配 authorizer 列表中的 authorizer：如果都失败了， 返回 `Forbidden` 并停止 [进一步处理](https://github.com/kubernetes/kubernetes/blob/v1.21.0/staging/src/k8s.io/apiserver/pkg/endpoints/filters/authorization.go#L60)。如果成功，就继续。

内置的 **几种 authorizer 类型**：

- [webhook](https://github.com/kubernetes/kubernetes/blob/v1.21.0/staging/src/k8s.io/apiserver/plugin/pkg/authorizer/webhook/webhook.go#L143)： 与其他服务交互，验证是否有权限。
- [ABAC](https://github.com/kubernetes/kubernetes/blob/v1.21.0/pkg/auth/authorizer/abac/abac.go#L223)： 根据**静态文件中规定的策略**（policies）来进行鉴权。
- [RBAC](https://github.com/kubernetes/kubernetes/blob/v1.21.0/plugin/pkg/auth/authorizer/rbac/rbac.go#L43)： 根据 role 进行鉴权，其中 role 是 k8s 管理员提前配置的。
- [Node](https://github.com/kubernetes/kubernetes/blob/v1.21.0/plugin/pkg/auth/authorizer/node/node_authorizer.go#L67)： 确保 node clients，例如 kubelet，只能访问本机内的资源。

要看它们的具体做了哪些事情，可以查看它们各自的 `Authorize()` 方法。

## Admission control

至此，认证和鉴权都通过了。但这还没结束，K8s 中的**其它组件还需要对请求进行检查**， 其中就包括 [admission controllers](https://kubernetes.io/docs/admin/admission-controllers/#what-are-they)。

### 与鉴权的区别

- 鉴权（authorization）在前面，关注的是**用户是否有操作权限**，
- Admission controllers 在更后面，**对请求进行拦截和过滤，确保它们符合一些更广泛的集群规则和限制**， 是**将请求对象持久化到 etcd 之前的最后堡垒**。

### 工作方式

- 与认证和鉴权类似，也是遍历一个列表，
- 但有一点核心区别：**任何一个 controller 检查没通过，请求就会失败**。

### 设计：可扩展

- 每个 controller 作为一个 plugin 存放在[`plugin/pkg/admission` 目录](https://github.com/kubernetes/kubernetes/tree/master/plugin/pkg/admission),
- 设计时已经考虑，只需要实现很少的几个接口
- 但注意，**admission controller 最终会编译到 k8s 的二进制文件**（而非独立的 plugin binary）

### 类型

Admission controllers 通常按不同目的分类，包括：**资源管理、安全管理、默认值管 理、引用一致性**（referential consistency）等类型。

例如，下面是资源管理类的几个 controller：

- `InitialResources`：为容器设置默认的资源限制（基于过去的使用量）；
- `LimitRanger`：为容器的 requests and limits 设置默认值，或对特定资源设置上限（例如，内存默认 512MB，最高不超过 2GB）。
- `ResourceQuota`：资源配额。

# 3 写入 etcd

K8s 已经完成对请求的验证，允许它进行接下来的处理。

kube-apiserver 将**对请求进行反序列化，构造 runtime objects**（ kubectl generator 的反过程），并将它们**持久化到 etcd**。

## 调用栈概览

对于本文创建 pod 的请求，相应的入口是 [POST handler](https://github.com/kubernetes/kubernetes/blob/v1.21.0/staging/src/k8s.io/apiserver/pkg/endpoints/installer.go#L815) ，它又会进一步将请求委托给一个创建具体资源的 handler。

```
registerResourceHandlers // staging/src/k8s.io/apiserver/pkg/endpoints/installer.go
 |-case POST:
// staging/src/k8s.io/apiserver/pkg/endpoints/installer.go

        switch () {
        case "POST": // Create a resource.
            var handler restful.RouteFunction
            if isNamedCreater {
                handler = restfulCreateNamedResource(namedCreater, reqScope, admit)
            } else {
                handler = restfulCreateResource(creater, reqScope, admit)
            }

            handler = metrics.InstrumentRouteFunc(action.Verb, group, version, resource, subresource, .., handler)
            article := GetArticleForNoun(kind, " ")
            doc := "create" + article + kind
            if isSubresource {
                doc = "create " + subresource + " of" + article + kind
            }

            route := ws.POST(action.Path).To(handler).
                Doc(doc).
                Operation("create"+namespaced+kind+strings.Title(subresource)+operationSuffix).
                Produces(append(storageMeta.ProducesMIMETypes(action.Verb), mediaTypes...)...).
                Returns(http.StatusOK, "OK", producedObject).
                Returns(http.StatusCreated, "Created", producedObject).
                Returns(http.StatusAccepted, "Accepted", producedObject).
                Reads(defaultVersionedObject).
                Writes(producedObject)

            AddObjectParams(ws, route, versionedCreateOptions)
            addParams(route, action.Params)
            routes = append(routes, route)
        }

        for route := range routes {
            route.Metadata(ROUTE_META_GVK, metav1.GroupVersionKind{
                Group:   reqScope.Kind.Group,
                Version: reqScope.Kind.Version,
                Kind:    reqScope.Kind.Kind,
            })
            route.Metadata(ROUTE_META_ACTION, strings.ToLower(action.Verb))
            ws.Route(route)
        }
```

## kube-apiserver 请求处理过程

从 apiserver 的请求处理函数开始：

```
// staging/src/k8s.io/apiserver/pkg/server/handler.go

func (d director) ServeHTTP(w http.ResponseWriter, req *http.Request) {
    path := req.URL.Path

    // check to see if our webservices want to claim this path
    for _, ws := range d.goRestfulContainer.RegisteredWebServices() {
        switch {
        case ws.RootPath() == "/apis":
            if path == "/apis" || path == "/apis/" {
                return d.goRestfulContainer.Dispatch(w, req)
            }

        case strings.HasPrefix(path, ws.RootPath()):
            if len(path) == len(ws.RootPath()) || path[len(ws.RootPath())] == '/' {
                return d.goRestfulContainer.Dispatch(w, req)
            }
        }
    }

    // if we didn't find a match, then we just skip gorestful altogether
    d.nonGoRestfulMux.ServeHTTP(w, req)
}
```

如果能匹配到请求（例如匹配到前面注册的路由），它将 [分派给相应的 handler](https://github.com/kubernetes/kubernetes/blob/v1.21.0/staging/src/k8s.io/apiserver/pkg/server/handler.go#L136) ；否则，fall back 到 [path-based handler](https://github.com/kubernetes/kubernetes/blob/v1.21.0/staging/src/k8s.io/apiserver/pkg/server/mux/pathrecorder.go#L238) （`GET /apis` 到达的就是这里）；

基于 path 的 handlers：

```
// staging/src/k8s.io/apiserver/pkg/server/mux/pathrecorder.go

func (h *pathHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    if exactHandler, ok := h.pathToHandler[r.URL.Path]; ok {
        return exactHandler.ServeHTTP(w, r)
    }

    for prefixHandler := range h.prefixHandlers {
        if strings.HasPrefix(r.URL.Path, prefixHandler.prefix) {
            return prefixHandler.handler.ServeHTTP(w, r)
        }
    }

    h.notFoundHandler.ServeHTTP(w, r)
}
```

如果还是没有找到路由，就会 fallback 到 non-gorestful handler，最终可能是一个 not found handler。

对于我们的场景，会匹配到一条已经注册的、名为 [`createHandler`](https://github.com/kubernetes/kubernetes/blob/v1.21.0/staging/src/k8s.io/apiserver/pkg/endpoints/handlers/create.go#L37) 为的路由。

## Create handler 处理过程

```
// staging/src/k8s.io/apiserver/pkg/endpoints/handlers/create.go

func createHandler(r rest.NamedCreater, scope *RequestScope, admit Interface, includeName bool) http.HandlerFunc {
    return func(w http.ResponseWriter, req *http.Request) {
        namespace, name := scope.Namer.Name(req) // 获取资源的 namespace 和 name（etcd item key）
        s := negotiation.NegotiateInputSerializer(req, false, scope.Serializer)

        body := limitedReadBody(req, scope.MaxRequestBodyBytes)
        obj, gvk := decoder.Decode(body, &defaultGVK, original)

        admit = admission.WithAudit(admit, ae)

        requestFunc := func() (runtime.Object, error) {
            return r.Create(
                name,
                obj,
                rest.AdmissionToValidateObjectFunc(admit, admissionAttributes, scope),
            )
        }

        result := finishRequest(ctx, func() (runtime.Object, error) {
            if scope.FieldManager != nil {
                liveObj := scope.Creater.New(scope.Kind)
                obj = scope.FieldManager.UpdateNoErrors(liveObj, obj, managerOrUserAgent(options.FieldManager, req.UserAgent()))
                admit = fieldmanager.NewManagedFieldsValidatingAdmissionController(admit)
            }

            admit.(admission.MutationInterface)
            mutatingAdmission.Handles(admission.Create)
            mutatingAdmission.Admit(ctx, admissionAttributes, scope)

            return requestFunc()
        })

        code := http.StatusCreated
        status, ok := result.(*metav1.Status)
        transformResponseObject(ctx, scope, trace, req, w, code, outputMediaType, result)
    }
}
```

1. 首先解析 HTTP request，然后执行基本的验证，例如保证 JSON 与 versioned API resource 期望的是一致的；

2. 执行审计和最终 admission；

   这里会执行所谓的 **Mutation** 操作，例如，如果 pod 打了 `sidecar-injector-webhook.xxx/inject: true` 标签，并且配置了合适的 Mutation webhook 和 server， 在这一步就会给它**自动注入 sidecar**，完整例子可参考 IBM Cloud 博客 [Diving into Kubernetes MutatingAdmissionWebhook](https://medium.com/ibm-cloud/diving-into-kubernetes-mutatingadmissionwebhook-6ef3c5695f74)。

![img](https://arthurchiao.art/assets/img/what-happens-when-k8s-creates-pods/mutating-admission-webhook.jpg)

3. 将资源最终[写到 etcd](https://github.com/kubernetes/kubernetes/blob/v1.21.0/staging/src/k8s.io/apiserver/pkg/endpoints/handlers/create.go#L401)， 这会进一步调用到 [storage provider](https://github.com/kubernetes/kubernetes/blob/v1.21.0/staging/src/k8s.io/apiserver/pkg/registry/generic/registry/store.go#L362)。

   **etcd key 的格式一般是** `<namespace>/<name>`（例如，`default/nginx-0`），但这个也是可配置的。

4. 最后，storage provider 执行一次 `get` 操作，确保对象真的创建成功了。如果有额外的收尾任务（additional finalization），会执行 post-create handlers 和 decorators。

5. 返回 [生成的](https://github.com/kubernetes/kubernetes/blob/v1.21.0/staging/src/k8s.io/apiserver/pkg/endpoints/handlers/create.go#L131-L142) HTTP response。

另外，kube-apiserver 通过 ListWatch 监听了 etcd 的 pod 资源，因此 etcd 创建 pod 成功之后， kube-apiserver 会收到 `create` 事件，将 pod 信息更新到它的 in-memory cache 里。

# Initializers

**对象持久化到 etcd 之后，apiserver 并未将其置位对外可见，它也不会立即就被调度**， 而是要先等一些 [initializers](https://kubernetes.io/docs/admin/extensible-admission-controllers/#initializers) 运行完成。

## Initializer

Initializer 是**与特定资源类型（resource type）相关的 controller**，

- 负责**在该资源对外可见之前对它们执行一些处理**，
- 如果一种资源类型没有注册任何 initializer，这个步骤就会跳过，**资源对外立即可见**。

这是一种非常强大的特性，使得我们能**执行一些通用的启动初始化（bootstrap）操作**。例如，

- 向 Pod 注入 sidecar、暴露 80 端口，或打上特定的 annotation。
- 向某个 namespace 内的所有 pod 注入一个存放了测试证书（test certificates）的 volume。
- 禁止创建长度小于 20 个字符的 Secret （例如密码）

## InitializerConfiguration

可以用 `InitializerConfiguration` **声明对哪些资源类型（resource type）执行哪些 initializer**。

例如，要实现所有 pod 创建时都运行一个自定义的 initializer `custom-pod-initializer`， 可以用下面的 yaml：

```
apiVersion: admissionregistration.k8s.io/v1alpha1
kind: InitializerConfiguration
metadata:
  name: custom-pod-initializer
initializers:
  - name: podimage.example.com
    rules:
      - apiGroups:
          - ""
        apiVersions:
          - v1
        resources:
          - pods
```

创建以上配置（`kubectl create -f xx.yaml`）之后，K8s 会将 `custom-pod-initializer` **追加到每个 pod 的 `metadata.initializers.pending` 字段**。

在此之前需要**启动 initializer controller**，它会

- 定期扫描是否有新 pod 创建；
- 当**检测到它的名字出现在 pod 的 pending 字段**时，就会执行它的处理逻辑；
- 执行完成之后，它会将自己的名字从 pending list 中移除。

pending list 中的 initializers，每次只有第一个 initializer 能执行。 当**所有 initializer 执行完成，`pending` 字段为空**之后，就认为 **这个对象已经完成初始化了**（considered initialized）。

细心的同学可能会有疑问：**前面说这个对象还没有对外可见，那用 户空间的 initializer controller 又是如何能检测并操作这个对象的呢？**答案是： kube-apiserver 提供了一个 **`?includeUninitialized`** 查询参数，它会返回所有对象，包括那些还未完成初始化的（uninitialized ones）。

## InitializerConfiguration

可以用 `InitializerConfiguration` **声明对哪些资源类型（resource type）执行哪些 initializer**。

例如，要实现所有 pod 创建时都运行一个自定义的 initializer `custom-pod-initializer`， 可以用下面的 yaml：

```
apiVersion: admissionregistration.k8s.io/v1alpha1
kind: InitializerConfiguration
metadata:
  name: custom-pod-initializer
initializers:
  - name: podimage.example.com
    rules:
      - apiGroups:
          - ""
        apiVersions:
          - v1
        resources:
          - pods
```

创建以上配置（`kubectl create -f xx.yaml`）之后，K8s 会将 `custom-pod-initializer` **追加到每个 pod 的 `metadata.initializers.pending` 字段**。

在此之前需要**启动 initializer controller**，它会

- 定期扫描是否有新 pod 创建；
- 当**检测到它的名字出现在 pod 的 pending 字段**时，就会执行它的处理逻辑；
- 执行完成之后，它会将自己的名字从 pending list 中移除。

pending list 中的 initializers，每次只有第一个 initializer 能执行。 当**所有 initializer 执行完成，`pending` 字段为空**之后，就认为 **这个对象已经完成初始化了**（considered initialized）。

细心的同学可能会有疑问：**前面说这个对象还没有对外可见，那用 户空间的 initializer controller 又是如何能检测并操作这个对象的呢？**答案是： kube-apiserver 提供了一个 **`?includeUninitialized`** 查询参数，它会返回所有对象，包括那些还未完成初始化的（uninitialized ones）。

# 5 Control loops（控制循环）

至此，对象已经在 etcd 中了，所有的初始化步骤也已经完成了。 下一步是设置资源拓扑（resource topology）。例如，一个 Deployment 其实就是一组 ReplicaSet，而一个 ReplicaSet 就是一组 Pod。 K8s 是如何根据一个 HTTP 请求创建出这个层级关系的呢？靠的是 **K8s 内置的控制器**（controllers）。

K8s 中大量使用 “controllers”，

- 一个 controller 就是一个**异步脚本**（an asynchronous script），
- 不断检查资源的**当前状态**（current state）和**期望状态**（desired state）是否一致，
- 如果不一致就尝试将其变成期望状态，这个过程称为 **reconcile**。

每个 controller 负责的东西都比较少，**所有 controller 并行运行， 由 kube-controller-manager 统一管理**。

## 5.1 Deployments controller

### Deployments controller 启动

当一个 Deployment record 存储到 etcd 并（被 initializers）初始化之后， kube-apiserver 就会将其置为对外可见的。此后， Deployment controller 监听了 Deployment 资源的变动，因此此时就会检测到这个新创建的资源。

```
// pkg/controller/deployment/deployment_controller.go

// NewDeploymentController creates a new DeploymentController.
func NewDeploymentController(dInformer DeploymentInformer, rsInformer ReplicaSetInformer,
    podInformer PodInformer, client clientset.Interface) (*DeploymentController, error) {

    dc := &DeploymentController{
        client:        client,
        queue:         workqueue.NewNamedRateLimitingQueue(),
    }
    dc.rsControl = controller.RealRSControl{ // ReplicaSet controller
        KubeClient: client,
        Recorder:   dc.eventRecorder,
    }

    // 注册 Deployment 事件回调函数
    dInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
        AddFunc:    dc.addDeployment,    // 有 Deployment 创建时触发
        UpdateFunc: dc.updateDeployment,
        DeleteFunc: dc.deleteDeployment,
    })
    // 注册 ReplicaSet 事件回调函数
    rsInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
        AddFunc:    dc.addReplicaSet,
        UpdateFunc: dc.updateReplicaSet,
        DeleteFunc: dc.deleteReplicaSet,
    })
    // 注册 Pod 事件回调函数
    podInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
        DeleteFunc: dc.deletePod,
    })

    dc.syncHandler = dc.syncDeployment
    dc.enqueueDeployment = dc.enqueue

    return dc, nil
}
```

### 创建 Deployment：回调函数处理

在本文场景中，触发的是 controller [注册的 addDeployment() 回调函数](https://github.com/kubernetes/kubernetes/blob/v1.21.0/pkg/controller/deployment/deployment_controller.go#L122) 其所做的工作就是将 deployment 对象放到一个内部队列：

```
// pkg/controller/deployment/deployment_controller.go

func (dc *DeploymentController) addDeployment(obj interface{}) {
    d := obj.(*apps.Deployment)
    dc.enqueueDeployment(d)
}
```

### 主处理循环

worker 不断遍历这个 queue，从中 dequeue item 并进行处理：

```
// pkg/controller/deployment/deployment_controller.go

func (dc *DeploymentController) worker() {
    for dc.processNextWorkItem() {
    }
}

func (dc *DeploymentController) processNextWorkItem() bool {
    key, quit := dc.queue.Get()
    dc.syncHandler(key.(string)) // dc.syncHandler = dc.syncDeployment
}

// syncDeployment will sync the deployment with the given key.
func (dc *DeploymentController) syncDeployment(key string) error {
    namespace, name := cache.SplitMetaNamespaceKey(key)

    deployment := dc.dLister.Deployments(namespace).Get(name)
    d := deployment.DeepCopy()

    // 获取这个 Deployment 的所有 ReplicaSets, while reconciling ControllerRef through adoption/orphaning.
    rsList := dc.getReplicaSetsForDeployment(d)

    // 获取这个 Deployment 的所有 pods, grouped by their ReplicaSet
    podMap := dc.getPodMapForDeployment(d, rsList)

    if d.DeletionTimestamp != nil { // 这个 Deployment 已经被标记，等待被删除
        return dc.syncStatusOnly(d, rsList)
    }

    dc.checkPausedConditions(d)
    if d.Spec.Paused { // pause 状态
        return dc.sync(d, rsList)
    }

    if getRollbackTo(d) != nil {
        return dc.rollback(d, rsList)
    }

    scalingEvent := dc.isScalingEvent(d, rsList)
    if scalingEvent {
        return dc.sync(d, rsList)
    }

    switch d.Spec.Strategy.Type {
    case RecreateDeploymentStrategyType:             // re-create
        return dc.rolloutRecreate(d, rsList, podMap)
    case RollingUpdateDeploymentStrategyType:        // rolling-update
        return dc.rolloutRolling(d, rsList)
    }
    return fmt.Errorf("unexpected deployment strategy type: %s", d.Spec.Strategy.Type)
}
```

controller 会通过 label selector 从 kube-apiserver 查询 与这个 deployment 关联的 ReplicaSet 或 Pod records（然后发现没有）。

如果发现当前状态与预期状态不一致，就会触发同步过程（（synchronization process））。 这个同步过程是无状态的，也就是说，它并不区分是新记录还是老记录，一视同仁。

### 执行扩容（scale up）

如上，发现 pod 不存在之后，它会开始扩容过程（scaling process）：

```
// pkg/controller/deployment/sync.go

// scale up/down 或新创建（pause）时都会执行到这里
func (dc *DeploymentController) sync(d *apps.Deployment, rsList []*apps.ReplicaSet) error {

    newRS, oldRSs := dc.getAllReplicaSetsAndSyncRevision(d, rsList, false)
    dc.scale(d, newRS, oldRSs)

    // Clean up the deployment when it's paused and no rollback is in flight.
    if d.Spec.Paused && getRollbackTo(d) == nil {
        dc.cleanupDeployment(oldRSs, d)
    }

    allRSs := append(oldRSs, newRS)
    return dc.syncDeploymentStatus(allRSs, newRS, d)
}
```

大致步骤：

1. Rolling out (例如 creating）一个 ReplicaSet resource
2. 分配一个 label selector
3. 初始版本好（revision number）置为 1

ReplicaSet 的 PodSpec，以及其他一些 metadata 是从 Deployment 的 manifest 拷过来的。

最后会更新 deployment 状态，然后重新进入 reconciliation 循环，直到 deployment 进入预期的状态。

### 小结

由于 **Deployment controller 只负责 ReplicaSet 的创建**，因此下一步 （ReplicaSet -> Pod）要由 reconciliation 过程中的另一个 controller —— ReplicaSet controller 来完成。

## 5.2 ReplicaSets controller

上一步周，Deployments controller 已经创建了 Deployment 的第一个 ReplicaSet，但此时还没有任何 Pod。 下面就轮到 ReplicaSet controller 出场了。 它的任务是监控 ReplicaSet 及其依赖资源（pods）的生命周期，实现方式也是注册事件回调函数。

### ReplicaSets controller 启动

```
// pkg/controller/replicaset/replica_set.go

func NewReplicaSetController(rsInformer ReplicaSetInformer, podInformer PodInformer,
    kubeClient clientset.Interface, burstReplicas int) *ReplicaSetController {

    return NewBaseController(rsInformer, podInformer, kubeClient, burstReplicas,
        apps.SchemeGroupVersion.WithKind("ReplicaSet"),
        "replicaset_controller",
        "replicaset",
        controller.RealPodControl{
            KubeClient: kubeClient,
        },
    )
}

// 抽象出 NewBaseController() 是为了代码复用，例如 NewReplicationController() 也会调用这个函数。
func NewBaseController(rsInformer, podInformer, kubeClient clientset.Interface, burstReplicas int,
    gvk GroupVersionKind, metricOwnerName, queueName, podControl PodControlInterface) *ReplicaSetController {

    rsc := &ReplicaSetController{
        kubeClient:       kubeClient,
        podControl:       podControl,
        burstReplicas:    burstReplicas,
        expectations:     controller.NewUIDTrackingControllerExpectations(NewControllerExpectations()),
        queue:            workqueue.NewNamedRateLimitingQueue()
    }

    rsInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
        AddFunc:    rsc.addRS,
        UpdateFunc: rsc.updateRS,
        DeleteFunc: rsc.deleteRS,
    })
    rsc.rsLister = rsInformer.Lister()

    podInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
        AddFunc: rsc.addPod,
        UpdateFunc: rsc.updatePod,
        DeleteFunc: rsc.deletePod,
    })
    rsc.podLister = podInformer.Lister()

    rsc.syncHandler = rsc.syncReplicaSet
    return rsc
}
```

### 创建 ReplicaSet：回调函数处理

### 主处理循环

当一个 ReplicaSet 被（Deployment controller）创建之后，

```
// pkg/controller/replicaset/replica_set.go

// syncReplicaSet will sync the ReplicaSet with the given key if it has had its expectations fulfilled,
// meaning it did not expect to see any more of its pods created or deleted.
func (rsc *ReplicaSetController) syncReplicaSet(key string) error {

    namespace, name := cache.SplitMetaNamespaceKey(key)
    rs := rsc.rsLister.ReplicaSets(namespace).Get(name)

    selector := metav1.LabelSelectorAsSelector(rs.Spec.Selector)

    // 包括那些不匹配 rs selector，但有 stale controller ref 的 pod
    allPods := rsc.podLister.Pods(rs.Namespace).List(labels.Everything())
    filteredPods := controller.FilterActivePods(allPods) // Ignore inactive pods.
    filteredPods = rsc.claimPods(rs, selector, filteredPods)

    if rsNeedsSync && rs.DeletionTimestamp == nil { // 需要同步，并且没有被标记待删除
        rsc.manageReplicas(filteredPods, rs)        // *主处理逻辑*
    }

    newStatus := calculateStatus(rs, filteredPods, manageReplicasErr)
    updatedRS := updateReplicaSetStatus(AppsV1().ReplicaSets(rs.Namespace), rs, newStatus)
}
```

RS controller 检查 ReplicaSet 的状态， 发现当前状态和期望状态之间有偏差（skew），因此接下来调用 `manageReplicas()` 来 reconcile 这个状态，在这里做的事情就是增加这个 ReplicaSet 的 pod 数量。

```
// pkg/controller/replicaset/replica_set.go

func (rsc *ReplicaSetController) manageReplicas(filteredPods []*v1.Pod, rs *apps.ReplicaSet) error {
    diff := len(filteredPods) - int(*(rs.Spec.Replicas))
    rsKey := controller.KeyFunc(rs)

    if diff < 0 {
        diff *= -1
        if diff > rsc.burstReplicas {
            diff = rsc.burstReplicas
        }

        rsc.expectations.ExpectCreations(rsKey, diff)
        successfulCreations := slowStartBatch(diff, controller.SlowStartInitialBatchSize, func() {
            return rsc.podControl.CreatePodsWithControllerRef( // 扩容
                // 调用栈 CreatePodsWithControllerRef -> createPod() -> Client.CoreV1().Pods().Create()
                rs.Namespace, &rs.Spec.Template, rs, metav1.NewControllerRef(rs, rsc.GroupVersionKind))
        })

        // The skipped pods will be retried later. The next controller resync will retry the slow start process.
        if skippedPods := diff - successfulCreations; skippedPods > 0 {
            for i := 0; i < skippedPods; i++ {
                // Decrement the expected number of creates because the informer won't observe this pod
                rsc.expectations.CreationObserved(rsKey)
            }
        }
        return err
    } else if diff > 0 {
        if diff > rsc.burstReplicas {
            diff = rsc.burstReplicas
        }

        relatedPods := rsc.getIndirectlyRelatedPods(rs)
        podsToDelete := getPodsToDelete(filteredPods, relatedPods, diff)
        rsc.expectations.ExpectDeletions(rsKey, getPodKeys(podsToDelete))

        for _, pod := range podsToDelete {
            go func(targetPod *v1.Pod) {
                rsc.podControl.DeletePod(rs.Namespace, targetPod.Name, rs) // 缩容
            }(pod)
        }
    }

    return nil
}
```

增加 pod 数量的操作比较小心，每次最多不超过 burst count（这个配置是从 ReplicaSet 的父对象 Deployment 那里继承来的）。

另外，创建 Pods 的过程是 [批处理的](https://github.com/kubernetes/kubernetes/blob/v1.21.0/pkg/controller/replicaset/replica_set.go#L487), “慢启动”操，开始时是 `SlowStartInitialBatchSize`，每执行成功一批，下次的 batch size 就翻倍。 这样设计是为了避免给 kube-apiserver 造成不必要的压力，例如，如果由于 quota 不足，这批 pod 大部分都会失败，那 这种方式只会有一小批请求到达 kube-apiserver，而如果一把全上的话，请求全部会打过去。 同样是失败，这种失败方式比较优雅。

### Owner reference

K8s **通过 Owner Reference**（子资源中的一个字段，指向的是其父资源的 ID） **维护对象层级**（hierarchy）。这可以带来两方面好处：

1. 实现了 cascading deletion，即父对象被 GC 时会确保 GC 子对象；
2. 父对象之间不会出现竞争子对象的情况（例如，两个父对象认为某个子对象都是自己的）

另一个隐藏的好处是：Owner Reference 是有状态的：如果 controller 重启，重启期间不会影响 系统的其他部分，因为资源拓扑（resource topology）是独立于 controller 的。 这种隔离设计也体现在 controller 自己的设计中：**controller 不应该操作 其他 controller 的资源**（resources they don’t explicitly own）。

有时也可能会出现“孤儿”资源（”orphaned” resources）的情况，例如

1. 父资源删除了，子资源还在；
2. GC 策略导致子资源无法被删除。

这种情况发生时，**controller 会确保孤儿资源会被某个新的父资源收养**。 多个父资源都可以竞争成为孤儿资源的父资源，但只有一个会成功（其余的会收到一个 validation 错误）。

## 5.3 Informers

很多 controller（例如 RBAC authorizer 或 Deployment controller）需要将集群信息拉到本地。

例如 RBAC authorizer 中，authenticator 会将用户信息保存到请求上下文中。随后， RBAC authorizer 会用这个信息获取 etcd 中所有与这个用户相关的 role 和 role bindings。

那么，controller 是如何访问和修改这些资源的？在 K8s 中，这是通过 informer 机制实现的。

**informer 是一种 controller 订阅存储（etcd）事件的机制**，能方便地获取它们感兴趣的资源。

- 这种方式除了提供一种很好的抽象之外，还负责处理缓存（caching，非常重要，因为可 以减少 kube-apiserver 连接数，降低 controller 侧和 kube-apiserver 侧的序列化 成本）问题。
- 此外，这种设计还使得 controller 的行为是 threadsafe 的，避免影响其他组件或服务。

关于 informer 和 controller 的联合工作机制，可参考 [这篇博客](http://borismattijssen.github.io/articles/kubernetes-informers-controllers-reflectors-stores)。

## 5.4 Scheduler（调度器）

以上 controllers 执行完各自的处理之后，etcd 中已经有了一个 Deployment、一个 ReplicaSet 和三个 Pods，可以通过 kube-apiserver 查询到。 但此时，**这三个 pod 还卡在 Pending 状态，因为它们还没有被调度到任何节点**。 **另外一个 controller —— 调度器** —— 负责做这件事情。

scheduler 作为控制平面的一个独立服务运行，但**工作方式与其他 controller 是一样的**： 监听事件，然后尝试 reconcile 状态。作为一个无限循环，scheduler 会寻找所有 **`nodeName`** 字段为空的 pod，为它们选择合适的 node，这就是调度过程。

### 调用栈概览

```
Run // pkg/scheduler/scheduler.go 
  |-SchedulingQueue.Run()
  |
  |-scheduleOne()
     |-bind
     |  |-RunBindPlugins
     |     |-runBindPlugins
     |        |-Bind
     |-sched.Algorithm.Schedule(pod)
        |-findNodesThatFitPod
        |-prioritizeNodes
        |-selectHost
```

### 调度过程

```
// pkg/scheduler/core/generic_scheduler.go

// 将 pod 调度到指定 node list 中的某台 node 上
func (g *genericScheduler) Schedule(ctx context.Context, fwk framework.Framework,
    state *framework.CycleState, pod *v1.Pod) (result ScheduleResult, err error) {

    feasibleNodes, diagnosis := g.findNodesThatFitPod(ctx, fwk, state, pod) // 过滤可用 nodes
    if len(feasibleNodes) == 0
        return result, &framework.FitError{}

    if len(feasibleNodes) == 1 // 可用 node 只有一个，就选它了
        return ScheduleResult{SuggestedHost:  feasibleNodes[0].Name}, nil

    priorityList := g.prioritizeNodes(ctx, fwk, state, pod, feasibleNodes)
    host := g.selectHost(priorityList)

    return ScheduleResult{
        SuggestedHost:  host,
        EvaluatedNodes: len(feasibleNodes) + len(diagnosis.NodeToStatusMap),
        FeasibleNodes:  len(feasibleNodes),
    }, err
}

// Filters nodes that fit the pod based on the framework filter plugins and filter extenders.
func (g *genericScheduler) findNodesThatFitPod(ctx context.Context, fwk framework.Framework,
    state *framework.CycleState, pod *v1.Pod) ([]*v1.Node, framework.Diagnosis, error) {

    diagnosis := framework.Diagnosis{
        NodeToStatusMap:      make(framework.NodeToStatusMap),
        UnschedulablePlugins: sets.NewString(),
    }

    // Run "prefilter" plugins.
    s := fwk.RunPreFilterPlugins(ctx, state, pod)
    allNodes := g.nodeInfoSnapshot.NodeInfos().List()

    if len(pod.Status.NominatedNodeName) > 0 && featureGate.Enabled(features.PreferNominatedNode) {
        feasibleNodes := g.evaluateNominatedNode(ctx, pod, fwk, state, diagnosis)
        if len(feasibleNodes) != 0 {
            return feasibleNodes, diagnosis, nil
        }
    }

    feasibleNodes := g.findNodesThatPassFilters(ctx, fwk, state, pod, diagnosis, allNodes)
    feasibleNodes = g.findNodesThatPassExtenders(pod, feasibleNodes, diagnosis.NodeToStatusMap)
    return feasibleNodes, diagnosis, nil
}
```

它会 [过滤 PodSpect 中 NodeName 字段为空的 pods](https://github.com/kubernetes/kubernetes/blob/v1.25.0/pkg/scheduler/) ，尝试为这样的 pods 挑选一个 node 调度上去。

### 调度算法

#### Resource requests/limits

如果 PodSpec 里面设置了 **`requests/limits`**，即 **显式要求了 CPU/memory 资源**，那无法满足这些条件的 node 就会被从备选列表中删除。

但要注意，**调度只看 requests，不看 limits**。例如，如果设置了 memory `request=1GB,limit=2GB`，那只要一台 node 的剩余可分配内存在 1GB 以上，就是符合要求的 node。

下面简单看下内置的默认调度算法。

#### 注册默认 predicates

这些 predicates 其实都是函数，被调用到时，执行相应的 [过滤](https://github.com/kubernetes/kubernetes/blob/v1.21.0/plugin/pkg/scheduler/core/generic_scheduler.go#L117)。

```
// pkg/scheduler/algorithmprovider/registry.go

// NewRegistry returns an algorithm provider registry instance.
func NewRegistry() Registry {
    defaultConfig := getDefaultConfig()
    applyFeatureGates(defaultConfig)

    caConfig := getClusterAutoscalerConfig()
    applyFeatureGates(caConfig)

    return Registry{
        schedulerapi.SchedulerDefaultProviderName: defaultConfig,
        ClusterAutoscalerProvider:                 caConfig,
    }
}

func getDefaultConfig() *schedulerapi.Plugins {
    plugins := &schedulerapi.Plugins{
        PreFilter: schedulerapi.PluginSet{...},
        Filter: schedulerapi.PluginSet{
            Enabled: []schedulerapi.Plugin{
                {Name: nodename.Name},        // 指定 node name 调度
                {Name: tainttoleration.Name}, // 指定 toleration 调度
                {Name: nodeaffinity.Name},    // 指定 node affinity 调度
                ...
            },
        },
        PostFilter: schedulerapi.PluginSet{...},
        PreScore: schedulerapi.PluginSet{...},
        Score: schedulerapi.PluginSet{
            Enabled: []schedulerapi.Plugin{
                {Name: interpodaffinity.Name, Weight: 1},
                {Name: nodeaffinity.Name, Weight: 1},
                {Name: tainttoleration.Name, Weight: 1},
                ...
            },
        },
        Reserve: schedulerapi.PluginSet{...},
        PreBind: schedulerapi.PluginSet{...},
        Bind: schedulerapi.PluginSet{...},
    }

    return plugins
}
```

plugin 的实现见 `pkg/scheduler/framework/plugins/`，以 `nodename` filter 为例：

```
// pkg/scheduler/framework/plugins/nodename/node_name.go

// Filter invoked at the filter extension point.
func (pl *NodeName) Filter(ctx context.Context, pod *v1.Pod, nodeInfo *framework.NodeInfo) *framework.Status {
    if !Fits(pod, nodeInfo) {
        return framework.NewStatus(UnschedulableAndUnresolvable, ErrReason)
    }
    return nil
}

// 如果 pod 没有指定 NodeName，或者指定的 NodeName 等于该 node 的 name，返回 true；其他返回 false
func Fits(pod *v1.Pod, nodeInfo *framework.NodeInfo) bool {
    return len(pod.Spec.NodeName) == 0 || pod.Spec.NodeName == nodeInfo.Node().Name
}
```

#### 对筛选出的 node 排序

选择了合适的 nodes 之后，接下来会执行一系列 priority function **对这些 nodes 进行排序**。 例如，如果算法是希望将 pods 尽量分散到整个集群，那 priority 会选择资源尽量空闲的节点。

这些函数会给每个 node 打分，**得分最高的 node 会被选中**，调度到该节点。

```
// pkg/scheduler/core/generic_scheduler.go

// 运行打分插件（score plugins）对 nodes 进行排序。
func (g *genericScheduler) prioritizeNodes(ctx context.Context, fwk framework.Framework,
    state *framework.CycleState, pod *v1.Pod, nodes []*v1.Node,) (framework.NodeScoreList, error) {

    // 如果没有指定 priority 配置，所有 node 将都得 1 分。
    if len(g.extenders) == 0 && !fwk.HasScorePlugins() {
        result := make(framework.NodeScoreList, 0, len(nodes))
        for i := range nodes {
            result = append(result, framework.NodeScore{ Name:  nodes[i].Name, Score: 1 })
        }
        return result, nil
    }

    preScoreStatus := fwk.RunPreScorePlugins(ctx, state, pod, nodes)       // PreScoe 插件
    scoresMap, scoreStatus := fwk.RunScorePlugins(ctx, state, pod, nodes)  // Score 插件

    result := make(framework.NodeScoreList, 0, len(nodes))
    for i := range nodes {
        result = append(result, framework.NodeScore{Name: nodes[i].Name, Score: 0})
        for j := range scoresMap {
            result[i].Score += scoresMap[j][i].Score
        }
    }

    if len(g.extenders) != 0 && nodes != nil {
        combinedScores := make(map[string]int64, len(nodes))
        for i := range g.extenders {
            if !g.extenders[i].IsInterested(pod) {
                continue
            }
            go func(extIndex int) {
                prioritizedList, weight := g.extenders[extIndex].Prioritize(pod, nodes)
                for i := range *prioritizedList {
                    host, score := (*prioritizedList)[i].Host, (*prioritizedList)[i].Score
                    combinedScores[host] += score * weight
                }
            }(i)
        }

        for i := range result {
            result[i].Score += combinedScores[result[i].Name] * (MaxNodeScore / MaxExtenderPriority)
        }
    }

    return result, nil
}
```

### 创建 `v1.Binding` 对象

算法选出一个 node 之后，调度器会 [创建一个 Binding 对象](https://github.com/kubernetes/kubernetes/blob/v1.21.0/plugin/pkg/scheduler/scheduler.go#L336-L342)， Pod 的 **ObjectReference 字段的值就是选中的 node 的名字**。

```
// pkg/scheduler/framework/runtime/framework.go

func (f *frameworkImpl) runBindPlugin(ctx context.Context, bp BindPlugin, state *CycleState,
    pod *v1.Pod, nodeName string) *framework.Status {

    if !state.ShouldRecordPluginMetrics() {
        return bp.Bind(ctx, state, pod, nodeName)
    }

    status := bp.Bind(ctx, state, pod, nodeName)
    return status
}
// pkg/scheduler/framework/plugins/defaultbinder/default_binder.go

// Bind binds pods to nodes using the k8s client.
func (b DefaultBinder) Bind(ctx, state *CycleState, p *v1.Pod, nodeName string) *framework.Status {
    binding := &v1.Binding{
        ObjectMeta: metav1.ObjectMeta{Namespace: p.Namespace, Name: p.Name, UID: p.UID},
        Target:     v1.ObjectReference{Kind: "Node", Name: nodeName}, // ObjectReference 字段为 nodeName
    }

    b.handle.ClientSet().CoreV1().Pods(binding.Namespace).Bind(ctx, binding, metav1.CreateOptions{})
}
```

如上，最后 `ClientSet().CoreV1().Pods(binding.Namespace).Bind()` 通过一个 **POST 请求发给 apiserver**。

### kube-apiserver 更新 pod 对象

kube-apiserver 收到这个 Binding object 请求后，registry 反序列化对象，更新 Pod 对象的下列字段：

- 设置 NodeName
- 添加 annotations
- 设置 `PodScheduled` status 为 `True`

```
// pkg/registry/core/pod/storage/storage.go

func (r *BindingREST) setPodHostAndAnnotations(ctx context.Context, podID, oldMachine, machine string,
    annotations map[string]string, dryRun bool) (finalPod *api.Pod, err error) {

    podKey := r.store.KeyFunc(ctx, podID)
    r.store.Storage.GuaranteedUpdate(ctx, podKey, &api.Pod{}, false, nil,
        storage.SimpleUpdate(func(obj runtime.Object) (runtime.Object, error) {

        pod, ok := obj.(*api.Pod)
        pod.Spec.NodeName = machine
        if pod.Annotations == nil {
            pod.Annotations = make(map[string]string)
        }
        for k, v := range annotations {
            pod.Annotations[k] = v
        }
        podutil.UpdatePodCondition(&pod.Status, &api.PodCondition{
            Type:   api.PodScheduled,
            Status: api.ConditionTrue,
        })

        return pod, nil
    }), dryRun, nil)
}
```

### 自定义调度器

> predicate 和 priority function 都是可扩展的，可以通过 `--policy-config-file` 指定。
>
> K8s 还可以自定义调度器（自己实现调度逻辑）。 **如果 PodSpec 中 schedulerName 字段不为空**，K8s 就会 将这个 pod 的调度权交给指定的调度器。

## 5.5 小结

总结一下前面已经完成的步骤：

1. HTTP 请求通过了认证、鉴权、admission control
2. Deployment, ReplicaSet 和 Pod resources 已经持久化到 etcd
3. 一系列 initializers 已经执行完毕，
4. 每个 Pod 也已经调度到了合适的 node 上。

但是，**到目前为止，我们看到的所有东西（状态），还只是存在于 etcd 中的元数据**。 下一步就是将这些状态同步到计算节点上，然后计算节点上的 agent（kubelet）就开始干活了。

# 6 kubelet

每个 K8s node 上都会运行一个名为 kubelet 的 agent，它负责

- pod 生命周期管理。

  这意味着，它负责将 “Pod” 的逻辑抽象（etcd 中的元数据）转换成具体的容器（container）。

- 挂载目录

- 创建容器日志

- 垃圾回收等等

## Pod sync（状态同步）

**kubelet 也可以认为是一个 controller**，它

1. 通过 ListWatch 接口，从 kube-apiserver **获取属于本节点的 Pod 列表**（根据 `spec.nodeName` [过滤](https://github.com/kubernetes/kubernetes/blob/v1.21.0/pkg/kubelet/config/apiserver.go#L32)），
2. 然后**与自己缓存的 pod 列表对比**，如果有 pod 创建、删除、更新等操作，就开始同步状态。

下面具体看一下同步过程。

### 同步过程

```
// pkg/kubelet/kubelet.go

// syncPod is the transaction script for the sync of a single pod.
func (kl *Kubelet) syncPod(o syncPodOptions) error {
    pod := o.pod

    if updateType == SyncPodKill { // kill pod 操作
        kl.killPod(pod, nil, podStatus, PodTerminationGracePeriodSecondsOverride)
        return nil
    }

    firstSeenTime := pod.Annotations["kubernetes.io/config.seen"] // 测量 latency，从 apiserver 第一次看到 pod 算起

    if updateType == SyncPodCreate { // create pod 操作
        if !firstSeenTime.IsZero() { // Record pod worker start latency if being created
            metrics.PodWorkerStartDuration.Observe(metrics.SinceInSeconds(firstSeenTime))
        }
    }

    // Generate final API pod status with pod and status manager status
    apiPodStatus := kl.generateAPIPodStatus(pod, podStatus)

    podStatus.IPs = []string{}
    if len(podStatus.IPs) == 0 && len(apiPodStatus.PodIP) > 0 {
        podStatus.IPs = []string{apiPodStatus.PodIP}
    }

    runnable := kl.canRunPod(pod)
    if !runnable.Admit { // Pod is not runnable; update the Pod and Container statuses to why.
        apiPodStatus.Reason = runnable.Reason
        ...
    }

    kl.statusManager.SetPodStatus(pod, apiPodStatus)

    // Kill pod if it should not be running
    if !runnable.Admit || pod.DeletionTimestamp != nil || apiPodStatus.Phase == v1.PodFailed {
        return kl.killPod(pod, nil, podStatus, nil)
    }

    // 如果 network plugin not ready，并且 pod 网络不是 host network 类型，返回相应错误
    if err := kl.runtimeState.networkErrors(); err != nil && !IsHostNetworkPod(pod) {
        return fmt.Errorf("%s: %v", NetworkNotReadyErrorMsg, err)
    }

    // Create Cgroups for the pod and apply resource parameters if cgroups-per-qos flag is enabled.
    pcm := kl.containerManager.NewPodContainerManager()

    if kubetypes.IsStaticPod(pod) { // Create Mirror Pod for Static Pod if it doesn't already exist
        ...
    }

    kl.makePodDataDirs(pod)                     // Make data directories for the pod
    kl.volumeManager.WaitForAttachAndMount(pod) // Wait for volumes to attach/mount
    pullSecrets := kl.getPullSecretsForPod(pod) // Fetch the pull secrets for the pod

    // Call the container runtime's SyncPod callback
    result := kl.containerRuntime.SyncPod(pod, podStatus, pullSecrets, kl.backOff)
    kl.reasonCache.Update(pod.UID, result)
}
```

1. 如果是 pod 创建事件，会记录一些 pod latency 相关的 metrics；

2. 然后调用 `generateAPIPodStatus()` **生成一个 v1.PodStatus 对象**，代表 pod 当前阶段（Phase）的状态。

   Pod 的 Phase 是对其生命周期中不同阶段的高层抽象，非常复杂，后面会介绍。

3. PodStatus 生成之后，将发送给 Pod status manager，后者的任务是**异步地通过 apiserver 更新 etcd 记录**。

4. 接下来会**运行一系列 admission handlers**，确保 pod 有正确的安全权限（security permissions）。

   其中包括 enforcing [AppArmor profiles and `NO_NEW_PRIVS`](https://github.com/kubernetes/kubernetes/blob/v1.21.0/pkg/kubelet/kubelet.go#L883-L884)。 在这个阶段**被 deny 的 Pods 将无限期处于 Pending 状态**。

5. 如果指定了 `cgroups-per-qos`，kubelet 将为这个 pod 创建 cgroups。可以实现更好的 QoS。

6. **为容器创建一些目录**。包括

   - pod 目录 （一般是 `/var/run/kubelet/pods/<podID>`）
   - volume 目录 (`<podDir>/volumes`)
   - plugin 目录 (`<podDir>/plugins`).

7. volume manager 将 [等待](https://github.com/kubernetes/kubernetes/blob/2723e06a251a4ec3ef241397217e73fa782b0b98/pkg/kubelet/volumemanager/volume_manager.go#L330) `Spec.Volumes` 中定义的 volumes attach 完成。取决于 volume 类型，pod 可能会等待很长时间（例如 cloud 或 NFS volumes）。

8. 从 apiserver 获取 `Spec.ImagePullSecrets` 中指定的 **secrets，注入容器**。

9. **容器运行时（runtime）创建容器**（后面详细描述）。

### Pod 状态

前面提到，`generateAPIPodStatus()` [生成一个 v1.PodStatus](https://github.com/kubernetes/kubernetes/blob/v1.21.0/pkg/kubelet/kubelet_pods.go#L1287) 对象，代表 pod 当前阶段（Phase）的状态。

Pod 的 Phase 是对其生命周期中不同阶段的高层抽象，包括

- `Pending`
- `Running`
- `Succeeded`
- `Failed`
- `Unknown`

生成这个状态的过程非常复杂，一些细节如下：

1. 首先，顺序执行一系列 `PodSyncHandlers` 。每个 handler **判断这个 pod 是否还应该留在这个 node 上**。 如果其中任何一个判断结果是否，那 pod 的 phase [将变为](https://github.com/kubernetes/kubernetes/blob/v1.21.0/pkg/kubelet/kubelet_pods.go#L1293-L1297) `PodFailed` 并最终会被**从这个 node 驱逐**。

   一个例子是 pod 的 `activeDeadlineSeconds` （Jobs 中会用到）超时之后，就会被驱逐。

2. 接下来决定 Pod Phase 的将是其 init 和 real containers。由于此时容器还未启动，因此 将**处于** [waiting](https://github.com/kubernetes/kubernetes/blob/v1.21.0/pkg/kubelet/kubelet_pods.go#L1244) **状态**。 **有 waiting 状态 container 的 pod，将处于 [`Pending`](https://github.com/kubernetes/kubernetes/blob/v1.21.0/pkg/kubelet/kubelet_pods.go#L1258-L1261) Phase**。

3. 由于此时容器运行时还未创建我们的容器 ，因此它将把 [`PodReady` 字段置为 False](https://github.com/kubernetes/kubernetes/blob/v1.21.0/pkg/kubelet/status/generate.go#L70-L81).

## CRI 及创建 pause 容器

至此，大部分准备工作都已完成，接下来即将创建容器了。**创建容器是通过 Container Runtime （例如 `docker` 或 `rkt`）完成的**。

为实现可扩展，kubelet 从 v1.5.0 开始，**使用 CRI（Container Runtime Interface）与具体的容器运行时交互**。 简单来说，CRI 提供了 kubelet 和具体 runtime implementation 之间的抽象接口， 用 [protocol buffers](https://github.com/google/protobuf) 和 gRPC 通信。

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

# 番外 创建带有PV的Pod

## 背景知识

### K8s CSI (Container Storage Interface )

> The Container Storage Interface (CSI) is a standard for exposing arbitrary block and file storage systems to containerized workloads on Container Orchestration Systems (COs) like Kubernetes.
>
> https://kubernetes-csi.github.io/docs/

CSI 是 K8s 支持的一种容器存储机制，扩展性非常好， 各存储方案只要根据规范实现一些接口，就能集成到 k8s 中提供存储服务。

一般来说，存储方案需要在每个 node 上部署一个称为 “**`CSI plugin`**” 的服务， kubelet 在创建带 PV 容器的过程中会调用这个 plugin。但要注意，

- K8s 的**网络插件** CNI plugin 是一个**可执行文件**， 放在 `/opt/cni/bin/` 下面就行了，kubelet 在创建 pod 网络时**直接运行** 这个可执行文件；
- K8s 的**存储插件** CSI plugin 是一个**服务**（某种程度上， 称为 **`agent`** 更好理解），kubelet 在初始化 PV 时通过 **`gRPC`** 调用这个 plugin；

### FUSE (Filesystem in Userspace)

FUSE 是一种用户态文件系统，使得用户开发自己的文件系统非常方便。

借 **`lxcfs`**（跟 juicefs 没关系，但也是一种 FUSE 文件系统）展示一下 **FUSE 的基本工作原理**：

![img](https://arthurchiao.art/assets/img/linux-container-and-runtime/lxcfs-fuse.png)

JuiceFS 基于 FUSE 实现了一个用户态文件系统。

> 来自社区文档的一段内容，简单整理：
>
> 传统上，实现一个 FUSE 文件系统，需要基于 Linux libfuse 库，它提供两种 API：
>
> - high-level API：**基于文件名和路径**。
>
>   libfuse 内部做了 VFS 树的模拟，对外暴露基于路径的 API。
>
>   适合元数据本身是基于路径提供的 API 的系统，比如 HDFS 或者 S3 之类。 如果元数据本身是基于 inode 的目录树，这种 inode → path →inode 的转换就会 影响性能。
>
> - low-level API：**基于 inode**。内核的 VFS 跟 FUSE 库交互就使用 low-level API。
>
> JuiceFS 的**元数据基于 inode 组织**，所以用 low-level API 实现（ 依赖 go-fuse 而非 libfuse），简单自然，性能好。

### JuiceFS 三种工作模式

JuiceFS 有几种工作或部署方式：

1. 进程挂载模式

   JuiceFS client 运行在 CSI Node plugin 容器中，所有需要挂载的 JuiceFS PV 都会在这个容器内以进程模式挂载。

2. CSI 方式，又可分为两种：

   1. mountpod 方式：在每个 node 上，CSI plugin 动态为每个**被 local pod 使用的 PV** 创建一个保姆 pod，

      - 这个 mount pod 是 **`per-PV`** 而非 per-business-pod 的， 也就是说如果 node 上有**多个业务 pod 在使用同一 PV，那只会有一个 mount pod**， 下图可以看出来，

        ![img](https://arthurchiao.art/assets/img/k8s-juicefs-csi/juicefs-pod-setup-workflow.png)

        Fig. JuiceFS as K8s CSI solution: workflow when a business pod is created (JuiceFS mountpod mode).

      - mount pod 里面装了 **`juicefs client`**，替业务 pod 完成 juicefs 相关的读写操作； 为了从字面上更容易理解，本文接下来把 mount pod 称为 **`dynamic client pod`** 或 client pod。

      - 这是 JuiceFS CSI 的**默认工作方式**；

      - FUSE 需要 mount pod 具有 privilege 权限；

      - client pod 重启会导致业务 pod 一段时间读写不可用，但 client pod 好了之后业务 pod 就能继续读写了。

   2. . CSI sidecar 方式：给每个使用 juicefs PV 的业务 pod 创建一个 sidecar 容器。

      - **`per-pod`** 级别的 sidecar；
      - 注意 sidecar 就不是 JuiceFS plugin 创建的了，CSI Controller 会注册一个 Webhook 来监听容器变动，在创建 pod 时， webhook 给 pod yaml 自动注入一个 sidecar，跟 Istio 自动给 pod 注入 Envoy 容器类似；
      - Sidecar 重启需要重建业务 Pod 才能恢复。
      - 也依赖 FUSE，所以 sidecar 需要 privilege 权限。这会导致**每个 sidecar 都能看到 node 上所有设备**，有风险，所以不建议；

# 创建一个使用 PV 的 pod 时，k8s 和 juicefs 组件都做了什么

![img](https://arthurchiao.art/assets/img/k8s-juicefs-csi/juicefs-pod-setup-workflow.png)

## Step 1：kubelet 启动，监听集群的 pod 资源变化

kubelet 作为 k8s 在每个 node 上的 agent，在启动后会监听整个 k8s 集群中的 pod 资源变化。 具体来说就是，kube-apiserver 中有 **`pod create/update/delete events`** 发生时，kubelet 都会立即收到。

## Step 2：kubelet 收到业务 pod 创建事件，**开始创建** pod

kubelet 收到一条 **`pod create`** 事件后，首先判断这个 pod 是否在自己的管辖范围内（spec 中的 **nodeName 是否是这台 node**）， 是的话就**开始创建这个 pod**。

### Step 2.1 创建业务 pod：初始化部分

**`kubelet.INFO`** 中有比较详细的日志：

```
10:05:57.410  Receiving a new pod "pod1(<pod1-id>)"
10:05:57.411  SyncLoop (ADD, "api"): "pod1(<pod1-id>)"
10:05:57.411  Needs to allocate 2 "nvidia.com/gpu" for pod "<pod1-id>" container "container1"
10:05:57.411  Needs to allocate 1 "our-corp.com/ip" for pod "<pod1-id>" container "container1"
10:05:57.413  Cgroup has some missing paths: [/sys/fs/cgroup/pids/kubepods/burstable/pod<pod1-id> /sys/fs/cgroup/systemd/kubepods/burstable/pod<pod1-id> /sys/fs/cgroup/cpuset/kubepods/burstable/pod<pod1-id> /sys/fs/cgroup/memory/kubepods/burstable/pod<pod1-id> /sys/fs/cgroup/cpu,cpuacct/kubepods/burstable/pod<pod1-id> /sys/fs/cgroup/cpu,cpuacct/kubepods/burstable/pod<pod1-id> /sys/fs/cgroup/hugetlb/kubepods/burstable/pod<pod1-id>]
10:05:57.413  Cgroup has some missing paths: [/sys/fs/cgroup/memory/kubepods/burstable/pod<pod1-id> /sys/fs/cgroup/systemd/kubepods/burstable/pod<pod1-id> /sys/fs/cgroup/cpu,cpuacct/kubepods/burstable/pod<pod1-id> /sys/fs/cgroup/cpu,cpuacct/kubepods/burstable/pod<pod1-id> /sys/fs/cgroup/hugetlb/kubepods/burstable/pod<pod1-id> /sys/fs/cgroup/pids/kubepods/burstable/pod<pod1-id> /sys/fs/cgroup/cpuset/kubepods/burstable/pod<pod1-id>]
10:05:57.413  Cgroup has some missing paths: [/sys/fs/cgroup/cpu,cpuacct/kubepods/burstable/pod<pod1-id> /sys/fs/cgroup/pids/kubepods/burstable/pod<pod1-id> /sys/fs/cgroup/cpuset/kubepods/burstable/pod<pod1-id> /sys/fs/cgroup/systemd/kubepods/burstable/pod<pod1-id> /sys/fs/cgroup/memory/kubepods/burstable/pod<pod1-id> /sys/fs/cgroup/cpu,cpuacct/kubepods/burstable/pod<pod1-id> /sys/fs/cgroup/hugetlb/kubepods/burstable/pod<pod1-id>]
10:05:57.415  Using factory "raw" for container "/kubepods/burstable/pod<pod1-id>"
10:05:57.415  Added container: "/kubepods/burstable/pod<pod1-id>" (aliases: [], namespace: "")
10:05:57.419  Waiting for volumes to attach and mount for pod "pod1(<pod1-id>)"

10:05:57.432  SyncLoop (RECONCILE, "api"): "pod1(<pod1-id>)"

10:05:57.471  Added volume "meminfo" (volSpec="meminfo") for pod "<pod1-id>" to desired state.
10:05:57.471  Added volume "cpuinfo" (volSpec="cpuinfo") for pod "<pod1-id>" to desired state.
10:05:57.471  Added volume "stat" (volSpec="stat") for pod "<pod1-id>" to desired state.
10:05:57.480  Added volume "share-dir" (volSpec="pvc-6ee43741-29b1-4aa0-98d3-5413764d36b1") for pod "<pod1-id>" to desired state.
10:05:57.484  Added volume "data-dir" (volSpec="juicefs-volume1-pv") for pod "<pod1-id>" to desired state.
...
```

可以看出里面会依次处理 pod 所需的各种资源：

1. 设备：例如 **`GPU`**；
2. IP 地址；
3. cgroup 资源隔离配置；
4. **`volumes`**。

本文主要关注 volume 资源。

### Step 2.2 处理 pod 依赖的 volumes

上面日志可以看到，业务 pod 里面声明了一些需要挂载的 volumes。**几种类型**：

1. hostpath 类型：直接把 node 路径挂载到容器内；
2. lxcfs 类型：为了解决资源视图问题 [2]；
3. 动态/静态 PV 类型

本文的 JuiceFS volume 就属于 PV 类型，继续看 kubelet 日志：

```
# kubelet.INFO
10:05:57.509  operationExecutor.VerifyControllerAttachedVolume started for volume "xxx"
10:05:57.611  Starting operationExecutor.MountVolume for volume "xxx" (UniqueName: "kubernetes.io/host-path/<pod1-id>-xxx") pod "pod1" (UID: "<pod1-id>") 
10:05:57.611  operationExecutor.MountVolume started for volume "juicefs-volume1-pv" (UniqueName: "kubernetes.io/csi/csi.juicefs.com^juicefs-volume1-pv") pod "pod1" (UID: "<pod1-id>") 
10:05:57.611  kubernetes.io/csi: mounter.GetPath generated [/var/lib/k8s/kubelet/pods/<pod1-id>/volumes/kubernetes.io~csi/juicefs-volume1-pv/mount]
10:05:57.611  kubernetes.io/csi: created path successfully [/var/lib/k8s/kubelet/pods/<pod1-id>/volumes/kubernetes.io~csi/juicefs-volume1-pv]
10:05:57.611  kubernetes.io/csi: saving volume data file [/var/lib/k8s/kubelet/pods/<pod1-id>/volumes/kubernetes.io~csi/juicefs-volume1-pv/vol_data.json]
10:05:57.611  kubernetes.io/csi: volume data file saved successfully [/var/lib/k8s/kubelet/pods/<pod1-id>/volumes/kubernetes.io~csi/juicefs-volume1-pv/vol_data.json]
10:05:57.613  MountVolume.MountDevice succeeded for volume "juicefs-volume1-pv" (UniqueName: "kubernetes.io/csi/csi.juicefs.com^juicefs-volume1-pv") pod "pod1" (UID: "<pod1-id>") device mount path "/var/lib/k8s/kubelet/plugins/kubernetes.io/csi/pv/juicefs-volume1-pv/globalmount"
10:05:57.616  kubernetes.io/csi: mounter.GetPath generated [/var/lib/k8s/kubelet/pods/<pod1-id>/volumes/kubernetes.io~csi/juicefs-volume1-pv/mount]
10:05:57.616  kubernetes.io/csi: Mounter.SetUpAt(/var/lib/k8s/kubelet/pods/<pod1-id>/volumes/kubernetes.io~csi/juicefs-volume1-pv/mount)
10:05:57.616  kubernetes.io/csi: created target path successfully [/var/lib/k8s/kubelet/pods/<pod1-id>/volumes/kubernetes.io~csi/juicefs-volume1-pv/mount]
10:05:57.618  kubernetes.io/csi: calling NodePublishVolume rpc [volid=juicefs-volume1-pv,target_path=/var/lib/k8s/kubelet/pods/<pod1-id>/volumes/kubernetes.io~csi/juicefs-volume1-pv/mount]
10:05:57.713  Starting operationExecutor.MountVolume for volume "juicefs-volume1-pv" (UniqueName: "kubernetes.io/csi/csi.juicefs.com^juicefs-volume1-pv") pod "pod1" (UID: "<pod1-id>") 
...
10:05:59.506  kubernetes.io/csi: mounter.SetUp successfully requested NodePublish [/var/lib/k8s/kubelet/pods/<pod1-id>/volumes/kubernetes.io~csi/juicefs-volume1-pv/mount]
10:05:59.506  MountVolume.SetUp succeeded for volume "juicefs-volume1-pv" (UniqueName: "kubernetes.io/csi/csi.juicefs.com^juicefs-volume1-pv") pod "pod1" (UID: "<pod1-id>") 
10:05:59.506  kubernetes.io/csi: mounter.GetPath generated [/var/lib/k8s/kubelet/pods/<pod1-id>/volumes/kubernetes.io~csi/juicefs-volume1-pv/mount]
```

对于每个 volume，依次执行，

1. operationExecutor.**`VerifyControllerAttachedVolume()`** 方法，做一些检查；
2. operationExecutor.**`MountVolume()`** 方法，将指定的 volume 挂载到容器目录；
3. 对于 CSI 存储，还会调用到 CSI plugin 的 **`NodePublishVolume()`** 方法，初始化对应的 PV，JuiceFS 就是这种模式。

接下来 kubelet 会不断**检测所有 volumes 是否都挂载好**，没好的话不会进入下一步（创建 sandbox 容器）。

## Step 3：`kubelet --> CSI plugin`（juicefs）：setup PV

下面进一步看一下 node CSI plugin 初始化 PV 挂载的逻辑。**调用栈**：

```
         gRPC NodePublishVolume()
kubelet ---------------------------> juicefs node plugin (also called "driver", etc)
```

## Step 4：JuiceFS CSI plugin 具体工作

看一下 JuiceFS CSI node plugin 的日志，这里直接在机器上看：

```
(node) $ docker logs --timestamps k8s_juicefs-plugin_juicefs-csi-node-xxx | grep juicefs-volume1
10:05:57.619 NodePublishVolume: volume_id is juicefs-volume1-pv

10:05:57.619 NodePublishVolume: creating dir /var/lib/k8s/kubelet/pods/<pod1-id>/volumes/kubernetes.io~csi/juicefs-volume1-pv/mount

10:05:57.620 ceFormat cmd: [/usr/local/bin/juicefs format --storage=OSS --bucket=xx --access-key=xx --secret-key=${secretkey} --token=${token} ${metaurl} juicefs-volume1]
10:05:57.874 Format output is juicefs <INFO>: Meta address: tikv://node1:2379,node2:2379,node3:2379/juicefs-volume1
10:05:57.874 cefs[1983] <INFO>: Data use oss://<bucket>/juicefs-volume1/

10:05:57.875 Mount: mounting "tikv://node1:2379,node2:2379,node3:2379/juicefs-volume1" at "/jfs/juicefs-volume1-pv" with options [token=xx]

10:05:57.884 createOrAddRef: Need to create pod juicefs-node1-juicefs-volume1-pv.
10:05:57.891 createOrAddRed: GetMountPodPVC juicefs-volume1-pv, err: %!s(<nil>)
10:05:57.891 ceMount: mount tikv://node1:2379,node2:2379,node3:2379/juicefs-volume1 at /jfs/juicefs-volume1-pv
10:05:57.978 createOrUpdateSecret: juicefs-node1-juicefs-volume1-pv-secret, juicefs-system
10:05:59.500 waitUtilPodReady: Pod juicefs-node1-juicefs-volume1-pv is successful

10:05:59.500 NodePublishVolume: binding /jfs/juicefs-volume1-pv at /var/lib/k8s/kubelet/pods/<pod1-id>/volumes/kubernetes.io~csi/juicefs-volume1-pv/mount with options []
10:05:59.505 NodePublishVolume: mounted juicefs-volume1-pv at /var/lib/k8s/kubelet/pods/<pod1-id>/volumes/kubernetes.io~csi/juicefs-volume1-pv/mount with options []
```

可以看到确实执行了 [**`NodePublishVolume()`**](https://github.com/juicedata/juicefs-csi-driver/blob/v0.23.6/pkg/driver/node.go) 方法， 这个方法是**每个 CSI plugin 方案各自实现的**，所以里面做什么事情就跟存储方案有很大关系。 接下来具体看看 JuiceFS plugin 做的什么。

### Step 4.1 给 pod PV 创建挂载路径，初始化 volume

默认配置下，每个 pod 会在 node 上对应一个存储路径，

```
(node) $ ll /var/lib/k8s/kubelet/pods/<pod-id>
containers/
etc-hosts
plugins/
volumes/
```

juicefs plugin 会在以上 **`volumes/`** 目录内给 PV 创建一个对应的子目录和挂载点，

`/var/lib/k8s/kubelet/pods/{pod1-id}/volumes/kubernetes.io~csi/juicefs-volume1-pv/mount`。

然后用 `juicefs` 命令行工具**格式化**，

```
$ /usr/local/bin/juicefs format --storage=OSS --bucket=xx --access-key=xx --secret-key=${secretkey} --token=${token} ${metaurl} juicefs-volume1
```

例如，如果 JuiceFS 对接的是**阿里云 OSS**，上面就对应阿里云的 bucket 地址及访问秘钥。

### Step 4.2 volume 挂载信息写入 MetaServer

此外，还会把这个挂载信息同步到 JuiceFS 的 MetaServer，这里用的是 TiKV，暂不展开：

![img](https://arthurchiao.art/assets/img/k8s-juicefs-csi/juicefs-pod-setup-workflow.png)

Fig. JuiceFS as K8s CSI solution: workflow when a business pod is created (JuiceFS mountpod mode).

### Step 4.3 JuiceFS plugin：如果 client pod 不存在，就创建一个

JuiceFS CSI plugin 判断这个 PV 在 node 上是否已经存在 client pod，如果不存在，就创建一个；存在就不用再创建了。

> 当 node 上最后一个使用某 PV 的业务 pod 销毁后，对应的 client pod 也会被 juicefs CSI plugin 自动删掉。

我们这个环境用的是 dynamic client pod 方式，因此会看到如下日志：

```
(node) $ docker logs --timestamps <csi plugin container> | grep 
...
10:05:57.884 createOrAddRef: Need to create pod juicefs-node1-juicefs-volume1-pv.
10:05:57.891 createOrAddRed: GetMountPodPVC juicefs-volume1-pv, err: %!s(<nil>)
10:05:57.891 ceMount: mount tikv://node1:2379,node2:2379,node3:2379/juicefs-volume1 at /jfs/juicefs-volume1-pv
10:05:57.978 createOrUpdateSecret: juicefs-node1-juicefs-volume1-pv-secret, juicefs-system
10:05:59.500 waitUtilPodReady:
```

JuiceFS node plugin 会去 k8s 里面创建一个名为 **`juicefs-{node}-{volume}-pv`** 的 dynamic client pod。

![img](https://arthurchiao.art/assets/img/k8s-juicefs-csi/juicefs-pod-setup-workflow.png)

Fig. JuiceFS as K8s CSI solution: workflow when a business pod is created (JuiceFS mountpod mode).

## Step 5：kubelet 监听到 client pod 创建事件

这时候 kubelet 的**业务 pod** 还没创建好，“伺候”它的 **`juicefs client pod`** 又来“请求创建”了：

```
(node) $ grep juicefs-<node>-<volume>-pv /var/log/kubernetes/kubelet.INFO | grep "received "
10:05:58.288 SyncPod received new pod "juicefs-node1-volume1-pv_juicefs-system", will create a sandbox for it
```

所以接下来进入创建 juicefs dynamic client pod 的流程。

> 兵马未动，粮草先行。juicefs client pod 没有好，**业务 pod 即使起来了也不能读写 juicefs volume**。

## Step 6：kubelet 创建 client pod

创建 client pod 的流程跟业务 pod 是类似的，但这个 pod 比较简单，我们省略细节，认为它直接就拉起来了。

查看这个 client pod 内**运行的进程**：

```
(node) $ dk top k8s_jfs-mount_juicefs-node1-juicefs-volume1-pv-xx
/bin/mount.juicefs ${metaurl} /jfs/juicefs-volume1-pv -o enable-xattr,no-bgjob,allow_other,token=xxx,metrics=0.0.0.0:9567
```

**`/bin/mount.juicefs`** 其实只是个 alias，指向的就是 `juicefs` **可执行文件**，

```
(pod) $ ls -ahl /bin/mount.juicefs
/bin/mount.juicefs -> /usr/local/bin/juicefs
```

## Step 7：client pod 初始化、FUSE 挂载

查看这个 client pod 干了什么：

```
root@node:~  # dk top k8s_jfs-mount_juicefs-node1-juicefs-volume1-pv-xx
<INFO>: Meta address: tikv://node1:2379,node2:2379,node3:2379/juicefs-volume1
<INFO>: Data use oss://<oss-bucket>/juicefs-volume1/
<INFO>: Disk cache (/var/jfsCache/<id>/): capacity (10240 MB), free ratio (10%), max pending pages (15)
<INFO>: Create session 667 OK with version: admin-1.2.1+2022-12-22.34c7e973
<INFO>: listen on 0.0.0.0:9567
<INFO>: Mounting volume juicefs-volume1 at /jfs/juicefs-volume1-pv ...
<INFO>: OK, juicefs-volume1 is ready at /jfs/juicefs-volume1-pv
```

1. 初始化本地 volume 配置
2. 与 MetaServer 交互
3. 暴露 prometheus metrics
4. 以 juicefs 自己的 mount 实现（前面看到的 `/bin/mount.juicefs`），将 volume 挂载到 `/jfs/juicefs-volume1-pv`，默认对应的是 **`/var/lib/juicefs/volume/juicefs-volume1-pv`**。

此时在 node 上就可以看到如下的**挂载信息**：

```
(node) $ cat /proc/mounts | grep JuiceFS:juicefs-volume1
JuiceFS:juicefs-volume1 /var/lib/juicefs/volume/juicefs-volume1-pv fuse.juicefs rw,relatime,user_id=0,group_id=0,default_permissions,allow_other 0 0
JuiceFS:juicefs-volume1 /var/lib/k8s/kubelet/pods/<pod-id>/volumes/kubernetes.io~csi/juicefs-volume1-pv/mount fuse.juicefs rw,relatime,user_id=0,group_id=0,default_permissions,allow_other 0 0
```

可以看到是 **`fuse.juicefs`** 方式的挂载。 忘了 FUSE 基本工作原理的，再来借 lxcfs 快速回忆一下：

![img](https://arthurchiao.art/assets/img/linux-container-and-runtime/lxcfs-fuse.png)

Fig. lxcfs/fuse workflow: how a read operation is handled [2]

这个 dynamic client pod 创建好之后， **业务 pod（此时还不存在）的读写操作**都会进入 FUSE 模块， 然后转发给用户态的 juicefs client 处理。juicefs client 针对不同的 object store 实现了对应的读写方法。

## Step 8：kubelet 创建业务 pod：完成后续部分

至此，Pod 所依赖的 volumes 都处理好了，kubelet 就会打印一条日志：

```
# kubelet.INFO
10:06:06.119  All volumes are attached and mounted for pod "pod1(<pod1-id>)"
```

接下来就可以**继续创建业务 pod** 了：

```
# kubelet.INFO
10:06:06.119  No sandbox for pod "pod1(<pod1-id>)" can be found. Need to start a new one
10:06:06.119  Creating PodSandbox for pod "pod1(<pod1-id>)"
10:06:06.849  Created PodSandbox "885c3a" for pod "pod1(<pod1-id>)"
...
```

## 小结

更详细的 pod 创建过程，可以参考 [1]。

# 3 业务 pod 读写 juicefs volume 流程

juicefs dynamic client pod 先于业务 pod 创建，所以业务 pod 创建好之后，就可以直接读写 juicefs PV (volume) 了，

![img](https://arthurchiao.art/assets/img/k8s-juicefs-csi/juicefs-pod-read-write-workflow.png)

Fig. JuiceFS as K8s CSI solution: workflow when a business pod reads/writes (JuiceFS mountpod mode).

这个过程可以大致分为四步。

## Step 1：pod 读写文件（R/W operations）

例如在 pod 内进入 volume 路径（e.g. `cd /data/juicefs-pv-dir/`），执行 ls、find 等等之类的操作。

## Step 2：R/W 请求被 FUSE 模块 hook，转给 juicefs client 处理

直接贴两张官方的图略作说明 [3]，这两张图也透露了随后的 step 3 & 4 的一些信息：

读操作：

![img](https://arthurchiao.art/assets/img/k8s-juicefs-csi/juicefs-internals-read.png)

Fig. JuiceFS Internals: read operations.

写操作：

![img](https://arthurchiao.art/assets/img/k8s-juicefs-csi/juicefs-internals-write.png)

Fig. JuiceFS Internals: write operations.

## Step 3：juicefs client pod 从 meta server 读取（文件或目录的）元数据

上面的图中已经透露了一些 JuiceFS 的元数据设计，例如 chunk、slice、block 等等。 读写操作时，client 会与 MetaServer 有相关的元信息交互。

## Step 4：juicefs client pod 从 object store 读写文件

这一步就是去 S3 之类的 object store 去读写文件了。