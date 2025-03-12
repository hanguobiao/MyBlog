---
title: KubeBlocks源码笔记三--Component
date: 2025-03-05
update: 2025-03-05
comment: false
tags:
  - kubeblocks
categories:
  - kubeblocks
---

Component是Kubeblocks的核心资源，也是Workload定义的最主要声明，组件和Sharding都是依赖于Component实现

*<!--more-->*

# Kubeblocks源码笔记三--Component

Component的CR 在cluster的Transformer流程生成最终通过plan.execute实际创建出来

而在Component_controller中和cluster_controller类似，也存在一个DAG的过程，Component所关联资源都是通过该过程增删改的。DAG的实现大同小异，这里对Component_controller中的Transformer做解析

```
planBuilder := newComponentPlanBuilder(reqCtx, r.Client)
if err := planBuilder.Init(); err != nil {
    return intctrlutil.CheckedRequeueWithError(err, reqCtx.Log, "")
}

plan, errBuild := planBuilder.
		AddTransformer(
			// handle component pre-terminate
			&componentPreTerminateTransformer{},
			// handle component deletion
			&componentDeletionTransformer{},
			// handle finalizers and referenced definition labels
			&componentMetaTransformer{},
			// validate referenced componentDefinition objects, and build synthesized component
			&componentLoadResourcesTransformer{},
			// do validation for the spec & definition consistency
			&componentValidationTransformer{},
			// handle sidecar container
			&componentMonitorContainerTransformer{},
			// allocate ports for host-network component
			&componentHostNetworkTransformer{},
			// handle component services
			&componentServiceTransformer{},
			// handle component system accounts
			&componentAccountTransformer{},
			// handle the TLS configuration
			&componentTLSTransformer{},
			// rerender parameters after v-scale and h-scale
			&componentRelatedParametersTransformer{Client: r.Client},
			// resolve and build vars for template and Env
			&componentVarsTransformer{},
			// provision component system accounts, depend on vars
			&componentAccountProvisionTransformer{},
			// render component configurations
			&componentConfigurationTransformer{Client: r.Client},
			// handle restore before workloads transform
			&componentRestoreTransformer{Client: r.Client},
			// handle the component workload
			&componentWorkloadTransformer{Client: r.Client},
			// handle RBAC for component workloads
			&componentRBACTransformer{},
			// handle component postProvision lifecycle action
			&componentPostProvisionTransformer{},
			// update component status
			&componentStatusTransformer{Client: r.Client},
			// notify dependent components the possible spec changes
			&componentNotifierTransformer{},
		).Build()

	// Execute stage
	// errBuild not nil means build stage partial success or validation error
	// execute the plan first, delay error handling
	if errExec := plan.Execute(); errExec != nil {
		return requeueError(errExec)
	}
```

下面对每个Transformer进行介绍

# componentPreTerminateTransformer

处理 Lifecycle中的 PreTerminate。由于可能存在失败的情况，所以一次调谐可能无法完成一次Action。当确认该Component需要执行PreTerminate时，则在Anno中标记。每次执行PreTerminateTransformer时会检查是否存在该标记，存在则向kbagnet发送请求，实际执行PreTerminate

与LifecycleActionSet的设计有关：

```
	if t.skipPreTerminate(transCtx) {
		return nil
	}
	if t.checkPreTerminateDone(transCtx, dag) {
		return nil
	}
	err := t.preTerminate(transCtx, compDef)
	if err != nil {
		return lifecycle.IgnoreNotDefined(err)
	}
	return t.markPreTerminateDone(transCtx, dag)
```



# componentDeletionTransformer

实际处理删除操作

```
	// step1: update the component status to deleting
	if comp.Status.Phase != appsv1.DeletingComponentPhase {
		comp.Status.Phase = appsv1.DeletingComponentPhase
		graphCli.Status(dag, comp, transCtx.Component)
		return intctrlutil.NewRequeueError(time.Second*1, "updating component status to deleting")
	}

	// step2: delete the sub-resources
	compName, err := component.ShortName(clusterName, comp.Name)
	if err != nil {
		return err
	}
	ml := constant.GetCompLabels(clusterName, compName)

	compScaleIn, ok := comp.Annotations[constant.ComponentScaleInAnnotationKey]
	if ok && compScaleIn == "true" {
		return t.handleCompDeleteWhenScaleIn(transCtx, graphCli, dag, comp, ml)
	}
	return t.handleCompDeleteWhenClusterDelete(transCtx, graphCli, dag, comp, ml)
```



# componentMetaTransformer

为Component添加Finalizer



# componentLoadResourcesTransformer

获取到所有的ComponentDefinition，并生成一个包含当前Component所有信息的SynthesizeComponent放到transCtx中。

```
synthesizedComp, err := component.BuildSynthesizedComponent(ctx, transCtx.Client, compDef, comp, transCtx.Cluster)
```

SynthesizeComponent包含了当前Component所有的静态和动态信息，包括ComponentDefinition和cluster中的相应部分。之后就是对SynthesizeComponent做一系列处理

```go
buildCompatibleHorizontalScalePolicy(compDefObj, synthesizeComp)

if err = mergeUserDefinedEnv(synthesizeComp, comp); err != nil {
    return nil, err
}

// build scheduling policy for workload
buildSchedulingPolicy(synthesizeComp, comp)

// update resources
buildAndUpdateResources(synthesizeComp, comp)

// build volumes & volumeClaimTemplates
buildVolumeClaimTemplates(synthesizeComp, comp)
// 检查Component定义的Voluem是否和PodSpec中冲突
if err = mergeUserDefinedVolumes(synthesizeComp, comp); err != nil {
    return nil, err
}

limitSharedMemoryVolumeSize(synthesizeComp, comp)

// build componentService
buildComponentServices(synthesizeComp, comp)

if err = overrideConfigTemplates(synthesizeComp, comp); err != nil {
    return nil, err
}

// build serviceAccountName
buildServiceAccountName(synthesizeComp)

// build runtimeClassName
buildRuntimeClassName(synthesizeComp, comp)

if err = buildKBAgentContainer(synthesizeComp); err != nil {
    return nil, errors.Wrap(err, "build kb-agent container failed")
}

if err = buildServiceReferences(ctx, cli, synthesizeComp, compDef, comp); err != nil {
    return nil, errors.Wrap(err, "build service references failed")
}
```

其中值得关注的流程如下所示

### buildFileTemplates

将Configs2字段与comp中的Configs做Merge（Configs2没有被用到）

### overrideNCheckConfigTemplates

检查comp.spec.Configs中是否都有对应的模版

### buildRuntimeClassName

生成cmpdName，默认为kb-{cmpdNAME}

### buildSidecars

SidecarDefinition将sidecarDef渲染到SynthesizeComponent

### buildKBAgentContainer

KBAgent是用于管理ComponentDefinition中LifecycleAction的组件，以sidecar的形式注入Pod

KBagent的介绍：

```
newContainer := func(name string, f func(*builder.ContainerBuilder) error) (*corev1.Container, error) {
		b := builder.NewContainerBuilder(name).
			SetImage(viper.GetString(constant.KBToolsImage)).
			SetImagePullPolicy(corev1.PullIfNotPresent).
			AddCommands(kbAgentCommand).
			AddEnv(mergedActionEnv4KBAgent(synthesizedComp)...).
			AddEnv(envVars...).
			SetSecurityContext(corev1.SecurityContext{
				RunAsGroup: &[]int64{1000}[0],
			})
		if f != nil {
			if err1 := f(b); err1 != nil {
				return nil, err1
			}
		}
		return b.GetObject(), nil
	}


container, err := newContainer(kbagent.ContainerName, func(b *builder.ContainerBuilder) error {
    ports, err1 := getAvailablePorts(synthesizedComp.PodSpec.Containers,
       []int32{int32(kbagent.DefaultHTTPPort), int32(kbagent.DefaultStreamingPort)})
    if err1 != nil {
       return err1
    }
    httpPort, streamingPort := int(ports[0]), int(ports[1])
    b.AddArgs("--port", strconv.Itoa(httpPort)).
       AddArgs("--streaming-port", strconv.Itoa(streamingPort)).
       AddPorts(
          corev1.ContainerPort{
             ContainerPort: int32(httpPort),
             Name:          kbagent.DefaultHTTPPortName,
             Protocol:      corev1.ProtocolTCP,
          },
          corev1.ContainerPort{
             ContainerPort: int32(streamingPort),
             Name:          kbagent.DefaultStreamingPortName,
             Protocol:      corev1.ProtocolTCP,
          }).
       SetStartupProbe(corev1.Probe{
          ProbeHandler: corev1.ProbeHandler{
             TCPSocket: &corev1.TCPSocketAction{Port: intstr.FromInt(httpPort)},
          }})
    return nil
})
```

KBAgent并不是只能使用固定的镜像，

#### handleCustomImageNContainerDefined

这里支持自定义kb-agent的镜像，用户可以在LifecycleAction中指定执行命令的镜像来替换掉默认的Kubeblocks-tools镜像

这里会检查所有的镜像是否一致

#### workerContainer

有一个名为kbagent-worker的initContainer，如果用户采用了自定义的KBAgent镜像，workerContainer会将所有的工具拷贝到使用自定义的KBAgent当中

## buildServiceReferences

Kubeblocks通过ServiceReferences来抽象跨Cluster的服务引用，还可以通过ServiceDescriptor来定义一个外部的服务引用（也就是定义一个服务地址）

Cluster：旧版本遗留

ClusterServiceSelector：通过指定Cluster的name来获取对应Cluster中的对应信息

ServiceDescriptor：定义一个ServiceDescriptor CR，抽象一个外部的引用

```
type ServiceRef struct {
    Name string `json:"name"`
    Namespace string `json:"namespace,omitempty"`

    // Deprecated since v0.9 since `clusterDefinition.spec.connectionCredential` is deprecated,
    Cluster string `json:"cluster,omitempty"`

    // References a service provided by another KubeBlocks Cluster.
    // It specifies the ClusterService and the account credentials needed for access.
    ClusterServiceSelector *ServiceRefClusterSelector `json:"clusterServiceSelector,omitempty"`

    // Specifies the name of the ServiceDescriptor object that describes a service provided by external sources.
    //
    // When referencing a service provided by external sources, a ServiceDescriptor object is required to establish
    // the service binding.
    // The `serviceDescriptor.spec.serviceKind` and `serviceDescriptor.spec.serviceVersion` should match the serviceKind
    // and serviceVersion declared in the definition.
    //
    // If both `cluster` and `serviceDescriptor` are specified, the `cluster` takes precedence.
    ServiceDescriptor string `json:"serviceDescriptor,omitempty"`
}
```

用户可以在CMPD中指定需要应用指定服务的哪些值。

```
type serviceRefReferenceVars struct {
    endpoint *appsv1.CredentialVar
    host     *appsv1.CredentialVar
    port     *appsv1.CredentialVar
    username *appsv1.CredentialVar
    password *appsv1.CredentialVar
    podFQDNs *appsv1.CredentialVar
}
```

首先会初始化ServiceDescriptorBuilder，利用resolver获取到需要的值

```
resolver := referencedVars
vars := &serviceRefReferenceVars{}
if err := resolver(ctx, cli, namespace, serviceRef, vars); err != nil {
  return nil, err
}

switch {
case serviceRef.Cluster != "":
    sd, err = handleServiceRefFromCluster(ctx, cli, namespace, *serviceRef, serviceRefDecl, true)
case serviceRef.ClusterServiceSelector != nil:
    sd, err = handleServiceRefFromCluster(ctx, cli, namespace, *serviceRef, serviceRefDecl, false)
case serviceRef.ServiceDescriptor != "":
    sd, err = handleServiceRefFromServiceDescriptor(ctx, cli, namespace, *serviceRef, serviceRefDecl)
}
```



```
func referencedVars(ctx context.Context, cli client.Reader, namespace string, serviceRef appsv1.ServiceRef, vars *serviceRefReferenceVars) error {
    if err := referencedServiceVars(ctx, cli, namespace, serviceRef, vars); err != nil {
       return err
    }
    if err := referencedPodFQDNsVar(ctx, cli, namespace, serviceRef, vars); err != nil {
       return err
    }
    if err := referencedCredentialVars(ctx, cli, namespace, serviceRef, vars); err != nil {
       return err
    }
    return nil
}
```

#### referencedServiceVars

通过拼接名称直接从Service获取信息，其中compServiceGetter会考虑各种情况，获取所有可能的Service

```
switch {
case len(selector.Service.Component) == 0:
    obj, err = clusterServiceGetter(ctx, cli, svcNamespace, selector.Cluster, selector.Service.Service)
case selector.Service.Service == "headless":
    obj, err = headlessCompServiceGetter(ctx, cli, svcNamespace, selector.Cluster, selector.Service.Component)
default:
    obj, err = compServiceGetter(ctx, cli, svcNamespace, selector.Cluster, selector.Service.Component, selector.Service.Service)
}
```

### referencedPodFQDNsVar

同理，FQDN一定会生成，通过拼接名字直接获取

### referencedCredentialVars

Credential涉及到用户名和密码，存储在对应Cluster的Secret当中

这里会直接获取到Secret相应字段，之后会注入到环境变量当中

```
secret := &corev1.Secret{}
if err := cli.Get(ctx, secretKey, secret); err != nil {
    return err
}

copySecretDataToCredentialVar(namespace, secret, constant.AccountNameForSecret, &vars.username)
```

```
func copySecretDataToCredentialVar(namespace string, secret *corev1.Secret, key string, v **appsv1.CredentialVar) {
    if _, ok := secret.Data[key]; !ok {
       return
    }
    if secret.Namespace == namespace || namespace == "" {
       *v = &appsv1.CredentialVar{
          ValueFrom: &corev1.EnvVarSource{
             SecretKeyRef: &corev1.SecretKeySelector{
                LocalObjectReference: corev1.LocalObjectReference{Name: secret.Name},
                Key:                  key,
             },
          },
       }
    } else {
       *v = &appsv1.CredentialVar{Value: string(secret.Data[key])}
    }
}
```

# componentValidationTransformer

do validation for the spec & definition consistency。

```
if err = validateCompReplicas(comp, transCtx.CompDef); err != nil {
    return intctrlutil.NewRequeueError(appsutil.RequeueDuration, err.Error())
}
```

# componentMonitorContainerTransformer

通过Component中的DisableExporter来添加或者移除监控的Monitor

```
if synthesizeComp.DisableExporter != nil && *synthesizeComp.DisableExporter {
    removeMonitorContainer(component.GetExporter(compDef.Spec), synthesizeComp)
}
```

这里的逻辑比较hack，之后计划通过sidecarDefinition替代

# componentHostNetworkTransformer

为使用了HostNetwork的Component分配端口

```
synthesizedComp := transCtx.SynthesizeComponent
ports, err := allocateHostPorts(synthesizedComp)
if err != nil {
  return err
}
return updateObjectsWithAllocatedPorts(synthesizedComp, ports)
```

对于所有port包括KBAgent、ConfigMap的port调用PortManager.AllocatePort分配当前主机不重复的端点

```
for _, c := range synthesizedComp.PodSpec.Containers {
    for _, p := range c.Ports {
       portKey := intctrlutil.BuildHostPortName(synthesizedComp.ClusterName, synthesizedComp.Name, c.Name, p.Name)
       if needAllocate(c.Name, p.Name) {
          port, err := pm.AllocatePort(portKey)
          if err != nil {
             return nil, err
          }
          insert(c.Name, p.Name, port)
       } else {
          if err := pm.UsePort(portKey, p.ContainerPort); err != nil {
             return nil, err
          }
       }
    }
}
```



PortManager在main -> InitHostPortManager() -> NewPortManager()中完成初始化

通过指定includes和exclude来确定可以使用的Port范围

```
includes, err := parsePortRanges(viper.GetString(constant.CfgHostPortIncludeRanges))
if err != nil {
    return err
}
excludes, err := parsePortRanges(viper.GetString(constant.CfgHostPortExcludeRanges))
if err != nil {
    return err
}
```

通过类似下面的CM来记录已经分配的HOST Port

```
Name:         kubeblocks-host-ports
Namespace:    default
Labels:       <none>
Annotations:  <none>

Data
====
cluster1-config-manager-config-manager:
----
1105
cluster2-mysql-mysql-comm-control:
----
1088
clsuter3-mysql-mysql-cm-server:
----
1077

```

PortManager包含以下方法

- sync：用于将CM中的Port情况同步到PortManager当中（应对重启之类的情况）
- update：将PortManager中的数据同步到CM
- delete：删掉PortManager中的port，并将更新同步到CM
- GetPort：获取PortManager中的该key对应的value
- UsePort：在PortManger中插入该值的使用，并调用update
- AllocatePort：判断key是否已经分配了port，检查port是否用尽，根据当前的cursor分配port，并调用update
- ReleasePort：调用delete



# componentServiceTransformer

处理ComponentService，通过SynthesizeComponent中的Service和runningServices的比较决定对Service的处理

```
graphCli, _ := transCtx.Client.(model.GraphClient)
for _, service := range synthesizeComp.ComponentServices {
    // component controller does not handle the default headless service; the default headless service is managed by the InstanceSet.
    if t.skipDefaultHeadlessSvc(synthesizeComp, &service) {
       continue
    }
    services, err := t.buildCompService(transCtx.Component, synthesizeComp, &service)
    if err != nil {
       return err
    }
    for _, svc := range services {
       if err = t.createOrUpdateService(ctx, dag, graphCli, &service, svc, transCtx.ComponentOrig); err != nil {
          return err
       }
       delete(runningServices, svc.Name)
    }
}

for svc := range runningServices {
    graphCli.Delete(dag, runningServices[svc], appsutil.InDataContext4G())
}
```

可以看到skipDefaultHeadlessSvc，这里并不会对HeadlessSvc进行创建这一流程在底层的Workload中处理，也就是InstanceSet

这里的引入了一个PodService的机制，会对每一个Pod生成一个Service，并通过apps.kubeblocks.io/pod-name的label来匹配路由到每一个Pod

```
services := make([]*appsv1.ComponentService, 0)
for name, ordinal := range pods {
    svc := service.DeepCopy()
    svc.Name = fmt.Sprintf("%s-%d", service.Name, ordinal)
    if len(service.ServiceName) == 0 {
       svc.ServiceName = fmt.Sprintf("%d", ordinal)
    } else {
       svc.ServiceName = fmt.Sprintf("%s-%d", service.ServiceName, ordinal)
    }
    if svc.Spec.Selector == nil {
       svc.Spec.Selector = make(map[string]string)
    }
    svc.Spec.Selector[constant.KBAppPodNameLabelKey] = name
    services = append(services, svc)
}
return t.buildServices(comp, synthesizeComp, services)
```

最后调用createOrUpdateService来创建或者更新Service

# componentAccountTransformer

处理Component的System Account，这一字段是数据库账户密码的抽象

处理逻辑：

1. 获取所有账号相关的secret
2. 根据synthesizedComp中的SystemAccounts字段确定实际需要的账户
3. 根据二者的DIff增删改Secret
   - 创建Secret会根据PasswordGenerationPolicy生成随机的密码来保证安全
   - 删除则会直接在DAG中删除
   - 更新的逻辑：会重新生成密码，并Merge Labels和Anno

```
// exist account objects
secrets, err := listSystemAccountObjects(ctx, synthesizedComp)
if err != nil {
    return err
}
runningNameSet := sets.New(maps.Keys(secrets)...)

// proto accounts
accounts, err := synthesizeSystemAccounts(transCtx.CompDef.Spec.SystemAccounts,
    transCtx.Component.Spec.SystemAccounts, false)
if err != nil {
    return err
}
protoNameSet := sets.New(maps.Keys(accounts)...)

createSet, deleteSet, updateSet := setDiff(runningNameSet, protoNameSet)
```

# componentTLSTransformer

 handle tls volume and cert

会根据配置生成一个secret为VolumeSource的Volume，并添加到对应的VolumeMount当中

```
secretObj, err := t.secretObject(transCtx, synthesizedComp)
if err != nil {
    return err
}

issuer := t.newTLSIssuer(compDef, synthesizedComp)
if enabled {
    if secretObj == nil {
       if err = t.handleCreate(transCtx.Context, transCtx.Client, dag, issuer); err != nil {
          return err
       }
    } else {
       if err = t.handleUpdate(transCtx.Context, transCtx.Client, dag, issuer, secretObj); err != nil {
          return err
       }
    }
    return t.updateVolumeNVolumeMount(compDef, synthesizedComp)
} else {
    // the issuer and secretObj may be nil
    return t.handleDelete(transCtx.Context, transCtx.Client, dag, issuer, secretObj)
}
```

# componentRelatedParametersTransformer

当v-scale 或者h-scale时，重新patch指定的CM

```
c.Patch(ctx.GetContext(), configNew, client.MergeFrom(config.DeepCopy()))
```

通过patch整个CM来触发配置渲染的流程，来达到在某些关心的配置变更时，重新渲染整个配置

# componentVarsTransformer



Kubeblocks中有大量的数据是通过环境变量的方式进行交互，这里的Transformer就是处理环境变量相关的逻辑

```go
vars := builtinTemplateVars(synthesizedComp, definedVars)
vars, credentialVars, err := resolveBuiltinNObjectRefVars(ctx, cli, synthesizedComp, definedVars)
if err != nil {
    return nil, nil, err
}
envVars, templateVars := resolveVarsReferenceNEscaping(vars, credentialVars)
return templateVars, append(envVars, credentialVars...), nil
```

builtinTemplateVars是一些内置的Vars

```
{constant.KBEnvNamespace, synthesizedComp.Namespace},
{constant.KBEnvClusterName, synthesizedComp.ClusterName},
{constant.KBEnvClusterUID, synthesizedComp.ClusterUID},
{constant.KBEnvClusterCompName, constant.GenerateClusterComponentName(synthesizedComp.ClusterName, synthesizedComp.Name)},
{constant.KBEnvCompName, synthesizedComp.Name},
{constant.KBEnvCompReplicas, strconv.Itoa(int(synthesizedComp.Replicas))},
```

resolveClusterObjectRefVars主要是处理valuefrom，从对应的来源中取出对应的值。

```
switch {
case source.ConfigMapKeyRef != nil:
    return resolveConfigMapKeyRef(ctx, cli, synthesizedComp, defineKey, *source.ConfigMapKeyRef)
case source.SecretKeyRef != nil:
    return resolveSecretKeyRef(ctx, cli, synthesizedComp, defineKey, *source.SecretKeyRef)
case source.HostNetworkVarRef != nil:
    return resolveHostNetworkVarRef(ctx, cli, synthesizedComp, defineKey, *source.HostNetworkVarRef, ext...)
case source.ServiceVarRef != nil:
    return resolveServiceVarRef(ctx, cli, synthesizedComp, defineKey, *source.ServiceVarRef)
case source.CredentialVarRef != nil:
    return resolveCredentialVarRef(ctx, cli, synthesizedComp, defineKey, *source.CredentialVarRef)
case source.ServiceRefVarRef != nil:
    return resolveServiceRefVarRef(ctx, cli, synthesizedComp, defineKey, *source.ServiceRefVarRef)
case source.ComponentVarRef != nil:
    return resolveComponentVarRef(ctx, cli, synthesizedComp, defineKey, *source.ComponentVarRef)
case source.ClusterVarRef != nil:
    return resolveClusterVarRef(ctx, cli, synthesizedComp, defineKey, *source.ClusterVarRef)
}
```

evaluateObjectVarsExpression处理tpl表达式

```go
eval := func(v appsv1.EnvVar) error {
    if !evaluable(v) {
       return nil
    }
    tpl, err := varTemplate.Parse(*v.Expression)
    if err != nil {
       return err
    }
    var buf strings.Builder
    if err = tpl.Execute(&buf, values); err != nil {
       return err
    }
    update(v.Name, buf.String())
    return nil
}
```



# componentAccountProvisionTransformer

处理lifecycleAction中accountProvision，通过调用kb-agent来执行创建数据库用户的的lifecycle

1. 检查Component状态，获取LifecycleActions

2. 获取到SynthesizeComponent中所有SystemAccount
3. 通过比较Secret来确定哪些账号需要增删改，并执行相应的语句

```
accounts, _ := synthesizeSystemAccounts(compDef.Spec.SystemAccounts, comp.Spec.SystemAccounts, true)

secrets, err1 := listSystemAccountObjects(ctx, transCtx.SynthesizeComponent)
if err1 != nil {
    return err1
}
protoNameSet := sets.New(maps.Keys(secrets)...)

cond := t.provisionCond(transCtx)
provisionedNameSet := t.getProvisionedAccounts(cond)

createSet, deleteSet, updateSet := setDiff(provisionedNameSet, protoNameSet)
if len(createSet) == 0 && len(deleteSet) == 0 && len(updateSet) == 0 {
    return nil
}

lfa, err2 := t.lifecycleAction(transCtx)

t.provisionCondDone(transCtx, condCopy, &cond, err3)
```

# componentConfigurationTransformer

处理Component中configuration，将配置渲染为最终格式

```go
// configuration render
if err := plan.RenderConfigNScriptFiles(
    &configctrl.ResourceCtx{
       Context:       transCtx.Context,
       Client:        t.Client,
       Namespace:     comp.GetNamespace(),
       ClusterName:   synthesizeComp.ClusterName,
       ComponentName: synthesizeComp.Name,
    },
    cluster,
    comp,
    synthesizeComp,
    synthesizeComp.PodSpec,
    dependOnObjs); err != nil {
    return err
}
```

采用了流式编程的方式，对配置进行渲染，具体的配置处理逻辑放到单独的章节

```go
func (c *configOperator) Reconcile() error {
    var synthesizedComponent = c.SynthesizedComponent

    if len(synthesizedComponent.ConfigTemplates) == 0 && len(synthesizedComponent.ScriptTemplates) == 0 {
       return c.UpdateConfiguration()
    }

    return NewCreatePipeline(c.ReconcileCtx).
       Prepare().
       RenderScriptTemplate().      // render scriptTemplate into ConfigMap
       UpdateConfiguration().       // create or update Configuration
       Configuration().             // fetch the latest Configuration
       CreateConfigTemplate().      // render configTemplate into ConfigMap (only for the first time)
       UpdatePodVolumes().          // update podSpec.Volumes
       BuildConfigManagerSidecar(). // build configManager sidecar and update podSpec.Containers and podSpec.InitContainers
       UpdateConfigRelatedObject(). // handle InjectEnvTo, and create or update ConfigMaps
       UpdateConfigurationStatus(). // update ConfigurationItemStatus revision and phase etc.
       Complete()
}
```

配置相关：

# componentRestoreTransformer

handle restore before workloads transform

会通过kubeblocks.io/restore-from-backup判断是否处于恢复状态，之后会通过RestoreManager发起实际的恢复操作，即下发Restore的CR，由Restore的Controller处理数据恢复的命令

Restore并不在DAG的处理范畴所以这里会直接下发

```
restoreMGR := plan.NewRestoreManager(reqCtx.Ctx, t.Client, cluster, model.GetScheme(), nil, synthesizedComp.Replicas, 0)

postProvisionDone := checkPostProvisionDone(transCtx)
if err := restoreMGR.DoRestore(synthesizedComp, transCtx.Component, postProvisionDone); err != nil {
    return commitError(err)
}
```

RestoreManager的定义如下所示

```
// RestoreManager restores manager functions
// 1. support datafile/snapshot restore
// 2. support point in time recovery (PITR)
type RestoreManager struct {
    client.Client
    Ctx     context.Context
    Cluster *appsv1.Cluster
    Scheme  *k8sruntime.Scheme

    // private
    namespace                         string
    restoreTime                       string
    env                               []corev1.EnvVar
    parameters                        []dpv1alpha1.ParameterPair
    volumeRestorePolicy               dpv1alpha1.VolumeClaimRestorePolicy
    doReadyRestoreAfterClusterRunning bool
    startingIndex                     int32
    replicas                          int32
    restoreLabels                     map[string]string
}
```

DoRestore负责具体下发Restore CR

1. 恢复中的Cluster的Anno中会携带Backup的信息，通过这些信息可以获取到Backup
2. 调用BuildPrepareDataRestore来下发PrepareData类型的Restore（不同的Instance模版可能不同）
   1. 遍历comp.Instances，计算出模版对应的副本数
      1. 遍历每个comp.Instances，筛选出需要备份的PVC
      2. 通过上述信息构建出实际的Restore对象，并添加到restore
   2. 如果templateReplicas<comp.Replicas，则认为这部分是默认模版生成的，继续生成restore
   3. createRestoreAndWait:创建Restore，检查Restore的状态，不为completed就抛出错误，直到状态变为completed
3. 调用DoPostReady来下发PrepareData类型的Restore
   1. 这里PostReady是执行命令不需要针对PVC，所以可以根据配置的角色直接生成
   2. createRestoreAndWait
4. 执行到这里说明所有Restore已经completed，清理restore-from-backup的Anno

```
func (r *RestoreManager) DoRestore(comp *component.SynthesizedComponent, compObj *appsv1.Component, postProvisionDone bool) error {
    backupObj, err := r.initFromAnnotation(comp, compObj)
    if err != nil {
       return err
    }
    if backupObj == nil {
       return nil
    }
    if backupObj.Status.BackupMethod == nil {
       return intctrlutil.NewErrorf(intctrlutil.ErrorTypeRestoreFailed, `status.backupMethod of backup "%s" can not be empty`, backupObj.Name)
    }
    if err = r.DoPrepareData(comp, compObj, backupObj); err != nil {
       return err
    }
    if compObj.Status.Phase != appsv1.RunningComponentPhase {
       return nil
    }
    // wait for the post-provision action to complete.
    if !postProvisionDone {
       return nil
    }
    if r.doReadyRestoreAfterClusterRunning && r.Cluster.Status.Phase != appsv1.RunningClusterPhase {
       return nil
    }
    if err = r.DoPostReady(comp, compObj, backupObj); err != nil {
       return err
    }
    // mark component restore done
    if compObj.Annotations != nil {
       compObj.Annotations[constant.RestoreDoneAnnotationKey] = "true"
    }
    // do clean up
    return r.cleanupRestoreAnnotations(comp.Name)
}
```

# componentWorkloadTransformer

用于增删改Workload，Workload即实际生成Component所描述的Pods并对其进行管理。目前仅支持InstanceSet，可以理解为Statefulset的扩展。InstanceSet创建成功后就进入了InstanceSet的调谐流程。

```
runningITS, err := t.runningInstanceSetObject(ctx, synthesizeComp)
// inject volume mounts and build its proto
buildPodSpecVolumeMounts(synthesizeComp)
protoITS, err := factory.BuildInstanceSet(synthesizeComp, compDef)
if err != nil {
  return err
}
transCtx.ProtoWorkload = protoITS

if err = t.reconcileWorkload(transCtx.Context, t.Client, synthesizeComp, comp, runningITS, protoITS); err != nil {
  return err
}
graphCli, _ := transCtx.Client.(model.GraphClient)
if runningITS == nil {
  if protoITS != nil {
    if err := setCompOwnershipNFinalizer(comp, protoITS); err != nil {
      return err
    }
    graphCli.Create(dag, protoITS)
    return nil
  }
} else {
  if protoITS == nil {
    graphCli.Delete(dag, runningITS)
  } else {
    err = t.handleUpdate(reqCtx, graphCli, dag, synthesizeComp, comp, runningITS, protoITS)
  }
}
```

## buildPodSpecVolumeMounts



# componentRBACTransformer

handle RBAC for component workloads

# componentPostProvisionTransformer

handle component postProvision lifecycle action

# componentStatusTransformer

update component status





# 一些设计思路

# Motivation

- ComponentDefinition独立后可以方便复用。开发Cluster Definition可以用各种预先定义的Component Definition来搭积木。举两个例子：
  - ApeCloud MySQL proxy、vitess、pg patroni、risingwave都使用了etcd组件，可以直接复用某处预定义的etcd Component Definition
  - 各MySQL发行版（ApeCloud MySQL、Oracle MySQL、Percona MySQL、MariaDB、……）都可能会有使用proxy的需求，可以复用同一个proxy（比如ApeCloud MySQL proxy）的component definition，给多个MySQL发行版增加proxy功能
- 当前嵌入在ClusterDefinition CRD里的Component API 还需要改进。我认为可以对照以下的标准，反复“推敲”，来趋近一个规范的、抽象良好的API：
  - 层次分明。API中的每一个配置项都有其缩近，有相同缩进的概念要在一个层次上。不要把不同层次的概念并列收在同一层里。
  - 内聚。对配置做归类，相近的概念聚合后放到同一个父类目下。
  - 避免隐式配置。隐式配置是指在API中并未明确提出的，而是在代码中硬编码实现的设置或参数。隐式配置的问题在于一是难懂，需要翻代码才知道其来源，二是难扩展，需要改代码而非API配置才能实现扩展功能。我们需要将隐式配置项显式化的定义、暴露出来。
  - 用词描述精准。不要用大的词，有可能产生歧义的词，或者不为大众所理解的词。相反的，用约定俗成的、无歧义的、精确的词。不确定的多google，或者找人（比如我）讨论。多“推敲”。
  - 关键词连起来读像正常的英语句子。
  - 正交。不要在一个配置项耦合性的设置了多个维度的配置，将其拆为多个正交的配置。

# Concepts

- ***Component*** Component 是搭建出一个数据存储与处理系统的基础组装组件，一个Component通过StatefulSet(k8s原生、或者客户指定的StatefulSet例如OpenKruise)管理一到多个Pods，这些Pod都是同构的（共享同一个podSpec）。但Pod可以有不同的HA角色（例如在ActivePassive架构下，可以分为Primary和Secondary，而在ActiveActive架构下，Pod不区分角色）。映射到系统架构语言上，Component代表了在一个分布式系统中，某个组件的一组副本。Component支持的功能包括：高可用（failover&switchover）、副本复制关系管理、PVC生命周期管理、垂直和水平扩容、监控、日志。Component的Pod需要类似container lifecycle hooks的自定义功能，例如当一个Pod上线下线，需要注册其地址。
- ***Cluster*** Cluster包含一到多个Component，来代表一个分布式系统包含的多个组件。Cluster会暴露外部可使用的地址，备份系统也可以通过传入Cluster ID给一个Cluster进行备份。Cluster表示一个功能单一的分布式系统，例如一套数据库系统、一个存储系统、一个队列、一个数仓等。Component也有类似lifecycle的
- ***BluePrint（TODO）*** BluePrint是由多个Cluster组成，表示在业务层如何将多个单一功能的系统（Cluster）组合起来满足一个复杂的业务场景。例如，将多种数据库的日志写入一个队列系统，下游再由一些数仓进行消费，同时数据写入对象存储。