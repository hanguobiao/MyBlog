---
title: KubeBlocks源码笔记六--配置
date: 2025-03-05
update: 2025-03-05
comment: false
tags:
  - kubeblocks
categories:
  - kubeblocks
---

Kubeblocks提供了配置管理功能，包括配置的动态渲染和动态变更核心是通过goTemplate来动态生成配置，通过额外的Configmap来控制和管理配置的变更，同时也可以通过Component维度拆分来支持多sharding的配置需求。

*<!--more-->*

# Overview



# 调用栈

```
componentConfigurationTransformer.Transform -> RenderConfigNScriptFiles -> NewConfigReconcileTask().Reconcile()
|- NewCreatePipeline(c.ReconcileCtx).
|  —> RenderScriptTemplate().      // render scriptTemplate into ConfigMap
|  —> UpdateConfiguration().       // create or update Configuration
|  —> Configuration().             // fetch the latest Configuration
|  —> CreateConfigTemplate().      // render configTemplate into ConfigMap (only for the first time)
|  —> UpdatePodVolumes().          // update podSpec.Volumes
|  —> BuildConfigManagerSidecar(). // build configManager sidecar and update podSpec.Containers and podSpec.InitContainers
|  —> UpdateConfigRelatedObject(). // handle InjectEnvTo, and create or update ConfigMaps
|  —> UpdateConfigurationStatus(). // update ConfigurationItemStatus revision and phase etc.
|  —> Complete()


```

 

## 1. 准备工作

首先会从dag中获取到所有的ConfigMap和Secret，放入dependOnObjs并作为上下文传递到plan.RenderConfigNScriptFiles

```
// configuration render
if err := plan.RenderConfigNScriptFiles(
    &render.ResourceCtx{
       Context:       transCtx.Context,
       Client:        t.Client,
       Namespace:     comp.GetNamespace(),
       ClusterName:   synthesizedComp.ClusterName,
       ComponentName: synthesizedComp.Name,
    },
    cluster,
    comp,
    synthesizedComp,
    synthesizedComp.PodSpec,
    dependOnObjs); err != nil {
    return err
}
```

首先会创建configOperator对象，并调用Reconcile方法

```
return &configOperator{
		ReconcileCtx{
			ResourceCtx:          resourceCtx,
			Cluster:              cluster,
			Component:            component,
			SynthesizedComponent: synthesizedComponent,
			PodSpec:              podSpec,
			Cache:                localObjs,
		},
	}
```

Reconcile的函数使用Pipeline的方式对配置进行处理，下面对Pipeline中的步骤进行讲解

```
func (c *configOperator) Reconcile() error {
	var synthesizedComponent = c.SynthesizedComponent

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



## Prepare

首先讲一下流程编程的实现过程。每个实现函数都是由Pipeline调用，并返回一个Pipeline结构来实现流式调用。

pipeline的struct中包含：

- Ctx：上下文，包含需要的信息
- renderWrapper
- ResourceFetcher[pipeline]

```
type pipeline struct {
	// configuration *appsv1alpha1.Configuration
	renderWrapper renderWrapper

	ctx render.ReconcileCtx
	ResourceFetcher[pipeline]
}

type renderWrapper struct {
	render.TemplateRender

	volumes             map[string]appsv1.ComponentTemplateSpec
	templateAnnotations map[string]string
	renderedObjs        []client.Object

	renderedSecretObjs []client.Object

	ctx       context.Context
	cli       client.Client
	cluster   *appsv1.Cluster
	component *appsv1.Component
}

type ResourceFetcher[T any] struct {
	obj *T
	*render.ResourceCtx

	ClusterObj      *appsv1.Cluster
	ComponentObj    *appsv1.Component
	ComponentDefObj *appsv1.ComponentDefinition
	ClusterComObj   *appsv1.ClusterComponentSpec

	ConfigMapObj        *corev1.ConfigMap
	ConfigurationObj    *appsv1alpha1.Configuration
	ConfigConstraintObj *appsv1beta1.ConfigConstraint

	ComponentParameterObj *parametersv1alpha1.ComponentParameter
}

```

以Prepare为例，每一步的函数都会返回一个p.Wrap（）的函数，Wrap中会实际执行传输的函数，并捕捉Error。只到这里，可以将Pipeline简单理解为一次执行规定好的函数，并在捕获到Error后停止执行后的的步骤。

```
func (p *pipeline) Prepare() *pipeline {
    buildTemplate := func() (err error) {
       ctx := p.ctx
       p.renderWrapper = newTemplateRenderWrapper(p.Context, ctx.Client, render.NewTemplateBuilder(&ctx), ctx.Cluster, ctx.Component)
       return
    }
    return p.Wrap(buildTemplate)
}

func (r *ResourceFetcher[T]) Wrap(fn func() error) (ret *T) {
	ret = r.obj
	if r.Err != nil {
		return
	}
	r.Err = fn()
	return
}
```

### newTemplateRenderWrapper

Prepare中执行的newTemplateRenderWrapper创建了templateRenderWrapper，同时注入了一些内置函数，这些函数后面会使用Template语法实现，并作为内置函数供用户使用

```
func NewTemplateBuilder(reconcileCtx *ReconcileCtx) TemplateRender {
    builder := &templateRenderWrapper{
       namespace:        reconcileCtx.Namespace,
       clusterName:      reconcileCtx.ClusterName,
       templateName:     defaultTemplateName,
       cluster:          reconcileCtx.Cluster,
       component:        reconcileCtx.Component,
       podSpec:          reconcileCtx.PodSpec,
       builtinComponent: reconcileCtx.SynthesizedComponent,
       ctx:              reconcileCtx.Context,
       cli:              reconcileCtx.Client,
    }
    builder.injectBuiltInObjectsAndFunctions(reconcileCtx.Cache)
    return builder
}
```

templateRenderWrapper的接口定义为下面所示

```
type TemplateRender interface {
    // RenderConfigMapTemplate renders a ConfigMap template based on the provided specification.
    //
    // Parameters:
    // - templateSpec: The specification for the component template.
    //
    // Returns:
    // - A map containing the rendered template data.
    // - An error if the rendering fails.
    RenderConfigMapTemplate(templateSpec appsv1.ComponentTemplateSpec) (map[string]string, error)

    // RenderComponentTemplate renders a component template and validates the rendered data.
    //
    // Parameters:
    // - templateSpec: The specification for the component template.
    // - cmName: The name of the ConfigMap.
    // - dataValidator: A function to validate the rendered data.
    //
    // Returns:
    // - A pointer to the rendered ConfigMap.
    // - An error if the rendering or validation fails.
    RenderComponentTemplate(templateSpec appsv1.ComponentTemplateSpec,
       cmName string,
       dataValidator RenderedValidator) (*corev1.ConfigMap, error)
}
```

## RenderScriptTemplate

RenderScriptTemplate负责根据Component当中的scriptsTemplate字段生成保存脚本内容的ConfigMap并保存在内存中等待创建。

中间的负责具体处理逻辑的函数，基本上都是用Prepare中创建的renderWrapper去调用实际处理的函数

```
func (p *pipeline) RenderScriptTemplate() *pipeline {
    return p.Wrap(func() error {
       ctx := p.ctx
       return p.renderWrapper.renderScriptTemplate(ctx.Cluster, ctx.SynthesizedComponent, ctx.Cache)
    })
}
```

renderScriptTemplate函数会针对CMPD CR中的ScriptTemplates字段生成存储脚本的ConfigMap，并在之后通过VolumeMount挂载到底目标pod中。

这里会判断CM是否已经生成，即在Pipeline的ReconcileCtx.Cache中是否已经存在，并更新到renderWrapper的volumes当中

```
func (wrapper *renderWrapper) renderScriptTemplate(cluster *appsv1.Cluster, component *component.SynthesizedComponent,
    localObjs []client.Object) error {
    for _, templateSpec := range component.ScriptTemplates {
       cmName := core.GetComponentCfgName(cluster.Name, component.Name, templateSpec.Name)
       object := findMatchedLocalObject(localObjs, client.ObjectKey{
          Name:      cmName,
          Namespace: wrapper.cluster.Namespace}, generics.ToGVK(&corev1.ConfigMap{}))
       if object != nil {
          wrapper.addVolumeMountMeta(templateSpec, object, false, true)
          continue
       }

       // Generate ConfigMap objects for config files
       cm, err := wrapper.RenderComponentTemplate(templateSpec, cmName, nil)
       if err != nil {
          return err
       }
       if err := wrapper.addRenderedObject(templateSpec, cm, nil, true); err != nil {
          return err
       }
    }
    return nil
}
```

如果不存在则会实际生成ConfigMap。RenderComponentTemplate -> r.RenderConfigMapTemplate 。这里会通过goclient获取到对应名字的ConfigMap对象，并继续调用 r.render(cmObj.Data)完成内容的生成

```
// RenderComponentTemplate renders config file by config template provided by provider.
func (r *templateRenderWrapper) RenderComponentTemplate(
    templateSpec appsv1.ComponentTemplateSpec,
    cmName string,
    dataValidator RenderedValidator) (*corev1.ConfigMap, error) {
    // Render config template by TplEngine
    // The template namespace must be the same as the ClusterDefinition namespace
    configs, err := r.RenderConfigMapTemplate(templateSpec)
    if err != nil {
       return nil, err
    }

    if dataValidator != nil {
       if err = dataValidator(configs); err != nil {
          return nil, err
       }
    }

    // Using ConfigMap cue template render to configmap of config
    return factory.BuildConfigMapWithTemplate(r.cluster, r.builtinComponent, configs, cmName, templateSpec), nil
}
```

render函数会实际生成配置或者脚本的内容。对于configMap.data 中的每个文件执行rander，最终调用go 语言的text/template库完成实际渲染。实际上就是通过go Template语法渲染最终的配置文件go Template语法.

go Template语法：https://www.topgoer.com/%E5%B8%B8%E7%94%A8%E6%A0%87%E5%87%86%E5%BA%93/template.html

并且通过builtinObjectsAsValues，builtInFunctions来注入自定义的变量和自定义函数到go Template语法当中。

```
func (r *templateRenderWrapper) render(configs map[string]string) (map[string]string, error) {
    values, err := builtinObjectsAsValues(r.builtInObjects)
    if err != nil {
       return nil, err
    }

    rendered := make(map[string]string, len(configs))
    engine := gotemplate.NewTplEngine(values, r.builtInFunctions, r.templateName, r.cli, r.ctx)
    for file, configContext := range configs {
       newContext, err := engine.Render(configContext)
       if err != nil {
          return nil, r.formatError(file, err)
       }
       rendered[file] = newContext
    }
    return rendered, nil
}

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

具体的自定义变量和自定义函数可以直接查看这两个函数。这里就不在细究。

```
func builtinCustomObjects(builtin *builtInObjects) map[string]any {
    return map[string]any{
       builtinClusterObject:       builtin.cluster,
       builtinComponentObject:     builtin.component,
       builtinPodObject:           builtin.podSpec,
       builtinClusterDomainObject: viper.GetString(constant.KubernetesClusterDomainEnv),
    }
}

// BuiltInCustomFunctions builds a map of customized functions for KubeBlocks
func BuiltInCustomFunctions(c *templateRenderWrapper, component *component.SynthesizedComponent, localObjs []client.Object) *gotemplate.BuiltInObjectsFunc {
	return &gotemplate.BuiltInObjectsFunc{
		builtInMysqlCalBufferFunctionName:            calDBPoolSize,
		builtInGetVolumeFunctionName:                 getVolumeMountPathByName,
		builtInGetPvcFunctionName:                    getPVCByName,
		builtInGetEnvFunctionName:                    wrapGetEnvByName(c, component, localObjs),
		builtInGetPortFunctionName:                   getPortByName,
		builtInGetArgFunctionName:                    getArgByName,
		builtInGetContainerFunctionName:              getPodContainerByName,
		builtInGetContainerCPUFunctionName:           getContainerCPU,
		builtInGetPVCSizeByNameFunctionName:          getComponentPVCSizeByName,
		builtInGetPVCSizeFunctionName:                getPVCSize,
		builtInGetContainerMemoryFunctionName:        getContainerMemory,
		builtInGetContainerRequestMemoryFunctionName: getContainerRequestMemory,
	}
}

```

addRenderedObject会给生成的ConfigMap添加Reference还有annotation，之后会添加到renderWrapper的renderedObjs当中，

到此为止就完成了RenderScriptTemplate的步骤

```
func (wrapper *renderWrapper) addRenderedObject(templateSpec appsv1.ComponentTemplateSpec, cm *corev1.ConfigMap, configuration *appsv1alpha1.Configuration, asVolume bool) (err error) {
	// The owner of the configmap object is a cluster,
	// in order to manage the life cycle of configmap
	if configuration != nil {
		err = intctrlutil.SetControllerReference(configuration, cm)
	} else {
		err = intctrlutil.SetControllerReference(wrapper.component, cm)
	}
	if err != nil {
		return err
	}

	core.SetParametersUpdateSource(cm, constant.ReconfigureManagerSource)
	wrapper.addVolumeMountMeta(templateSpec, cm, true, asVolume)
	return nil
}
```

## UpdateConfiguration

这一步主要是构建Configuration CR，并且实际创建或者更新该CR

一个Configuration CR类似这样，包括

- clusterRef：从属的cluster
- componentName
- configItemDetails：
  - configSpec：指向和具体配置相关的一些CR信息，以及一些配置描述信息
  - payload与实际的资源保持同步，用于计算一些特殊配置

```
apiVersion: apps.kubeblocks.io/v1alpha1
kind: Configuration
spec:
  clusterRef: asmysql-aspxea
  componentName: mysql
  configItemDetails:
  - configSpec:
      constraintRef: mysql-8.0-config-constraints
      name: mysql-replication-config
      namespace: kb-system
      reRenderResourceTypes:
      - vscale
      templateRef: mysql-8.0-config-template
      volumeName: mysql-config
    name: mysql-replication-config
    payload:
      component-resource:
        limits:
          cpu: 500m
          memory: 512Mi
        requests:
          cpu: 500m
          memory: 512Mi

```

基本思路是先生成configuration的原型，也就是本次Reconcile期望的状态，与实际的configuration比较。根据不同来创建或者更新configuration

这里的configuration会直接通过Client创建，而不是加入dag在整个Reconcile过程的后面实际创建。这与配置的设计有一定关系，配置并没有纳入到数据库集群的生命周期的范畴当中（也就是cluster、Component之类的CRD），而是作为一个较为独立的模块来完成配置的渲染和生效过程。这一点从启动时的flag也可探究一二。

```
func (p *pipeline) UpdateConfiguration() *pipeline {
    buildConfiguration := func() (err error) {
       expectedConfiguration := p.createConfiguration()
       if intctrlutil.SetControllerReference(p.ctx.Component, expectedConfiguration) != nil {
          return
       }
       _, _ = UpdateConfigPayload(&expectedConfiguration.Spec, p.ctx.SynthesizedComponent)

       existingConfiguration := appsv1alpha1.Configuration{}
       err = p.ResourceFetcher.Client.Get(p.Context, client.ObjectKeyFromObject(expectedConfiguration), &existingConfiguration)
       switch {
       case err == nil:
          return p.updateConfiguration(expectedConfiguration, &existingConfiguration)
       case apierrors.IsNotFound(err):
          return p.ResourceFetcher.Client.Create(p.Context, expectedConfiguration)
       default:
          return err
       }
    }
    return p.Wrap(buildConfiguration)
}
```

updateConfiguration的过程也就是一个merge的过程，最后会通过p.Client.Patch直接更新

```
func (p *pipeline) updateConfiguration(expected *appsv1alpha1.Configuration, existing *appsv1alpha1.Configuration) error {
    fromMap := func(items []appsv1alpha1.ConfigurationItemDetail) *cfgutil.Sets {
       sets := cfgutil.NewSet()
       for _, item := range items {
          sets.Add(item.Name)
       }
       return sets
    }

    updateConfigSpec := func(item appsv1alpha1.ConfigurationItemDetail) appsv1alpha1.ConfigurationItemDetail {
       if newItem := expected.Spec.GetConfigurationItem(item.Name); newItem != nil {
          item.ConfigSpec = newItem.ConfigSpec
       }
       return item
    }

    oldSets := fromMap(existing.Spec.ConfigItemDetails)
    newSets := fromMap(expected.Spec.ConfigItemDetails)

    addSets := cfgutil.Difference(newSets, oldSets)
    delSets := cfgutil.Difference(oldSets, newSets)

    newConfigItems := make([]appsv1alpha1.ConfigurationItemDetail, 0)
    for _, item := range existing.Spec.ConfigItemDetails {
       if !delSets.InArray(item.Name) {
          newConfigItems = append(newConfigItems, updateConfigSpec(item))
       }
    }
    for _, item := range expected.Spec.ConfigItemDetails {
       if addSets.InArray(item.Name) {
          newConfigItems = append(newConfigItems, item)
       }
    }

    patch := client.MergeFrom(existing)
    updated := existing.DeepCopy()
    updated.Spec.ConfigItemDetails = newConfigItems
    return p.Client.Patch(p.Context, updated, patch)
}
```

## Configuration

这一步的处理就是获取到Configuration并放到r.ConfigurationObj

```
func (r *ResourceFetcher[T]) Configuration() *T {
    configKey := client.ObjectKey{
       Name:      cfgcore.GenerateComponentConfigurationName(r.ClusterName, r.ComponentName),
       Namespace: r.Namespace,
    }
    return r.Wrap(func() (err error) {
       configuration := appsv1alpha1.Configuration{}
       err = r.Client.Get(r.Context, configKey, &configuration)
       if err != nil {
          return client.IgnoreNotFound(err)
       }
       r.ConfigurationObj = &configuration
       return
    })
}
```

```
func (r *ResourceFetcher[T]) Configuration() *T {
    configKey := client.ObjectKey{
       Name:      cfgcore.GenerateComponentConfigurationName(r.ClusterName, r.ComponentName),
       Namespace: r.Namespace,
    }
    return r.Wrap(func() (err error) {
       configuration := appsv1alpha1.Configuration{}
       err = r.Client.Get(r.Context, configKey, &configuration)
       if err != nil {
          return client.IgnoreNotFound(err)
       }
       r.ConfigurationObj = &configuration
       return
    })
}
```

## CreateConfigTemplate

> render configTemplate into ConfigMap (only for the first time)

这一步主要生成配置相关的ConfigMap的内容

```
func (p *pipeline) CreateConfigTemplate() *pipeline {
    return p.Wrap(func() error {
       ctx := p.ctx
       return p.renderWrapper.renderConfigTemplate(ctx.Cluster, ctx.SynthesizedComponent, ctx.Cache, p.ConfigurationObj)
    })
}
```

处理步骤：

1. 计算Revision
2. 针对SynthesizedComponent中的每个ConfigTemplates字段
   1. 获取实际的ConfigMap对象
   2. 添加到renderWrapper中的volumes（如果该配置需要以Secret的形式使用则不添加）
   3. 生成配置的实际内容
   4. 渲染用户指定模版
   5. 更新Labels

```
func (wrapper *renderWrapper) renderConfigTemplate(cluster *appsv1.Cluster,
    component *component.SynthesizedComponent, localObjs []client.Object, configuration *appsv1alpha1.Configuration) error {
    revision := fromConfiguration(configuration)
    for _, configSpec := range component.ConfigTemplates {
       var item *appsv1alpha1.ConfigurationItemDetail
       cmName := core.GetComponentCfgName(cluster.Name, component.Name, configSpec.Name)
       origCMObj, err := wrapper.checkRerenderTemplateSpec(cmName, localObjs)
       if err != nil {
          return err
       }
       // If ConfigMap already exists, skip the rendering process.
       // In this way, the Component controller only creates ConfigMap objects for the first time,
       // and does not update the ConfigMap objects in the subsequent reconfiguration process.
       // The subsequent reconfiguration process is handled by the Configuration controller.
       if origCMObj != nil {
          wrapper.addVolumeMountMeta(configSpec.ComponentTemplateSpec, origCMObj, false, !toSecret(configSpec))
          continue
       }
       if configuration != nil {
          item = configuration.Spec.GetConfigurationItem(configSpec.Name)
       }
       newCMObj, err := wrapper.rerenderConfigTemplate(cluster, component, configSpec, item)
       if err != nil {
          return err
       }
       if err := applyUpdatedParameters(item, newCMObj, configSpec, wrapper.cli, wrapper.ctx); err != nil {
          return err
       }
       if err := wrapper.addRenderedObject(configSpec.ComponentTemplateSpec, newCMObj, configuration, !toSecret(configSpec)); err != nil {
          return err
       }
       if err := updateConfigMetaForCM(newCMObj, item, revision); err != nil {
          return err
       }
    }
    return nil
}
```

通过RenderComponentTemplate渲染内容与渲染脚本相同

这里多了一个自定义模版的功能，也就是用户通过ImportTemplateRef字段来制定一些关键参数的配置规则，在配置渲染时，这部分配置会与之前生成的配置进行merge。让用户可以更加方便的指定一些动态配置规则。实际渲染的方式仍然是text/template

merge的方式包括：

```
const (
    PatchPolicy     MergedPolicy = "patch"
    ReplacePolicy   MergedPolicy = "replace"
    OnlyAddPolicy   MergedPolicy = "add"
    NoneMergePolicy MergedPolicy = "none"
)
```



## UpdatePodVolumes

> update podSpec.Volumes

经过上面的配置和脚本渲染，需要以volume的形式挂载的ConfigMap都保存在renderWrapper.volumes

```
func (p *pipeline) UpdatePodVolumes() *pipeline {
    return p.Wrap(func() error {
       return intctrlutil.CreateOrUpdatePodVolumes(p.ctx.PodSpec,
          p.renderWrapper.volumes,
          configSetFromComponent(p.ctx.SynthesizedComponent.ConfigTemplates))
    })
}
```

CreateOrUpdateVolume会生成最终的ConfigMap对象对应的volume对象

参数中传递的两个函数就是createFn，updateFn

CreateOrUpdatePodVolumes -> for cmName in volumeKeys ->

```
if podVolumes, err = CreateOrUpdateVolume(podVolumes, templateSpec.VolumeName, func(volumeName string) corev1.Volume {
    return corev1.Volume{
       Name: volumeName,
       VolumeSource: corev1.VolumeSource{
          ConfigMap: &corev1.ConfigMapVolumeSource{
             LocalObjectReference: corev1.LocalObjectReference{Name: cmName},
             // TODO: remove ComponentTemplateSpec.DefaultMode
             DefaultMode: BuildVolumeMode(configSet, templateSpec),
          },
       },
    }
}, func(volume *corev1.Volume) error {
    configMap := volume.ConfigMap
    if configMap == nil {
       return fmt.Errorf("mount volume[%s] requires a ConfigMap: [%+v]", volume.Name, volume)
    }
    configMap.Name = cmName
    return nil
}); err != nil {
    return err
}
```



## BuildConfigManagerSidecar

> buildConfigManagerWithComponent build the configmgr sidecar container and update it
>  into PodSpec if configuration reload option is on

如果用户有配置动态更新的需求，那么就需要在Pod中引入一个sidecar--configManager，来完成这类需求

这一步就是判断用户是否需要配置更新的功能，如果需要就在pod注入一个sidecar

```
func (p *pipeline) BuildConfigManagerSidecar() *pipeline {
    return p.Wrap(func() error {
       return buildConfigManagerWithComponent(p.ctx.PodSpec, p.ctx.SynthesizedComponent.ConfigTemplates, p.Context, p.Client, p.ctx.Cluster, p.ctx.SynthesizedComponent)
    })
}
```

```
// buildConfigManagerWithComponent build the configmgr sidecar container and update it
// into PodSpec if configuration reload option is on
func buildConfigManagerWithComponent(podSpec *corev1.PodSpec, configSpecs []appsv1.ComponentConfigSpec,
    ctx context.Context, cli client.Client, cluster *appsv1.Cluster, synthesizedComp *component.SynthesizedComponent) error {
    var err error
    var buildParams *cfgcm.CfgManagerBuildParams

    volumeDirs, usingConfigSpecs := getUsingVolumesByConfigSpecs(podSpec, configSpecs)
    if len(volumeDirs) == 0 {
       return nil
    }
    configSpecMetas, err := cfgcm.GetSupportReloadConfigSpecs(usingConfigSpecs, cli, ctx)
    if err != nil {
       return err
    }
    // Configmap uses subPath case: https://github.com/kubernetes/kubernetes/issues/50345
    // The files are being updated on the host VM, but can't be updated in the container.
    configSpecMetas = cfgcm.FilterSupportReloadActionConfigSpecs(configSpecMetas, volumeDirs)
    if len(configSpecMetas) == 0 {
       return nil
    }
    if buildParams, err = buildConfigManagerParams(cli, ctx, cluster, synthesizedComp, configSpecMetas, volumeDirs, podSpec); err != nil {
       return err
    }
    if buildParams == nil {
       return nil
    }

    // This sidecar container will be able to view and signal processes from other containers
    checkAndUpdateSharProcessNamespace(podSpec, buildParams, configSpecMetas)
    container, err := factory.BuildCfgManagerContainer(buildParams)
    if err != nil {
       return err
    }
    updateEnvPath(container, buildParams)
    updateCfgManagerVolumes(podSpec, buildParams)

    // Add sidecar to podTemplate
    podSpec.Containers = append(podSpec.Containers, *container)
    if len(buildParams.ToolsContainers) > 0 {
       podSpec.InitContainers = append(podSpec.InitContainers, buildParams.ToolsContainers...)
    }
    filter := func(c *corev1.Container) bool {
       names := []string{container.Name}
       for _, cc := range buildParams.ToolsContainers {
          names = append(names, cc.Name)
       }
       return slices.Contains(names, c.Name)
    }
    component.InjectEnvVars4Containers(synthesizedComp, synthesizedComp.EnvVars, synthesizedComp.EnvFromSources, filter)
    return nil
}
```

下面会针对涉及到的函数进行解析

### getUsingVolumesByConfigSpecs

接下来关注getUsingVolumesByConfigSpecs

1. 检查生成的ConfigMap是否被使用，即是否通过volumeMount挂载到Pod当中。如果没有的话则视为配置和脚本并没有被使用，那么就不需要注入configManager的sidecar

```
usingConfigSpecs := make([]appsv1.ComponentConfigSpec, 0, len(configSpecs))
config2Containers := make(map[string][]*corev1.Container)
for _, configSpec := range configSpecs {
    usingContainers := intctrlutil.GetPodContainerWithVolumeMount(podSpec, configSpec.VolumeName)
    if len(usingContainers) == 0 {
       continue
    }
    usingConfigSpecs = append(usingConfigSpecs, configSpec)
    config2Containers[configSpec.Name] = usingContainers
}

// No container using any config template
if len(usingConfigSpecs) == 0 {
  log.Log.Info(fmt.Sprintf("configSpec config is not used by any container, and pass. configSpec configs: %v", configSpecs))
  return nil, nil
}
```

2. 从筛选出的实际使用配置功能的Container中获取到所有的VolumeMount信息，并返回

```
// Find out which configurations are used by the container
volumeDirs := make([]corev1.VolumeMount, 0, len(configSpecs)+1)
for _, configSpec := range usingConfigSpecs {
    // Ignore config template, e.g scripts configmap
    if !core.NeedReloadVolume(configSpec) {
       continue
    }
    sets := cfgutil.NewSet()
    for _, container := range config2Containers[configSpec.Name] {
       volume := intctrlutil.GetVolumeMountByVolume(container, configSpec.VolumeName)
       if volume != nil && !sets.InArray(volume.Name) {
          volumeDirs = append(volumeDirs, *volume)
          sets.Add(volume.Name)
       }
    }
}
```

### GetSupportReloadConfigSpecs

configSpecs中的ConfigConstraintRef指向了一个ConfigConstraint CR，这个CR就是控制配置的reload行为的

这里Get到实际的ConfigConstraint，根据其具体内容判断当前configSpec是否需要reload，并返回需要reload的configSpec组合的ConfigSpecMeta

### FilterSupportReloadActionConfigSpecs

这里直接贴出该函数的注释

```
// FilterSupportReloadActionConfigSpecs 根据重新加载操作类型和卷挂载配置，对提供的 ConfigSpecMeta 切片进行过滤。
// 它处理两种对 ConfigMap 的更新：
//
// 1. 异步模式：KubeBlocks 控制器负责更新 ConfigMap，而 kubelet 将 ConfigMap 同步到卷中。
// config-manager 使用 fsnotify 检测配置更改并执行重新加载操作。这需要将 ConfigMap 挂载为卷。
// 然而，在异步模式下，如果卷挂载是子路径，kubelet 不会将 ConfigMap 内容同步到容器中（参见 kubernetes/kubernetes#50345）。
// 因此，config-manager 无法检测到配置更改，并且不支持对此类配置进行动态参数更新。
// 因此，需要移除具有子路径卷挂载的异步类型 ConfigSpecs。
//
// 2. 同步模式：对于同步模式（无论重新加载操作类型是 TPLScriptType 触发器还是 ShellType 触发器），控制器直接监听
// ConfigMap 的更改并主动调用重新加载操作。
//
// 无论是异步还是同步类型，都需要将 ConfigSpecs 传递给 config-manager。
//
// 检查逻辑是一个 OR 条件：要么是第一种类型（同步模式），要么是第二种类型（异步）且具有非子路径的卷挂载配置。
```

### buildConfigManagerParams

生成ConfigManager需要的参数

```
func buildConfigManagerParams(cli client.Client, ctx context.Context, cluster *appsv1.Cluster, comp *component.SynthesizedComponent, configSpecBuildParams []cfgcm.ConfigSpecMeta, volumeDirs []corev1.VolumeMount, podSpec *corev1.PodSpec) (*cfgcm.CfgManagerBuildParams, error) {
    cfgManagerParams := &cfgcm.CfgManagerBuildParams{
       ManagerName:               constant.ConfigSidecarName,
       ComponentName:             comp.Name,
       Image:                     viper.GetString(constant.KBToolsImage),
       Volumes:                   volumeDirs,
       Cluster:                   cluster,
       ConfigSpecsBuildParams:    configSpecBuildParams,
       ConfigLazyRenderedVolumes: make(map[string]corev1.VolumeMount),
       ContainerPort:             viper.GetInt32(constant.ConfigManagerGPRCPortEnv),
    }

    if podSpec.HostNetwork {
       containerPort, err := allocConfigManagerHostPort(comp)
       if err != nil {
          return nil, err
       }
       cfgManagerParams.ContainerPort = containerPort
    }

    if err := cfgcm.BuildConfigManagerContainerParams(cli, ctx, cfgManagerParams, volumeDirs); err != nil {
       return nil, err
    }
    if err := buildReloadToolsContainer(cfgManagerParams, podSpec); err != nil {
       return nil, err
    }
    return cfgManagerParams, nil
}
```

这里涉及到HostNetwork模式下的Port分配，详情见：

### checkAndUpdateSharProcessNamespace

有一些数据库的配置reload是通过signal来触发的，这里可以使用K8s PodSec中的ShareProcessNamespace字段，使得进程之间可见

```
  // 在 Pod 中的所有容器之间共享一个单一的进程命名空间。
  // 当启用此选项时，容器将能够查看并信号化同一 Pod 中其他容器的进程，
  // 并且每个容器中的第一个进程不会被分配 PID 1。
  // HostPID 和 ShareProcessNamespace 不能同时设置。
  // 可选：默认为 false。
  // +k8s:conversion-gen=false
  // +optional
	ShareProcessNamespace *bool `json:"shareProcessNamespace,omitempty" protobuf:"varint,27,opt,name=shareProcessNamespace"`
```

### BuildCfgManagerContainer

生成configManager 的Container对象

### updateCfgManagerVolumes

更新scripts和Config相关的Volume

```
for _, vm := range []*[]corev1.Volume{
    &configManager.ScriptVolume,
    &configManager.CMConfigVolumes,
} {
    for i := range *vm {
       podVolumes, _ = intctrlutil.CreateOrUpdateVolume(podVolumes, (*vm)[i].Name, func(string) corev1.Volume {
          return (*vm)[i]
       }, nil)
    }
}

```

```
func CreateOrUpdateVolume(volumes []corev1.Volume, volumeName string, createFn createVolumeFn, updateFn updateVolumeFn) ([]corev1.Volume, error) {
	// for update volume
	if existIndex := findVolumeWithVolumeName(volumes, volumeName); existIndex >= 0 {
		if updateFn == nil {
			return volumes, nil
		}
		if err := updateFn(&volumes[existIndex]); err != nil {
			return volumes, err
		}
		return volumes, nil
	}

	// for create volume
	return append(volumes, createFn(volumeName)), nil
}
```



### 将sidecar添加到pod

```
podSpec.Containers = append(podSpec.Containers, *container)
if len(buildParams.ToolsContainers) > 0 {
    podSpec.InitContainers = append(podSpec.InitContainers, buildParams.ToolsContainers...)
}
```



### InjectEnvVars4Containers

synthesizedComp是每次Component Reconcile时生成的，包含Reconcile需要的大多数信息。有一些Component级别共享的ENV就保存在 synthesizedComp.EnvVars。configManager需要将这些ENV注入自身的容器当中，保证配置更新的时候可以使用这些变量。



## UpdateConfigRelatedObject

> handle InjectEnvTo, and create or update ConfigMaps

```
func (p *pipeline) UpdateConfigRelatedObject() *pipeline {
    updateMeta := func() error {
       if err := injectTemplateEnvFrom(p.ctx.Cluster, p.ctx.SynthesizedComponent, p.ctx.PodSpec, p.Client, p.Context, p.renderWrapper.renderedObjs); err != nil {
          return err
       }
       return createConfigObjects(p.Client, p.Context, p.renderWrapper.renderedObjs, p.renderWrapper.renderedSecretObjs)
    }

    return p.Wrap(updateMeta)
}
```

### injectTemplateEnvFrom

injectTemplateEnvFrom 会将配置模版中的配置项以环境变量的形式注入到Pod容器，其中：

- fetchConfigmap：会首先从renderWrapper.renderedObjs获取缓存的对象，如果不存在则通过cli.get直接获取到ConfigMap

```
// func injectTemplateEnvFrom
for _, template := range component.ConfigTemplates {
    if !InjectEnvEnabled(template) || template.ConfigConstraintRef == "" {
       continue
    }
    cmName := core.GetComponentCfgName(cluster.Name, component.Name, template.Name)
    if cm, err = fetchConfigmap(localObjs, cmName, cluster.Namespace, cli, ctx); err != nil {
       return err
    }
    cc, err := getConfigConstraint(template, cli, ctx)
    if err != nil {
       return err
    }
    envMap, err := fromConfigmapFiles(fromConfigSpec(template, cm), cm, cc.FileFormatConfig)
    if err != nil {
       return err
    }
    if len(envMap) == 0 {
       continue
    }
    if err := injectConfigmap(envMap, template, cmName); err != nil {
       return err
    }
}
```

#### fromConfigmapFiles

该函数接受configSpec.Keys作为参数，该值指定ConfigSpec中哪些文件支持动态修改和重新加载

```
for _, file := range keys {
  envMap, err := fromFileContent(formatter, cm.Data[file])
  if err != nil {
    return nil, err
  }
  mergeMap(gEnvMap, envMap)
}
```

-> LoadConfigObjectFromContent，在这里根据ConfigConstraintSpec中对配置文件格式的描述，生成不同格式的configObject，并解析出配置的KV值

```
func LoadConfigObjectFromContent(cfgType appsv1beta1.CfgFileFormat, rawData string) (map[string]interface{}, error) {
    configObject, err := unstructured.LoadConfig("validate", rawData, cfgType)
    if err != nil {
       return nil, err
    }

    return configObject.GetAllParameters(), nil
}

func LoadConfig(name string, content string, format appsv1beta1.CfgFileFormat) (ConfigObject, error) {
	configObject, err := CfgObjectRegistry().GetConfigObject(name, format)
	if err != nil {
		return nil, err
	}
	if err := configObject.Unmarshal(content); err != nil {
		return nil, err
	}
	return configObject, nil
}
```

##### 配置文件解析

由于配置设计多种文件格式，所以需要多种格式的解析器，在Kubeblocks的配置中，解析器的接口抽象为ConfigObject，并且由ConfigObjectRegistry统一生成

```
type ConfigObjectRegistry struct {
    objectCreator map[appsv1beta1.CfgFileFormat]ConfigObjectCreator
}

func (c *ConfigObjectRegistry) RegisterConfigCreator(format appsv1beta1.CfgFileFormat, creator ConfigObjectCreator) {
	c.objectCreator[format] = creator
}

func (c *ConfigObjectRegistry) GetConfigObject(name string, format appsv1beta1.CfgFileFormat) (ConfigObject, error) {
	creator, ok := c.objectCreator[format]
	if !ok {
		return nil, fmt.Errorf("not supported type[%s]", format)
	}
	return creator(name), nil
}
```

```
type ConfigObject interface {
    // Update sets the value for the key in ConfigObject
    Update(key string, value any) error

    // RemoveKey configuration parameter
    RemoveKey(key string) error

    // Get returns an interface.
    Get(key string) interface{}

    // GetString returns the value associated with the key as a string
    GetString(key string) (string, error)

    // GetAllParameters returns all config params as a map[string]interface{}
    GetAllParameters() map[string]interface{}

    // SubConfig returns new Sub ConfigObject instance.
    SubConfig(key string) ConfigObject

    // Marshal outputs the ConfigObject to string
    Marshal() (string, error)

    // Unmarshal reads a string and returns the valid key/value pair of valid variables.
    Unmarshal(str string) error
}
```

以YamlConfig为例，在init函数中会注册到ConfigObjectRegistry当中

```
type yamlConfig struct {
    name   string
    config map[string]any
}

func init() {
    CfgObjectRegistry().RegisterConfigCreator(appsv1beta1.YAML, func(name string) ConfigObject {
       return &yamlConfig{name: name}
    })
}
```

很多配置统一采用了github.com/spf13/viper库进行解析，通过CfgFileFormat来确定解析方式

```
type viperWrap struct {
    *oviper.Viper

    name   string
    format appsv1beta1.CfgFileFormat
}

func init() {
    CfgObjectRegistry().RegisterConfigCreator(appsv1beta1.Ini, createViper(appsv1beta1.Ini))
    // CfgObjectRegistry().RegisterConfigCreator(appsv1beta1.YAML, createViper(appsv1beta1.YAML))
    CfgObjectRegistry().RegisterConfigCreator(appsv1beta1.JSON, createViper(appsv1beta1.JSON))
    CfgObjectRegistry().RegisterConfigCreator(appsv1beta1.Dotenv, createViper(appsv1beta1.Dotenv))
    CfgObjectRegistry().RegisterConfigCreator(appsv1beta1.HCL, createViper(appsv1beta1.HCL))
    CfgObjectRegistry().RegisterConfigCreator(appsv1beta1.TOML, createViper(appsv1beta1.TOML))
    CfgObjectRegistry().RegisterConfigCreator(appsv1beta1.Properties, createViper(appsv1beta1.Properties))
}

func createViper(format appsv1beta1.CfgFileFormat) ConfigObjectCreator {
	return func(name string) ConfigObject {
		return &viperWrap{
			name:   name,
			format: format,
			Viper:  newCfgViper(format),
		}
	}
}

```

#### injectConfigmap

将EnvFrom注入到PodSpec当中

```
injectConfigmap := func(envMap map[string]string, configSpec appsv1.ComponentConfigSpec, cmName string) error {
    envSourceObject, err := createOrUpdateResourceFromConfigTemplate(cluster, component, configSpec, client.ObjectKeyFromObject(cm), envMap, ctx, cli, true)
    if err != nil {
       return core.WrapError(err, "failed to generate env configmap[%s]", cmName)
    }
    if toSecret(configSpec) && configSpec.VolumeName != "" {
       podSpec.Volumes = updateSecretVolumes(podSpec.Volumes, configSpec, envSourceObject, component)
    } else {
       injectEnvFrom(podSpec.Containers, containersInjectedTo(configSpec), envSourceObject.GetName(), withEnvSource(toSecret(configSpec)))
       injectEnvFrom(podSpec.InitContainers, containersInjectedTo(configSpec), envSourceObject.GetName(), withEnvSource(toSecret(configSpec)))
    }
    return nil
}
```

### createConfigObjects

Create Or Update 所有配置涉及到的ConfigMap

## UpdateConfigurationStatus

> update ConfigurationItemStatus revision and phase etc.

```
func (p *pipeline) UpdateConfigurationStatus() *pipeline {
    return p.Wrap(func() error {
       if p.ConfigurationObj == nil {
          return nil
       }

       existing := p.ConfigurationObj
       reversion := fromConfiguration(existing)
       patch := client.MergeFrom(existing)
       updated := existing.DeepCopy()
       for _, item := range existing.Spec.ConfigItemDetails {
          CheckAndUpdateItemStatus(updated, item, reversion)
       }
       return p.ResourceFetcher.Client.Status().Patch(p.Context, updated, patch)
    })
}
```



## Complete



# ConfigManager



# 未来计划

之后配置部分会从Kubeblocks的apps.kubeblocks.io API group中正式独立，成为独立的API group

而ConfigManager也会和KBAgent整合到一个sidecar中，方便管理

会将配置文件和配置项进行区分，即可以没有配置文件直接操作配置项
