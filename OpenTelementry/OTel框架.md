OpenTelemetry Collector是OTel采集器的框架，提供了监控数据采集的一套标准框架

，定义了一套

​                    extension

receiver -> processor -> exporter 

的数据采集流

具体实现上，整个框架采用插件化的思想，每个部分都可以采用组件库中现成的组件，或者自己编写的组件



# 调用栈

```
main -> run(CollectorSettings) -> runInteractive(CollectorSettings) -> cmd.Execute
|- NewCollector
|  |- NewConfigProvider -> NewResolver
|  |  |- for factory in set.ProviderFactories
|  |  |  |- factory.Create(set.ProviderSettings)
|  |  |- for factory in set.ConverterFactories
|  |  |  |- factory.Create(set.ConverterSettings)
|  |  |- for uri in set.URIs -> newLocation(uri)
|- col.Run -> setupConfigurationComponents
|  |- service.New()
|  |- col.service.Start()
|  |  |- srv.host.ServiceExtensions.Start
|  |  |- srv.host.Pipelines.StartAll
|  |  |- rv.host.ServiceExtensions.NotifyPipelineReady()


```

## 启动流程

云原生应用典型的以Cobra库构建命令行启动，通过cmd.Execute()，

首先看一下OpenTelementry-Collector的核心类，从注释可以获取到Collector的处理流程

收集器生命周期： 

1. New 构造一个新的收集器。 
2. Run 启动收集器。
3. Run 调用 setupConfigurationComponents 处理配置。 
4.  如果配置解析失败，收集器的配置可以重新加载。 
5. 如果解析器收到关闭错误，收集器可以关闭。 
6. Run 运行 runAndWaitForShutdownEvent 并等待关闭事件。 
7. SIGINT 和 SIGTERM 信号、错误以及调用 (*Collector).Shutdown 可以触发关闭事件。 
8. 关闭时，首先通知管道，然后关闭管道和扩展。 
9. 用户可以随时调用 (*Collector).Shutdown 来关闭收集器。

```
// Collector represents a server providing the OpenTelemetry Collector service.
type Collector struct {
    set CollectorSettings

    configProvider *ConfigProvider

    serviceConfig *service.Config
    service       *service.Service
    state         *atomic.Int64

    // shutdownChan is used to terminate the collector.
    shutdownChan chan struct{}
    // signalsChannel is used to receive termination signals from the OS.
    signalsChannel chan os.Signal
    // asyncErrorChannel is used to signal a fatal error from any component.
    asyncErrorChannel          chan error
    bc                         *bufferedCore
    updateConfigProviderLogger func(core zapcore.Core)
}
```

先来看一下Collector的初始化过程：初始化了logger、ConfigProvider

记录了状态为StateStarting

```
bc := newBufferedCore(zapcore.DebugLevel)
cc := &collectorCore{core: bc}
logger := zap.New(cc, options...)

configProvider, err := NewConfigProvider(set.ConfigProviderSettings)

state.Store(int64(StateStarting))
return &Collector{
    set:          set,
    state:        state,
    shutdownChan: make(chan struct{}),
    // Per signal.Notify documentation, a size of the channel equaled with
    // the number of signals getting notified on is recommended.
    signalsChannel:             make(chan os.Signal, 3),
    asyncErrorChannel:          make(chan error),
    configProvider:             configProvider,
    bc:                         bc,
    updateConfigProviderLogger: cc.SetCore,
}, nil
```

# Resolver

这里初始化的Resolver用于加载、处理配置。并且可以watch配置的更新

解析配置的过程如下：

1. 从所有给定的 "URI" 中检索单独的配置，并按检索顺序合并它们。

2. 合并 Conf 后，按给定顺序应用转换器。 

配置解析完成后，`Resolver` 可以作为一个单一的点来监视通过配置提供程序检索的配置数据的更新，这些提供程序用于处理 "初始" 配置并生成 "有效" 配置。典型用法如下：

Resolver.Resolve(ctx)

Resolver.Watch() // 等待事件。	

重复 Resolve/Watch 循环，直到关闭 Collector 进程。 

Resolver.Shutdown(ctx)

## Reload

```
// Watch blocks until any configuration change was detected or an unrecoverable error
// happened during monitoring the configuration changes.
//
// Error is nil if the configuration is changed and needs to be re-fetched. Any non-nil
// error indicates that there was a problem with watching the config changes.
//
// Should never be called concurrently with itself or Get.
func (cm *ConfigProvider) Watch() <-chan error {
	return cm.mapResolver.Watch()
}
```

主服务会监听这个Channel，接受到信号后会触发配置的重载。