---
title: OpenTelemetry Collector 架构源码
date: 2025-03-20
update: 2025-03-21
comment: false
tags:
  - OpenTelemetry
categories:
  - OpenTelemetry
---

OpenTelemetry Collector是OTel采集器的框架，提供了监控数据采集的一套标准框架

*<!--more-->*

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

# 启动流程

云原生应用典型的以Cobra库构建命令行启动，通过cmd.Execute()，

首先看一下OpenTelementry-Collector的核心类，从注释可以获取到Collector的处理流程

收集器生命周期： 

1. New 构造一个新的收集器。 
2. Run 启动收集器。
3. Run 调用 setupConfigurationComponents 处理配置。 
4. 如果配置解析失败，收集器的配置可以重新加载。 
5. 如果解析器收到关闭错误，收集器可以关闭。 
6. Run 运行 runAndWaitForShutdownEvent 并等待关闭事件。 
7. SIGINT 和 SIGTERM 信号、错误以及调用 (*Collector).Shutdown 可以触发关闭事件。 
8. 关闭时，首先通知管道，然后关闭管道和扩展。 
9. 用户可以随时调用 (*Collector).Shutdown 来关闭收集器。



# 初始化Collector

Collector的struct定义为

```go
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

NewCollector中会初始化Collector对象以及其中的组件

- 初始化bc、cc等日志logger组件
- 初始化configProvider配置的相关组件





## 配置相关

这里讲一下OTel-collector配置相关的部分

配置是OTel-collector的一个关键特性，OpenTelementry采用了插件化的模式，用户可以自由选择需要的插件，来组成自己的数据采集Pipeline。用户正是通过配置来确定Pipeline的组成和处理流程

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



### Provider

Provider的定义如下所示

```
type Provider interface {
	Retrieve(ctx context.Context, uri string, watcher WatcherFunc) (*Retrieved, error)

	Scheme() string

	Shutdown(ctx context.Context) error
}

type ConfigProvider struct {
	mapResolver *confmap.Resolver
}

type Resolver struct {
	uris          []location
	providers     map[string]Provider
	defaultScheme string
	converters    []Converter

	closers []CloseFunc
	watcher chan error
}
```

ConfigProvider的struct中只包含了一个Resolver，作为配置的实际处理从struct定义中可以看出Resolver支持不同的Provider，这些Provider在main函数中显式定义出来

```
set := otelcol.CollectorSettings{
    BuildInfo: info,
    Factories: components,
    ConfigProviderSettings: otelcol.ConfigProviderSettings{
       ResolverSettings: confmap.ResolverSettings{
          ProviderFactories: []confmap.ProviderFactory{
             envprovider.NewFactory(),
             fileprovider.NewFactory(),
             httpprovider.NewFactory(),
             httpsprovider.NewFactory(),
             yamlprovider.NewFactory(),
          },
       },
    },
    ProviderModules: map[string]string{
       envprovider.NewFactory().Create(confmap.ProviderSettings{}).Scheme():   "go.opentelemetry.io/collector/confmap/provider/envprovider v1.26.0",
       fileprovider.NewFactory().Create(confmap.ProviderSettings{}).Scheme():  "go.opentelemetry.io/collector/confmap/provider/fileprovider v1.26.0",
       httpprovider.NewFactory().Create(confmap.ProviderSettings{}).Scheme():  "go.opentelemetry.io/collector/confmap/provider/httpprovider v1.26.0",
       httpsprovider.NewFactory().Create(confmap.ProviderSettings{}).Scheme(): "go.opentelemetry.io/collector/confmap/provider/httpsprovider v1.26.0",
       yamlprovider.NewFactory().Create(confmap.ProviderSettings{}).Scheme():  "go.opentelemetry.io/collector/confmap/provider/yamlprovider v1.26.0",
    },
    ConverterModules: []string{},
}
```

创建Provider时采用了工厂模式

NewFactory返回了一个Provider 的工厂函数，这里以fileprovider为例来看一下

```
func NewFactory() confmap.ProviderFactory {
    return confmap.NewProviderFactory(newProvider)
}

func newProvider(confmap.ProviderSettings) confmap.Provider {
    return &provider{}
}
```

可以看到newProvider传递了newProvider的函数指针，将T->Provider，s->ProviderSettings

当调用Create时相当于调用了newProvider(ProviderSettings)这里返回了&provider{}也就是fileprovider.provider

```
func NewFactory() confmap.ProviderFactory {
	return confmap.NewProviderFactory(newProvider)
}

func NewProviderFactory(f CreateProviderFunc) ProviderFactory {
	return newConfmapModuleFactory(f)
}

type CreateProviderFunc = createConfmapFunc[Provider, ProviderSettings]

type createConfmapFunc[T any, S any] func(s S) T

func newProvider(ps confmap.ProviderSettings) confmap.Provider {
	return &provider{
		logger: ps.Logger,
	}
}

type confmapModuleFactory[T any, S any] struct {
	f createConfmapFunc[T, S]
}

func (c confmapModuleFactory[T, S]) Create(s S) T {
	return c.f(s)
}
```

provider读取文件是通过provider.Retrieve，fileprovider这里也就是os.ReadFile

```
func (fmp *provider) Retrieve(_ context.Context, uri string, _ confmap.WatcherFunc) (*confmap.Retrieved, error) {
    if !strings.HasPrefix(uri, schemeName+":") {
       return nil, fmt.Errorf("%q uri is not supported by %q provider", uri, schemeName)
    }

    // Clean the path before using it.
    content, err := os.ReadFile(filepath.Clean(uri[len(schemeName)+1:]))
    if err != nil {
       return nil, fmt.Errorf("unable to read the file %v: %w", uri, err)
    }

    return confmap.NewRetrievedFromYAML(content)
}
```



### 配置热更新

OTel配置的一大特点就是支持配置热更新，修改配置不需要重启整个服务。在启动后，Provider会监听resolver.watcher这个chan，如果发现配置发生变更，就会通过这个chan发出通知。这里的watcher在Collector框架中并没有实现，用户需要自行实现通知watcher的逻辑

```
func (cm *ConfigProvider) Watch() <-chan error {
    return cm.mapResolver.Watch()
}

func (mr *Resolver) Watch() <-chan error {
	return mr.watcher
}
```

在主循环中，watcher这个chan被触发时，会调用reloadConfiguration重新加载配置

```
case err := <-col.configProvider.Watch():
    if err != nil {
       col.service.Logger().Error("Config watch failed", zap.Error(err))
       break LOOP
    }
    if err = col.reloadConfiguration(ctx); err != nil {
       return err
    }
```

实质上是暂停所有服务，并重新启动

```

func (col *Collector) reloadConfiguration(ctx context.Context) error {
    col.service.Logger().Warn("Config updated, restart service")
    col.setCollectorState(StateClosing)

    if err := col.service.Shutdown(ctx); err != nil {
       return fmt.Errorf("failed to shutdown the retiring config: %w", err)
    }

    if err := col.setupConfigurationComponents(ctx); err != nil {
       return fmt.Errorf("failed to setup configuration components: %w", err)
    }

    return nil
}
```





9. 

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

## setupConfigurationComponents

```
factories, err := col.set.Factories()

cfg, err := col.configProvider.Get(ctx, factories)
err = xconfmap.Validate(cfg)
err = conf.Marshal(cfg)

col.service, err = service.New(ctx, service.Settings{
		BuildInfo:     col.set.BuildInfo,
		CollectorConf: conf,

		ReceiversConfigs:    cfg.Receivers,
		ReceiversFactories:  factories.Receivers,
		ProcessorsConfigs:   cfg.Processors,
		ProcessorsFactories: factories.Processors,
		ExportersConfigs:    cfg.Exporters,
		ExportersFactories:  factories.Exporters,
		ConnectorsConfigs:   cfg.Connectors,
		ConnectorsFactories: factories.Connectors,
		ExtensionsConfigs:   cfg.Extensions,
		ExtensionsFactories: factories.Extensions,

		ModuleInfos: service.ModuleInfos{
			Receiver:  buildModuleInfo(factories.ReceiverModules),
			Processor: buildModuleInfo(factories.ProcessorModules),
			Exporter:  buildModuleInfo(factories.ExporterModules),
			Extension: buildModuleInfo(factories.ExtensionModules),
			Connector: buildModuleInfo(factories.ConnectorModules),
		},
		AsyncErrorChannel: col.asyncErrorChannel,
		LoggingOptions:    col.set.LoggingOptions,
	}, cfg.Service)
	
if err = col.service.Start(ctx)
```

### service.new

```
New 
|- srv := &Service{ host: &graph.Host{
|  |- Receivers:  builders.NewReceiver
|  |-	Processors: builders.NewProcessor
|  |-	Exporters:  builders.NewExporter
|  |-	Connectors: builders.NewConnector
|  |-	Extensions: builders.NewExtension
|- }}
|- srv.initGraph(ctx, cfg) -> graph.Build(ctx, graph.Settings{...}) 
|  |- pipelines.createNodes(set); // 通过配置生成Receivers、Processors、Exporters，特殊处理创建connector
|  |  |- for pipelineID, pipelineCfg in set.PipelineConfigs
|  |  |  |- for recvID in pipelineCfg.Receivers
|  |  |  |  |- // 判断是否使用了connector
|  |  |  |  |- rcvrNode := g.createReceiver(pipelineID, recvID)
|  |  |  |  |- pipe.receivers[rcvrNode.ID()] = rcvrNode
|  |  |  |- pipe.capabilitiesNode = newCapabilitiesNode(pipelineID)
|  |  |  |- for procID in pipelineCfg.Processors
|  |  |  |  |- procNode := g.createProcessor(pipelineID, procID)
|  |  |  |  |- pipe.processors = append(pipe.processors, procNode)
|  |  |  |- pipe.fanOutNode = newFanOutNode(pipelineID)
|  |  |  |- for exprID in pipelineCfg.Exporters 
|  |  |  |  |- // 判断是否使用了connector
|  |  |  |  |- expNode := g.createExporter(pipelineID, exprID)
|  |  |  |  |- pipe.exporters[expNode.ID()] = expNode

|  |  |- for connID in connectors // 创建connector
|  |  |  |- factory := set.ConnectorBuilder.Factory(connID.Type())
|  |  |  |- for eID in connectorsAsExporter[connID]
|  |  |  |  |- for rID in connectorsAsReceiver[connID]
|  |  |  |  |  |- connNode := g.createConnector(eID, rID, connID)
|  |  |  |  |  |- g.pipelines[eID].exporters[connNode.ID()] = connNode
|  |  |  |  |  |- g.pipelines[rID].receivers[connNode.ID()] = connNode

|  |- pipelines.createEdges() // 在Pipeline中生成Edge，形成DAG
|  |- pipelines.buildComponents(ctx, set) // 实例化Pipeline中的实际组件，调用组件的工厂方法
|  |  |- n.buildComponent(ctx, set.Telemetry, set.BuildInfo, set.ReceiverBuilder, g.nextConsumers(n.ID()))
|  |  |- 处理capabilitiesNode
|  |  |- 处理fanOutNode

|- srv.initExtensions(ctx, cfg.Extensions) -> extensions.New
|  |- for extID in cfg
|  |  |- set.Extensions.Create(ctx, extSet)
|  |- order, err := computeOrder(exts)
```

graph.Build是构建OTel-Collector**数据流水线拓扑结构**的核心，主要负责解析配置文件中的接收器（Receivers）、处理器（Processors）、导出器（Exporters）和连接器（Connectors），并建立它们之间的逻辑关系，最终生成可执行的 **有向无环图（DAG）**

graph的定义如下

```
type Graph struct {
    // All component instances represented as nodes, with directed edges indicating data flow.
    componentGraph *simple.DirectedGraph

    // Keep track of how nodes relate to pipelines, so we can declare edges in the graph.
    pipelines map[pipeline.ID]*pipelineNodes

    // Keep track of status source per node
    instanceIDs map[int64]*componentstatus.InstanceID

    telemetry component.TelemetrySettings
}
```



# service.Start

调用栈

```
Start
|- srv.host.ServiceExtensions.Start(ctx, srv.host)
|- if srv.collectorConf != nil
|  |- srv.host.ServiceExtensions.NotifyConfig
|- srv.host.Pipelines.StartAll(ctx, srv.host)
|  |- for i := reversed(nodes)
|  |  |- comp.Start
|- srv.host.ServiceExtensions.NotifyPipelineReady()
```

这里是采集服务最终启动的位置



1. 首先启动Extension，Extension可以理解为一种扩展机制，拥有很高的自由度。
2. 之后就是启动所有的Pipelines
3. 之后通知Pipeline，Extension已经Ready

```
func (srv *Service) Start(ctx context.Context) error {
    srv.telemetrySettings.Logger.Info("Starting "+srv.buildInfo.Command+"...",
       zap.String("Version", srv.buildInfo.Version),
       zap.Int("NumCPU", runtime.NumCPU()),
    )

    if err := srv.host.ServiceExtensions.Start(ctx, srv.host); err != nil {
       return fmt.Errorf("failed to start extensions: %w", err)
    }

    if srv.collectorConf != nil {
       if err := srv.host.ServiceExtensions.NotifyConfig(ctx, srv.collectorConf); err != nil {
          return err
       }
    }

    if err := srv.host.Pipelines.StartAll(ctx, srv.host); err != nil {
       return fmt.Errorf("cannot start pipelines: %w", err)
    }

    if err := srv.host.ServiceExtensions.NotifyPipelineReady(); err != nil {
       return err
    }

    srv.telemetrySettings.Logger.Info("Everything is ready. Begin running and processing data.")
    return nil
}
```

