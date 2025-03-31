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



这里的节点是实际上暴露给用户的，实际是Pipeline中还包括一些隐藏节点

​                                                      extension

receiver -> capabilitiesNode -> processor -> exporter -> fanOutNode

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



# capabilitiesNode

每条管道在receiver之后都有一个“虚拟”能力节点，为每条管道提供一个一致的“第一个消费者”

使用了next初始化，等效于直接调用next

```
case *capabilitiesNode:
    capability := consumer.Capabilities{
       // The fanOutNode represents the aggregate capabilities of the exporters in the pipeline.
       MutatesData: g.pipelines[n.pipelineID].fanOutNode.getConsumer().Capabilities().MutatesData,
    }
    for _, proc := range g.pipelines[n.pipelineID].processors {
       capability.MutatesData = capability.MutatesData || proc.(*processorNode).getConsumer().Capabilities().MutatesData
    }
    next := g.nextConsumers(n.ID())[0]
    switch n.pipelineID.Signal() {
    case pipeline.SignalTraces:
       cc := capabilityconsumer.NewTraces(next.(consumer.Traces), capability)
       n.baseConsumer = cc
       n.ConsumeTracesFunc = cc.ConsumeTraces
    case pipeline.SignalMetrics:
       cc := capabilityconsumer.NewMetrics(next.(consumer.Metrics), capability)
       n.baseConsumer = cc
       n.ConsumeMetricsFunc = cc.ConsumeMetrics
    case pipeline.SignalLogs:
       cc := capabilityconsumer.NewLogs(next.(consumer.Logs), capability)
       n.baseConsumer = cc
       n.ConsumeLogsFunc = cc.ConsumeLogs
    case xpipeline.SignalProfiles:
       cc := capabilityconsumer.NewProfiles(next.(xconsumer.Profiles), capability)
       n.baseConsumer = cc
       n.ConsumeProfilesFunc = cc.ConsumeProfiles
    }
```



# fanOutNode

在processor和Exporter之间，由于一个pipeline可以有多个Exporter，所以fanoutNode就是用于处理分发的情况

New时，接收了所有的nextConsumer，把它们分为修改了数据和只读的情况

```
func NewLogs(lcs []consumer.Logs) consumer.Logs {
    // Don't wrap if there is only one non-mutating consumer.
    if len(lcs) == 1 && !lcs[0].Capabilities().MutatesData {
       return lcs[0]
    }

    lc := &logsConsumer{}
    for i := 0; i < len(lcs); i++ {
       if lcs[i].Capabilities().MutatesData {
          lc.mutable = append(lc.mutable, lcs[i])
       } else {
          lc.readonly = append(lc.readonly, lcs[i])
       }
    }
```

之后就是确定是否clone还是直接传输原始的数据

```
if len(lsc.mutable) > 0 {
  // Clone the data before sending to all mutating consumers except the last one.
  for i := 0; i < len(lsc.mutable)-1; i++ {
    errs = multierr.Append(errs, lsc.mutable[i].ConsumeLogs(ctx, cloneLogs(ld)))
  }
  // Send data as is to the last mutating consumer only if there are no other non-mutating consumers and the
  // data is mutable. Never share the same data between a mutating and a non-mutating consumer since the
  // non-mutating consumer may process data async and the mutating consumer may change the data before that.
  lastConsumer := lsc.mutable[len(lsc.mutable)-1]
  if len(lsc.readonly) == 0 && !ld.IsReadOnly() {
    errs = multierr.Append(errs, lastConsumer.ConsumeLogs(ctx, ld))
  } else {
    errs = multierr.Append(errs, lastConsumer.ConsumeLogs(ctx, cloneLogs(ld)))
  }
}

// Mark the data as read-only if it will be sent to more than one read-only consumer.
if len(lsc.readonly) > 1 && !ld.IsReadOnly() {
  ld.MarkReadOnly()
}
for _, lc := range lsc.readonly {
  errs = multierr.Append(errs, lc.ConsumeLogs(ctx, ld))
}
```



# 失败重试

exporter的对象可能数据库等，有可能存在问题导致某次发送请求失败，这是就需要一个失败重试机制来兜底，尤其是一些重要的数据，例如日志等。

每个Exporter都继承自baseExporter，重试机制就在这里。开启重试的话baseExporter的firstSender就会设置为RetrySender，由RetrySender通过重试机制调用具体的firstSender

```
if be.retryCfg.Enabled {
    be.RetrySender = newRetrySender(be.retryCfg, set, be.firstSender)
    be.firstSender = be.RetrySender
}
```

处理流程：

1. ##### Backoff**策略初始化**

2. 主循环调用rs.next.Send(ctx, req)，分析Err，下面的情况会抛出错误

   - `err == nil` 时直接返回
   - `consumererror.IsPermanent(err)` 识别（如4xx客户端错误）->不可重试错误直接抛出
   -  `backoff.NextBackOff() == backoff.Stop`（间隔超过`MaxInterval`或被封顶）-> 抛出
   - `maxElapsedTime`全局时间窗口过期
   - 监听`ctx.Done()`信号
   - 监听`rs.stopCh`（优雅关闭场景）

3. 没有无法重复的错误，重复主循环

```
func (rs *retrySender) Send(ctx context.Context, req request.Request) error {
    // Do not use NewExponentialBackOff since it calls Reset and the code here must
    // call Reset after changing the InitialInterval (this saves an unnecessary call to Now).
    expBackoff := backoff.ExponentialBackOff{
       InitialInterval:     rs.cfg.InitialInterval,
       RandomizationFactor: rs.cfg.RandomizationFactor,
       Multiplier:          rs.cfg.Multiplier,
       MaxInterval:         rs.cfg.MaxInterval,
    }
    span := trace.SpanFromContext(ctx)
    retryNum := int64(0)
    var maxElapsedTime time.Time
    if rs.cfg.MaxElapsedTime > 0 {
       maxElapsedTime = time.Now().Add(rs.cfg.MaxElapsedTime)
    }
    for {
       span.AddEvent(
          "Sending request.",
          trace.WithAttributes(attribute.Int64("retry_num", retryNum)))

       err := rs.next.Send(ctx, req)
       if err == nil {
          return nil
       }

       // Immediately drop data on permanent errors.
       if consumererror.IsPermanent(err) {
          return fmt.Errorf("not retryable error: %w", err)
       }

       if errReq, ok := req.(request.ErrorHandler); ok {
          req = errReq.OnError(err)
       }

       backoffDelay := expBackoff.NextBackOff()
       if backoffDelay == backoff.Stop {
          return fmt.Errorf("no more retries left: %w", err)
       }

       throttleErr := throttleRetry{}
       if errors.As(err, &throttleErr) {
          backoffDelay = max(backoffDelay, throttleErr.delay)
       }

       nextRetryTime := time.Now().Add(backoffDelay)
       if !maxElapsedTime.IsZero() && maxElapsedTime.Before(nextRetryTime) {
          // The delay is longer than the maxElapsedTime.
          return fmt.Errorf("no more retries left: %w", err)
       }

       if deadline, has := ctx.Deadline(); has && deadline.Before(nextRetryTime) {
          // The delay is longer than the deadline.  There is no point in
          // waiting for cancelation.
          return fmt.Errorf("request will be cancelled before next retry: %w", err)
       }

       backoffDelayStr := backoffDelay.String()
       span.AddEvent(
          "Exporting failed. Will retry the request after interval.",
          trace.WithAttributes(
             attribute.String("interval", backoffDelayStr),
             attribute.String("error", err.Error())))
       rs.logger.Info(
          "Exporting failed. Will retry the request after interval.",
          zap.Error(err),
          zap.String("interval", backoffDelayStr),
       )
       retryNum++

       // back-off, but get interrupted when shutting down or request is cancelled or timed out.
       select {
       case <-ctx.Done():
          return fmt.Errorf("request is cancelled or timed out: %w", err)
       case <-rs.stopCh:
          return experr.NewShutdownErr(err)
       case <-time.After(backoffDelay):
       }
    }
}
```
