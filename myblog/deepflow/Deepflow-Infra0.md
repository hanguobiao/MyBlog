---
title: Deepflow数据采集流
date: 2025-03-30
update: 2025-03-30
comment: false
tags:
  - Deepflow
  - BPF
categories:
  - Deepflow
---

简单记录一下Deepflow Agent的采集流程的数据流

*<!--more-->*

# 架构

![img](https://myblog-1307634347.cos.ap-guangzhou.myqcloud.com/blog/v2-8ff49324100985a093fb0f1d0939beb5_1440w.jpg)

a)程序信息，如进程ID、线程ID、协程ID、进程名

b)网络信息，如全局socket id、五元组、TCP Sequence（代表已发送字节数）

c)Tracing信息，如timestamp，ingress/egress 方向

d)系统调用信息，如读/写数据长度、传给deepflow agent的payload等

a)cBPF用于记录网络流量

b)uprobe记录用户空间数据，如TLS加密前流量

c)其它监控系统数据，如OpenTelemetry



# 数据采集

```mermaid
flowchart LR

Dispatcher -->|MetaPacket| FlowGenerator
FlowGenerator -->|MetaPacket| FlowMap[(FlowMap)]
FlowGenerator -->|"TaggedFlow (1s)"| queue.1([queue])
queue.1 --> QuadrupleGenerator
QuadrupleGenerator --> SubQuadGen.1["SubQuadGen (1s)"]
SubQuadGen.1 -->|"AccumulatedFlow (1s)"| QuadrupleStash.1[("QuadrupleStash (1s)")]
SubQuadGen.1 -->|QuadrupleConnections| ConcurrentConnection.1[("ConcurrentConnection (1s)")]
SubQuadGen.1 -->|"AccumulatedFlow (1s)"| queue.2([queue]) --> Collector.1[Collector] -->|"Metrics(Document)"| queue.3([queue]) --> UniformSender.1[UniformSender]
QuadrupleGenerator --> SubQuadGen.2["SubQuadGen (1m)"]
SubQuadGen.2 -->|"AccumulatedFlow (1m)"| QuadrupleStash.2[("QuadrupleStash (1m)")]
SubQuadGen.2 -->|QuadrupleConnections| ConcurrentConnection.2[("ConcurrentConnection (1m)")]
SubQuadGen.2 -->|"AccumulatedFlow (1m)"| queue.4([queue]) --> Collector.2[Collector] -->|"Metrics(Document)"| queue.5([queue]) --> UniformSender.1
QuadrupleGenerator --> queue.6([queue]) --> FlowAggr -->|"TaggedFlow (1m)"| throttler -->|"L4FlowLog(TaggedFlow)"| queue.7([queue]) --> UniformSender.2[UniformSender]
queue.1 --> L7QuadrupleGenerator
L7QuadrupleGenerator --> SubQuadGen.1["SubQuadGen (1s)"]
SubQuadGen.1 -->|"AppMeterWithFlow (1s)"| queue.2([queue])
L7QuadrupleGenerator --> SubQuadGen.2["SubQuadGen (1m)"]
SubQuadGen.2 -->|"AppMeterWithFlow (1m)"| queue.4([queue])

FlowGenerator -->|MetaAppProto| queue.8([queue]) --> AppProtoLogsParser -->|AppProtoLogsData| throttler.1[throttler] -->|"L7FlowLog(AppProtoLogsData)"| queue.9([queue]) --> UniformSender.3[UniformSender]

EbpfCollector -->|MetaPacket| queue.10([queue]) --> EbpfRunner -->|AppProtoLogsData| SessionAggr --> throttler.2[throttler] -->|"L7FlowLog(AppProtoLogsData)"| queue.9
EbpfCollector -->|stack_profile_data| ebpf_on_cpu_callback -->|"Profile"| queue.9
```

# Dispatcher

是核心采集器，Deepflow通过AF_PACKET/cBPF采集到原始的数据包

1. BaseDispatcher::recv()接收包
2. 缓存到vec，最多64个包
3. 达到容量触发发送，批量发送到"dispatcher-packet-to-flow-generator"线程，循环做如下操作
   1. Decap tunnel
   2. Lookup l2end
   3. Generate MetaPacket
   4. Generate tagged flow，通过调用 flow_map.inject_meta_packet(&config, &mut meta_packet)实现
4. 进入flow generator



## packet处理



# flow generator

这里对采集的的数据包进行聚合生成tagged_flow，解析生成l7 perf、AppLog等

1. 数据包解析，提取各层协议的信息
2. 使用（源IP地址、目的IP、源端口、目的端口、协议）来定义和识别流
3. 将属于同一流的数据包进行聚合

4. 这里会调用plugin来对用户层协议进行解析比如mysqlLog



# QuadrupleGenerator

生成秒级flow meter、汇聚成分钟级meter、发送至deepflow server数据平面。共四个线程:

1.quadruple_generator: QuadrupleGeneratorThread=>生成秒级flow meter
2.l4_flow_aggr: Option<FlowAggrThread>=>秒级flow meter汇聚成minute meter
3.second_collector: Option<Collector>=>秒级meter收集，并发送至deepflow server数据平面
4.minute_collector: Option<Collector>=》分钟级meter收集，并发送至deepflow server数据平面





# EbpfCollector

采集socket的追踪

采集tls

采集SSL


Reference: https://zhuanlan.zhihu.com/p/713489970