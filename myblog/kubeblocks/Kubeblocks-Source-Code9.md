---
title: KubeBlocks源码笔记九--Sharding
date: 2025-03-05
update: 2025-03-05
comment: false
tags:
  - kubeblocks
categories:
  - kubeblocks
---

很多的数据库都是支持Sharding的，Kubeblocks也提供了Sharding的支持，简单来说一个Sharding就是一个Component，通过这样的方式来实现Sharding

*<!--more-->*

这里以Redis Cluster来介绍Kubeblocks对于Sharding的支持

首先看一个Redis的案例，cluster中的字段为shardingSpecs：

该cluster会创建一个3 Sharding 的Redis集群每个Sharding包含主备两个Redis实例

Sharding模版和普通cluster中的**componentSpecs**一致，指向的redis-cluster-7就是一个正常的Redis主备逻辑的CMPD，并做了一些Sharding的配置

这里相当于用多个Component来表示Sharding







