---
title: Cilium Code Walk Through 1.2 - Hive?
date: 2025-02-27
update: 2025-02-28
comment: false
tags:
  - Cilium
categories:
  - Cilium
---

Cilium在1.13版本开始采用Hive的方式进行初始化，这里就根据官方文档来学习一下Hive的初始化逻辑

Reference: https://docs.cilium.io/en/stable/contributing/development/hive

*<!--more-->*
# Guide to the Hive

Cilium 使用依赖注入（通过 `pkg/hive`）来连接其组件的初始化、启动和停止。

依赖注入（DI）是一种将对象的使用与其创建和初始化分离的技术。本质上，依赖注入是通过自动化的方式管理之前手工处理依赖关系的过程。对象的构造函数只需要将依赖项声明为函数参数，其余的工作由库来完成。这有助于构建一个松耦合的模块化架构，因为它消除了初始化和配置的集中化需求。它还减少了使用全局变量而不是显式传递对象的倾向，这通常是错误的来源（由于意外的初始化顺序），并且在测试中难以处理（因为需要为下一个测试恢复状态）。通过依赖注入，组件被描述为普通值（在我们的依赖注入风格中是“Cell”），这使得组件间依赖关系的可视化成为可能，并为内部架构的检查敞开了大门。

