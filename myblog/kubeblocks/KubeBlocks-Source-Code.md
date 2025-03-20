---
title: KubeBlocks源码笔记系列
date: 2025-03-05
update: 2025-03-05
comment: false
tags:
  - kubeblocks
categories:
  - kubeblocks
---

在 Kubernetes 上运行无状态应用早已成为标准实践，但当我们将目光投向数据库（MySQL/PostgreSQL）等有状态工作负载时，往往会面临各种各样的挑战。KubeBlocks正是为此而诞生的。KubeBlocks作为有状态应用部署以及Operator开发的头部玩家，其代码有较高的参考价值，这里就从源码角度一探究竟

*<!--more-->*

一、部署与启动 [Kubeblocks源码笔记一--部署与启动](http://123.60.75.117/2025/03/05/Kubeblocks%E6%BA%90%E7%A0%81%E7%AC%94%E8%AE%B0%E4%B8%80--%E9%83%A8%E7%BD%B2%E4%B8%8E%E5%90%AF%E5%8A%A8/)

二、Transformer机制 [Kubeblocks源码笔记二--Transformer机制](http://123.60.75.117/2025/03/05/Kubeblocks%E6%BA%90%E7%A0%81%E7%AC%94%E8%AE%B0%E4%BA%8C--Transformer/)

三、Component [Kubeblocks源码笔记三--Component](http://123.60.75.117/2025/03/05/Kubeblocks%E6%BA%90%E7%A0%81%E7%AC%94%E8%AE%B0%E4%B8%89--Component/)

四、Workload [Kubeblocks源码笔记四--Workload](http://123.60.75.117/2025/03/05/Kubeblocks%E6%BA%90%E7%A0%81%E7%AC%94%E8%AE%B0%E5%9B%9B--workload/)

五、kbagent [Kubeblocks源码笔记五--kbagent](http://123.60.75.117/2025/03/05/Kubeblocks%E6%BA%90%E7%A0%81%E7%AC%94%E8%AE%B0%E4%BA%94--KBAgent/)

六、配置 [Kubeblocks源码笔记六--配置](http://123.60.75.117/2025/03/05/Kubeblocks%E6%BA%90%E7%A0%81%E7%AC%94%E8%AE%B0%E5%85%AD--%E9%85%8D%E7%BD%AE/)

七、备份恢复 [Kubeblocks源码笔记七--备份恢复](http://123.60.75.117/2025/03/05/Kubeblocks%E6%BA%90%E7%A0%81%E7%AC%94%E8%AE%B0%E4%B8%83--%E5%A4%87%E4%BB%BD%E6%81%A2%E5%A4%8D/)

八、Event消息传递（WIP） [Kubeblocks源码笔记八--Event](http://123.60.75.117/2025/03/05/Kubeblocks%E6%BA%90%E7%A0%81%E7%AC%94%E8%AE%B0%E5%85%AB--Event/)

九、Sharding [Kubeblocks源码笔记九--Sharding](http://123.60.75.117/2025/03/05/Kubeblocks%E6%BA%90%E7%A0%81%E7%AC%94%E8%AE%B0%E4%B9%9D--Sharding/)