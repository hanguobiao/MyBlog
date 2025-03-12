---
title: (转+译)Cilium Code Walk Through
date: 2025-02-27
update: 2025-02-28
comment: false
tags:
  - Cilium
categories:
  - Cilium
---

使用 Cilium 时，总是想要深入代码，但是Cilium的实现方式比较难以理解，尤其是我这样之前对于网络并没过多了解，这时遇到了大神Arthur的Cilium源码系列，获益匪浅。出于学习和整理目的，翻译为中文，并根据1.16版本对一些内容进行修改，目前仅供自己使用。之后有计划按照自己的理解重新写一半加深理解

Reference：https://arthurchiao.art/blog/cilium-code-series/

*<!--more-->*

