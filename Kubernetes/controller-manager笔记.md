Controller Manager

Controller-manager是一个deamonset， 主要负责k8s集群各种资源的控制，node、Pod、Sts等。在自动化的概念中，控制环路是调节系统状态的非终止环路。在 Kubernetes 中，Controller是一个控制循环，它通过 apiserver 监视集群的共享状态，并进行更改，尝试将当前状态移动到所需状态。目前随 Kubernetes 一起提供的控制器示例包括

replication controller, endpoints controller, namespace controller, and serviceaccounts controller.

# 源码笔记

**Kubernetes Version: 1.31**

# 整体实现

# NewControllerManagerCommand()

options.NewKubeControllerManagerOptions(): 对所有内置控制器以及全局配置进行初始化

KnownControllers(): 获取内置Controller，这些内置的控制器定义在`cmd/kube-controller-manager/app/`目录下

s.Config(KnownControllers()......) : 生成控制器管理配置项，获取与集群通讯所必须的基本信息(kubeconfig、clientset、event)。

# Run(): 是Controller-manager的核心

EventBroadcaster？？？

CreateControllerContext： 创建控制器 的上下文配置，用来在每个控制器执行时提供公共配置。StartControllers(): 启动所有的Controller

StartControllers(): 

遍历控制器

controllerDescriptor.GetInitFunc()执行控制器，传递 controllerCtx 上下文配置

# 具体的Controller

以statefulset-controller为例

![img](C:\Users\Administrator\Desktop\读书笔记\Kubernetes读书笔记\assets\1727000381733-1.png)

go statefulset.NewStatefulSetController().Run():

For int worker

->go wait.UntilWithContext(ctx, ssc.worker, time.*Second*)

ssc.work-> for ssc.processNextWorkItem(ctx) -> ssc.sync 

## sync()

set, err := ssc.setLister.StatefulSets(namespace).Get(name)

pods, err := ssc.getPodsForStatefulSet(ctx, set, selector)

ssc.syncStatefulSet()

processNextWorkItem() -> 