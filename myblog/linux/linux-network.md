---
title: (转)linux网络栈收包流程
date: 2025-03-20
update: 2025-03-21
comment: false
tags:
  - linux
categories:
  - linux
  - network
---

这里探究一下linux网络模块接收数据包的流程，核心流程参考了https://arthurchiao.art/blog/linux-net-stack-implementation-rx-zh/
添加了一些《深入linux内核架构》的内容，目前以自用为主

*<!--more-->*



# 收包流程

![img](https://myblog-1307634347.cos.ap-guangzhou.myqcloud.com/blog/rx-overview.png)

1. 内核：初始化网卡驱动；其中包括了注册 `poll()` 方法；
2. 网卡：收到包；
3. 网卡：通过 DMA 将包复制到内核内存中的 **ring buffer**；
4. 网卡：如果此时 NAPI 没有在执行，就产生硬件中断（IRQ），通知系统收到了一个包（否则不用额外 IRQ 就会把包收走）；触发软中断；
5. 内核：调度到软中断处理线程 `ksoftirqd`；
6. 内核：软中断处理，调用 NAPI 的 `poll()` 从 ring buffer 收包，并以 `skb` 的形式送至更上层处理；
7. 协议栈：L2 处理；
8. 协议栈：L3 处理；
9. 协议栈：L4 处理。

# 0 驱动注册

## 初始化硬中断（IRQ）

## 注册中断处理函数

## 注册网络设备

- 根据给定的网络 profile，创建一个内核 netdev 设备；
- 注册 ethtool 方法
- 注册 RX/TX 队列初始化方法，并执行初始化
- 注册 NAPI poll 方法
- 初始化硬件中断等

#### 注册netdev

mlx5e_create_netdev()`：创建 netdev、注册 `ethtool` 方法

net_device结构包含了与特定设备相关的所有信息。该结构的定义有200多行代码，是内核中 最庞大的结构。

```
struct net_device 
{ 
    char name[IFNAMSIZ]; 
    /* 设备名散列链表的链表元素 */ 
    struct hlist_node name_hlist; 
    /* I/O相关字段 */ 
    unsigned long mem_end; /* 共享内存结束位置 */ 
    unsigned long mem_start; /* 共享内存起始位置 */ 
    unsigned long base_addr; /* 设备I/O地址 */ 
    unsigned int irq; /* 设备IRQ编号 */ 
    unsigned long state; 
    struct list_head dev_list; 
    int (*init)(struct net_device *dev); 
    /* 接口索引。唯一的设备标识符*/ 
     int ifindex; 
    struct net_device_stats* (*get_stats)(struct net_device *dev); 
    /* 硬件首部描述 */ 
    const struct header_ops *header_ops; 
    unsigned short flags; /* 接口标志（按BSD方式） */ 
    unsigned mtu; /* 接口MTU值 */ 
    unsigned short type; /* 接口硬件类型 */ 
    unsigned short hard_header_len; /* 硬件首部长度 */ 
    /* 接口地址信息。 */ 
    unsigned char perm_addr[MAX_ADDR_LEN]; /* 持久硬件地址 */ 
    unsigned char addr_len; /* 硬件地址长度 */ 
     int promiscuity; 
    /* 协议相关指针 */ 
     void *atalk_ptr; /* AppleTalk相关指针 */ 
    void *ip_ptr; /* IPv4相关数据 */ 
    void *dn_ptr; /* DECnet相关数据 */ 
    void *ip6_ptr; /* IPv6相关数据 */ 
    void *ec_ptr; /* Econet相关数据 */ 
    unsigned long last_rx; /* 上一次接收操作的时间 */ 
    unsigned long trans_start; /* 上一次发送操作的时间（以jiffies为单位）*/ 
     /* eth_type_trans()所用的接口地址信息 */ 
    unsigned char dev_addr[MAX_ADDR_LEN]; /* 硬件地址，（在bcast成员之前，
    因为大多数分组都是单播） */ 
    unsigned char broadcast[MAX_ADDR_LEN]; /* 硬件多播地址 */ 
    int (*hard_start_xmit) (struct sk_buff *skb, 
     struct net_device *dev); 
     /* 在设备与网络断开后调用*/ 
    void (*uninit)(struct net_device *dev); 
     /* 在最后一个用户引用消失后调用*/ 
    void (*destructor)(struct net_device *dev); 
     /* 指向接口服务例程的指针 */ 
    int (*open)(struct net_device *dev); 
    int (*stop)(struct net_device *dev); 
    void (*set_multicast_list)(struct net_device *dev); 
    int (*set_mac_address)(struct net_device *dev, 
     void *addr); 
    int (*do_ioctl)(struct net_device *dev, 
     struct ifreq *ifr, int cmd); 
    int (*set_config)(struct net_device *dev, 
     struct ifmap *map); 
    int (*change_mtu)(struct net_device *dev, int new_mtu); 
    void (*tx_timeout) (struct net_device *dev); 
     int (*neigh_setup)(struct net_device *dev, struct neigh_parms *); 
     /* 该设备所在的网络命名空间 */ 
    struct net *nd_net; 
     /* class/net/name项 */ 
    struct device dev;
    ......
```

函数调用为

![image-20250321122302447](https://myblog-1307634347.cos.ap-guangzhou.myqcloud.com/blog/image-20250321122302447.png)

RX 队列及 RX handlers 初始化：大部分网卡都使用 DMA 将数据直接写到内存，接下来操作系统可以直接从里 面读取。实现这一目的所使用的数据结构就是 **ring buffer**（环形缓冲区）。 要实现这一功能，设备驱动必须和操作系统合作，**预留（reserve）出一段内存来给网卡使用**。 

启用网卡，注册 NAPI poll 方法

启用硬中断，等待数据包进来



# 1 网卡收包



# 2 DMA 将包复制到 RX 队列 (ring buffer)

## 第一次数据复制

在包从网卡到达应用层的过程中，会经历几次数据复制，这个对性能影响非常大，所以我们记录一下：

第一次是将包**从网卡通过 DMA 复制到 ring buffer**（下图左侧部分）；

![img](https://myblog-1307634347.cos.ap-guangzhou.myqcloud.com/blog/dma-ringbuffer.png)

## 3.2 下一步：更上层来收包

![img](https://myblog-1307634347.cos.ap-guangzhou.myqcloud.com/blog/dp-highlight-driver-poll-20250321122855213.png)



**如果驱动支持 XDP，那 XDP 程序将在 poll 机制内执行**。如果不支持，那 XDP 程序将只能**在更后面执行**（run significantly upstack，见 Step 6），性能会变差， 因此确定你使用的网卡是否支持 XDP 非常重要。

### NAPI 机制（轮询+中断）

![img](https://myblog-1307634347.cos.ap-guangzhou.myqcloud.com/blog/irq-and-napi-poll.png)

- 每次执行到 NAPI poll() 方法时，也就是会执行到网卡注册的 poll() 方法时，会批量从 ring buffer 收包；

  在这个 poll 工作时，会尽量把所有待收的包都收完（budget 可以配置和调优）；在此期间内新到达网卡的包，也不会再触发 IRQ；

- 不在这个调度周期内，收到的包会触发 IRQ，然后内核来启动 poll() 再收包；

  此外还有 IRQ 合并技术，用于减少 IRQ 数量，提升整体吞吐。

假如此时 NAPI poll() 没有正在运行， 接下来我们看通过 IRQ 来通知 CPU（图中第 4 步）从 ring buffer 收包的



# 3 触发硬件中断（IRQ）



# 4 内核调度到 `ksoftirqd` 线程

内核的**软中断系统**是一种**在硬中断处理上下文（驱动中）之外执行代码**的机制。

1. **可以把软中断系统想象成一系列内核线程**（每个 CPU 一个）， 这些线程执行针对不同事件注册的处理函数（handler）。

   如果用过 `top` 命令，可能会注意到 **`ksoftirqd/0`** 这个内核线程，其表示这个软中断线程跑在 CPU 0 上。

2. 内核子系统（比如网络）能通过 `open_softirq()` 注册软中断处理函数。

每个 CPU 上的调度器会调度执行不同的线程，例如处理 OOM 的线程、处理 swap 的线程，以及 我们的软中断处理线程。每个线程分配一定的时间片：

![img](https://myblog-1307634347.cos.ap-guangzhou.myqcloud.com/blog/cpu-schedule-threads.png)

1. **关闭所在 CPU 的所有硬中断**；
2. 判断如果有 pending softirq，则 执行 `__do_softirq()` 处理软中断，然后重新打开所在 CPU 的硬中断，然后返回；
3. 否则直接打开所在 CPU 的硬中断

![img](https://myblog-1307634347.cos.ap-guangzhou.myqcloud.com/blog/run_ksoftirqd.png)

# 5 软中断处理：从 ringbuffer 取数据送到协议栈

软中断线程 `ksoftirqd` 被处理器调度执行之后，会调用 `net_rx_action()` 方法。 这个函数的功能是 ring buffer 取出数据包，然后对其进行进入协议栈之前的大量处理。

Ring buffer 是内核内存，其中存放的包是网卡通过 DMA 直接送过来的， `net_rx_action()` 从处理 ring buffer 开始处理。

![image-20250321122440261](https://myblog-1307634347.cos.ap-guangzhou.myqcloud.com/blog/image-20250321122440261.png)

在给定的预算范围内，函数遍历当前 CPU 队列的 NAPI 变量列表，依次执行其 poll 方法。

1. `list_empty(&list) == true`：说明 list 已经为空，没有 NAPI 需要 poll 了（这个 list 是怎么初始化和更新的，需要好好研究）；
2. `budget <= 0`：说明收包的数量已经 >= netdev_budget（例如 2400 个，默认是 300）， 或者
3. `time_after_eq(jiffies, time_limit) == true`：说明累计运行时间已经 >= netdev_budget_us（例如 8ms，默认是 2ms）

## `skb = mlx5e_skb_from_cqe_linear()`：创建内核数据包

这个函数从 ringbuffer DMA 区域复制数据，然后初始化一个 **`struct sk_buff \*skb`** 结构体变量，也就是我们最常打交道的**内核协议栈中的数据包** 

那些依赖 skb 的邻居子系统、路由子系统、 Netfilter/iptables、TC、各种网络 BPF 程序（XDP 除外）

## 第二次数据复制

- 第一次是将包从网卡通过 DMA 复制到 ring buffer；对应图中第 3 步；
- 第二次是从 ring buffer 复制到 skb 结构体；对应图中第 6 步；

`mlx5e_complete_rx_cqe() -> mlx5e_build_rx_skb()`：初始化 L2 header、IPSec、时间戳等

### 已经完成的 CQ WQ （简单来说就是 RX ringbuffer）会释放掉，所以最后需要重新分配 CQ WQ：

### GRO（Generic Receive Offloading）

功能是**对分片的包进行重组然后交给更上层**，以提高吞吐。 GRO 给协议栈提供了一次**将包交给网络协议栈之前，对其检查校验和 、修改协议头和发送应答包（ACK packets）的机会**。

1. 如果 GRO 的 buffer 相比于包太小了，它可能会选择什么都不做；
2. 如果当前包属于某个更大包的一个分片，调用 `enqueue_backlog()` 将这个分片放到某个 CPU 的包队列；当包重组完成后，会交会协议栈网上送；
3. 如果当前包不是分片包，往上送。

**通过合并“足够类似”的包来减少传送给网络栈的包数，这有 助于减少 CPU 的使用量**。例如，考虑大文件传输的场景，包的数量非常多，大部分包都是一 段文件数据。相比于每次都将小包送到网络栈，可以将收到的小包合并成一个很大的包再送 到网络栈。GRO **使协议层只需处理一个 header**，

# 6 进入内核协议栈：L2 处理

## `__netif_receive_skb_core()`：送到协议层

`__netif_receive_skb_core` 完成**将数据送到协议栈**这一繁重工作。这里面做的事情非常多， 按顺序包括：

1. 处理 skb 时间戳；
2. **Generic XDP**：软件执行 XDP 程序（XDP 是硬件功能，本来应该由硬件网卡来执行）；
3. 处理 VLAN header；
4. TAP 处理：例如 **tcpdump 抓包**、流量过滤；
5. TC：TC 规则或 **TC BPF 程序**；
6. Netfilter：处理 iptables 规则等。

# 7 L3 协议层处理（IPv4）

`ip_rcv()` 方法的核心逻辑非常简单直接，就是一些数据合法性验证，统计计数器更新等 等，它在最后会以 **netfilter hook** 的方式调用 `ip_rcv_finish()` 方法。 这样任何 iptables 规则都能在 packet 刚进入 IP 层协议的时候被应用，在其他处理之前。

![image-20250321122555573](https://myblog-1307634347.cos.ap-guangzhou.myqcloud.com/blog/image-20250321122555573.png)

## Netfilter `NF_INET_PRE_ROUTING` hook

**netfilter 或 iptables 规则都是在软中断上下文中执行的**， 数量很多或规则很复杂时会导致**网络延迟**。

TC BPF 也是在软中断上下文中， 但要比 netfilter/iptables 规则高效地多，也发生在更前面（能提前返回），所以应尽可能用 BPF。

# 8（UDP）

![image-20250321123158086](https://myblog-1307634347.cos.ap-guangzhou.myqcloud.com/blog/image-20250321123158086.png)





## 8 L4 协议层处理（TCP）

TCP有限状态机

![image-20250321123221822](https://myblog-1307634347.cos.ap-guangzhou.myqcloud.com/blog/image-20250321123221822.png)

![image-20250321123818597](https://myblog-1307634347.cos.ap-guangzhou.myqcloud.com/blog/image-20250321123818597.png)

# 应用层

网络数据通过 `__skb_queue_tail()` 进入 socket 的接收队列，在此之前，会做几件事情：

1. 检查 socket 已分配的内存，如果超过了 receive buffer 的大小，丢弃这个包并更新计数
2. 应用 `sk_filter`，这允许在 socket 上执行 BPF 程序；
3. 执行 `sk_rmem_scedule`，确保有足够大的 receive buffer 接收这个数据报
4. 执行 `skb_set_owner_r`，这会计算数据报的长度并更新 `sk->sk_rmem_alloc` 计数
5. 调用`__skb_queue_tail` 将数据加到队列尾端

最后，所有在这个 socket 上等待数据的进程都收到一个通知通过 `sk_data_ready` 通知处理 函数。