# 《BPF之巅》学习笔记

# 概述

## 名词

### kprobe：提供针对内核的动态插桩技术

1. 将在要插桩的目标地址中的字节内容复制并保存（给单步断点腾出位置）
2. 以单步中断指令覆盖目标地址
3. 当指令流执行到断点时，断点函数会检查这个断点是否由kprobes注册的，如果是，就会执行kprobes
4. 原始指令会接着执行，指令流继续
5. 当不再需要kprobes时，原始的字节内容会被复制回目标地址上

如果是Ftrace已经做过插桩的地址，可以基于Ftrace进行kprobes优化

1. 将一个Ftrace kprobes处理函数注册为对应函数的Ftrace处理器
2. 当在函数起始处执行内建入口函数时，该函数会调用Ftrace，Ftrace接下来会调用kprobes
3. 当kprobes不再被使用时，从Ftrace中移除Ftrace-kprobes

如果是kretprobe

1. 对函数入口进行kprobe插桩
2. 当函数入口被kprobe命中时，将返回地址保存并替换为一个“蹦床”（trampoline）函数地址
3. 当函数最终返回时（ret指令），CPU将控制交给蹦床函数处理
4. 在kretprobes处理完成之后再返回到之前保存的地址
5. 不再需要kretprobes时，函数入口的kprobes就移除了

### Uprobes：提供了用户态的动态插桩技术

1. 将一个快速断点指令插入目标指令处，该指令将执行转交给uprobes处理函数，当不再需要uprobes时，目标指令回家恢复成原来的样子
2. 对于uretprobes也是在函数入口处使用uprobes进行插桩，而在函数返回之前，则使用一个蹦床函数会返回地址进行劫持，和kprobes类似

### USDT探针

编译应用程序时，在USDT探针的地址放置了一个nop指令。插桩时，这个地方会由内核使用uprobes动态的将其修改为一个断点指令。当该断点被触发时，内核会执行相应的BPF程序，其中带有USDT探针的参数。

动态USDT，需要被添加到源码并编译到最终的二进制文件，在插桩点留下nop指令，在ELF notes段中存放元数据。

1. 预编译一个共享库，带着想要内置在函数职工的USDT探针。其中有一个针对USDT探针的ELF notes区域，可以想其他USDT探针一样被插桩
2. 需要时，使用dlopen(3)加载该动态库
3. 针对目标语言增加对该共享库的调用。可以使用适合该语言的API，以便隐藏底层的共享库调用

### 性能监控计数器PMC

PMC：处理器上的硬件可编程计数器。是性能分析领域至关重要的资源。只有通过PMC才能测量CPU指令执行的效率、CPU缓存的命中率、内存/数据互联和设备总线的利用率，以及阻塞的指令周期等

任一时间在CPU中只允许固定数量的寄存器进行读取

计数模式：在此模式下，PMC能够追踪事件发生的频率，只要内好像有需要就可以随时读取。这种模式的开销几乎为零

溢出采样：此模式下，PMC在所监控的事件发生到一定次数时通知内核，这样内核可以获取额外的状态。监控的事件可能会以每秒百万、亿级别的频率发生，可能会导致系统性能下降到不可用。可以用一个可编程的计数器进行采样，当计数器溢出时向内核发信号

### perf_events

perf(1)命令所依赖的采样和跟踪机制。

BCC和bpftrace先是使用per_event作为环形缓冲区，之后增加了PMC的支持，又通过perf_event_open()来对所有事件进行观察

# 工具

## Libbpf-bootstrap 

是基于libbpf库的BPF开发脚手架

## BCC

### 工具

Funccount：在内核维护一个BPG映射表维护事件的计数

stackcount： 对导致某事件发生的函数调用栈进行技术，使用特殊的，调用栈信息专用的BPF映射表进行统计。用户空间读取调用栈ID和统计数字，然后从BPF映射表取出调用栈信息，在进行符号翻译和打印输出

trace：可以针对多个数据源进行每个事件的跟踪，支持kprobes、uprobes、跟踪点和USDT探针，可以回答以下问题：

- 当某个内核态/用户态函数被调用时，调用参数是什么？
- 函数的返回值是什么？
- 函数是如何被调用的？相应的用户态活内核态函数调用栈是什么？

适合低频事件或者过滤

示例使用trace追踪sock_alloc()来定位文件泄露 trace -tkU 'r::sock_alloc "open %llx" , retval' '__sock_release "close %llx", arg1'    -- 对sock_alloc()的返回值进行插桩，并打印返回值，socket地址以及调用栈信息。同时追踪了内核函数 __sock_release() 获取了第二个参数，这样可以获得被关闭的socket地址

Argdist： 针对函数调用参数分析的工具

### 内部实现

BCC由以下几部分组成

- C++前端API，用于内核态的BPF程序的编制，包括“
  - 预处理宏，负责将内存引用转换为bpf_probe_read()函数调用
- 一个C++后端
  - 使用Clang/LLVM编译BPF程序
  - 将BPF程序挂载到内核
  - 将BPF程序挂载到事件
  - 对BPF映射表进行读写
- 语言前端工具

![img](https://infracreate.feishu.cn/space/api/box/stream/download/asynccode/?code=OThmMDdlN2NjMjZhNjlhOGM0MmI5YWQwNjFiNmI3MjBfZFgzaWw0S2ZqTmpMV2VLQ2NpQWZFM2RVam5kNktlMmZfVG9rZW46UXZYb2JKTFlmb3RXT014SXNxWWNqMjBNblllXzE3MjcwMDI3NzM6MTcyNzAwNjM3M19WNA)

### 处理流程

1. 创建Python BPF对象，将BPF c程序传递给该对象
2. 使用BCC改写器对BPF C程序进行预处理，将内存访问替换为bpf_probe——read()
3. 使用Clang将BPF C程序编译为LLVM IR
4. 使用BCC codegen 根据需要增加额外的LLVM IR
5. LLVM将IR编译为BPF字节码，创建映射表
6. BCC程序通过映射表或者perf_event缓冲区读取数据

## BPFtrace

### 架构

基于BPF和BCC的开源跟踪器，提供了一个高级编程语言环境。

- 前端使用lex和yacc来对bpftrace编程语言进行词法和语法分析，使用clang来解析结构体。
- 后端将bpftrace程序编译为LLVM中间表示形式，再通过LLVM库将其编译为BPF代码

![img](https://infracreate.feishu.cn/space/api/box/stream/download/asynccode/?code=MGFkOTMxZTgwYWI1N2YyZGQyNTI0OGZhZWFhYzBjMmVfMVNRemtLYWI5RDl6OEwybDAwU3NBSXNwSFpwVGZpbnNfVG9rZW46TmljcWJUZXc3b3c0ckZ4dUROaWN5R0I3bklkXzE3MjcwMDI3NzM6MTcyNzAwNjM3M19WNA)

![img](https://infracreate.feishu.cn/space/api/box/stream/download/asynccode/?code=MWZhOGJiOWYwZjJhMWUxMzFmM2M3ZGE1ODNjZTkxYTNfUTlPN0FqbkxLZDFDWDhZNGNJeFpDc0FoSjIxb1B4TlRfVG9rZW46RzNGSWJWOU9TbzhRM2l4eTRLa2NnZGE4bm9mXzE3MjcwMDI3NzM6MTcyNzAwNjM3M19WNA)

### 事件源

- 动态插桩，内核态（kprobe）
- 动态插桩，用户态（uprobe）
- 静态插桩，内核态（tracepoint，software）
- 静态插桩，用户态（usdt，借助libbcc）
- 定期时间采样（profile）
- 周期事件（interval）
- PMC事件（hardware）
- 合成事件（BEGIN，END）

### bpftrace的内部运作

https://zhuanlan.zhihu.com/p/393199226

![img](https://infracreate.feishu.cn/space/api/box/stream/download/asynccode/?code=YTQ3ODVlM2FiODMzNjNjYmM0YWExZWRlMzhhYTE0MGVfTGoyUEgzZjdacmFoTDNaSThWOWlJbkJsb01yT1hXdm1fVG9rZW46T3VQdGJjQ2dnb05NQ2R4MEhnQmNyMEpYbkpkXzE3MjcwMDI3NzM6MTcyNzAwNjM3M19WNA)

bpftrace使用libbcc和libbpf完成对探针的插桩、程序的加载、以及使用USDT。使用LLVM将程序编译为BPF字节码

bpftrace的语言是使用lex和yacc文件定义的，会分别经过flex和bison程序处理。输出一个座位抽象语法树存在的程序。跟踪点解析器和Clang解析器会对这个结构进行语法分析。接下来就是代码的生成，将AST节点转为LLVM IR，再由LLVM编译为BPF字节码

# 背景知识

## CPU

### 名词

on-cpu：线程正在CPU上运行

off-cpu：线程的其他状态

### 事件源

![img](https://infracreate.feishu.cn/space/api/box/stream/download/asynccode/?code=MjNmYjYzMmZkNDg3YzVlMWU2YTY5NTM0ZjQzZDkzNjdfb0NPMWhDMmJUVjR2M1V0M1ZxbWk5VW1NRmc1aXZHbDBfVG9rZW46SWhZYmJtcVlBb0pVaGt4bHBRaGNGVWxzbkRiXzE3MjcwMDI3NzM6MTcyNzAwNjM3M19WNA)

### 传统工具

1. #### 内核统计

内核通过/proc接口显露统计数据，优点是额外消耗少

1. #### 硬件统计

硬件也会提供许多有用信息--尤其是CPU提供的性能监控计数器（PMC），

perf（1）

可以将PMC与模型特定的寄存器（MSR）配合来展示CPU硬件信息

1. #### 硬件采样

perf可以根据一个给定的数值N当PMC超过这个值，产生中断以便让内核抓取信息

1. #### 定时采样

以固定的时间间隔截取指令指针位置或者程序调用栈信息。这种类型粒度比较粗，可以很容易看出那些程序在占用CPU。

周期采样

perf1以定时采样的方式运行时，首先会尝试使用基于PMC的硬件CPU周期溢出事件来进行采样。这个事件会产生一个不可掩盖的中断，在对应的中断处理函数中会进行调用栈采样。

没有启动PMC的话，会改为基于hrimer的软中断采样。软中断模式通常可以应对大部分性能场景。但一些内核代码路径是没法进行软中断的，这会导致采样结果中缺少这种代码路径

1. #### 事件统计与事件追踪

perf1可以跟踪跟踪点。kprobes和uprobes以及USDTprobes的跟踪功能

### BPF工具

#### execsnoop

跟踪全系统中的新进程执行信息的工具，可以找到消耗大量CPU的短期进程，以及分析软件执行过程，包括启动脚本。可以用来寻找高频出现、消耗资源的短期进程。

execsnoop直接跟踪execve系统调用，可以直接打印execve的调用参数和返回值，这样可以抓取fork/clone->exec产生的新进程以及那些自己主动调用exec的进程。

#### Exitsnoop

可以跟踪进程退出事件，打印出进程的总运行时长和退出原因，运行时长是指进程从创建到终止的时长，包括CPU运行时间和非运行时间。可以帮助调试短时进程的问题

exitsnoop使用了sched：sched_process_exit跟踪点和参数信息，同时利用bpf_get_current_task（）从task结构中读取起始信息。

#### Runqlat

CPU调度器延迟分析工具，CPU调度器延迟被称为运行队列延迟，在需求超过供给，CPU资源处于饱和时，可以识别和量化问题的严重性

利用了CPU调度器的线程唤醒事件和线程上下文切换事件的跟踪来计算线程从唤醒到运行之间的时间间隔。

#### runqlen

采样CPU运行队列的长度信息，可以统计有多少线程正在等待运行。

#### Runslower

可以列出运行队列中等待延迟超过阈值的线程，输出受延迟影响的进程名和延迟时长。

利用内核中的ttwu_do_wakeup()函数、wake_up_new_task()函数和finish_task_switch()函数对应的kprobes。之后可能改为使用CPU调度器跟踪点

#### Cpudist

用来展示每次线程唤醒之后再CPU上执行的时长分布。可以定性分析CPU使用率

通过跟踪CPU调度器的上下文切换事件，额外开销大。

#### Cpufreq

采样CPU频率

跟踪内核中有频率变化的跟踪点

#### Profile（重点）

定时采样调用栈信息并汇报调用栈出现频率信息。profile的频率统计是在内核态中完成的

#### Offcputime

用于统计线程阻塞和脱离CPU运行的时间，同时输出堆栈信息，可以分析线程为什么没有在CPU上运行

通过跟踪上下文切换事件来记录一个线程脱离CPU的时间和返回CPU的时间，同时记录堆栈信息。使用finish_task_switch()kprobes 给脱离CPU的线程记录一个时间戳，并且讲启动线程的所有脱离CPU的时间进行合计。

#### sysout

统计系统中系统调用的数量

利用raw_syscall:sys_enter这个跟踪点，而没有使用常见的syscall：sys_enter_*跟踪点。原因是可以看到全部的系统调用，缺点是只能提供系统调用的ID。

#### argdist和trace

可以针对每个事件自动以处理方法。

argdist使用的是内核态的统计计数，可以用于那些调用非常频繁的系统调用。trace可以打印出每个事件，适合调查那些调用不频繁的系统调用，输出额外信息。

#### 待补全。。。。。。

## 内存

### 内存分配器

![img](https://infracreate.feishu.cn/space/api/box/stream/download/asynccode/?code=MGE4ZDRkNGM1MThiZjA0Zjc4NDMyNjFmYTlhNjE5NTBfSWVCN3RTNVZjeGdLVHJkSmdScWFnSVg1VlFLME8yZnNfVG9rZW46TVZGamJ3SHV0b1BaWFl4RjIxeGN2NklRbmpiXzE3MjcwMDI3NzM6MTcyNzAwNjM3M19WNA)

### 内存页和换页机制

![img](https://infracreate.feishu.cn/space/api/box/stream/download/asynccode/?code=YTRjMjg2MTJmYTg5ZTEzZWFmMDExZGM3MzZmMzU2MmZfVVd1cGpsVnZNTzFDb1pWMFM5M3lTYXEyYmQ5UUZyTDJfVG9rZW46TWJYdWJRbVZPb0hjdHR4ZlBWU2N2Sk9hblZoXzE3MjcwMDI3NzM6MTcyNzAwNjM3M19WNA)

#### 内存页的生命周期

1. 应用程序发起内存分配请求
2. 应用程序库代码要么直接从空闲列表中响应请求，要么先扩展虚拟内存地址空间再分配
   1. 利用brk（）来扩展堆的尺寸，以便使用新的堆地址响应请求
   2. 利用mmap（）来创建一个新的内存段地址
3. 内存分配后，应用程序试图使用store/load指令来使用之前分配的内存地址，这就要调用CPU内部的内存管理单元来进行虚拟地址到物理地址的转换。如果虚拟地址没有对应的物理地址，就会产生缺页错误
4. 缺页错误由系统内核处理。对应的处理函数中，内核会在物理内存空闲列表找到一个空闲地址并映射到该虚拟地址。之后内存会通知MMU以便未来直接查找该映射。现在该用户进程就占据了一个新的物理内存页。
5. 当系统内存需求超过一定水平时，内核中的页换出守护进程就开始寻找可以释放的内存页。

对于比较繁忙的用户态应用程序，每秒的内存分配可能超过数百万次，内存加载和存储指令以及MMU查表操作会更频繁，每秒数十亿次。

#### 页换出守护进程

页换出守护进程会被定期唤醒，会批量扫描活跃页的LRU列表和非活跃页的LRU列表以寻找可以释放的内存。当空闲内存低于某个阈值时，就会被唤醒。通常在后台运行，不会影响应用程序性能。

如果kswapd释放内存的速度不够快，导致页数量低于系统中配置的最低页数量，就会切换到直接回收模式：页回收会直接在前台运行，直接释放内存以便应对新的内存分配请求。内存分配会阻塞到有新的页被释放为止。

#### 内存溢出进程终止程序（OOM Killer）

OOM是释放内存的最后一道防线，该程序使用预定规则来选择要杀掉的进程。预定规则中定义将除内核关键任务和init（PID）进程之外占用内存最多的进程杀死。

#### 页压缩

内核有一个压缩程序负责移动内存页，扩大连续空间

### 事件源

![img](https://infracreate.feishu.cn/space/api/box/stream/download/asynccode/?code=OTcyY2E2YWE5OWY5OTViYWUxMGJjMTA1ZGJhZGRmNmFfTlZBYlpnRGZTa0lucjRsZkNMSjJGWjVSTjlFYzBOSmJfVG9rZW46Qkl0TmJHZk9Eb1hYNWZ4cEg3bWNvS0o5bkZoXzE3MjcwMDI3NzM6MTcyNzAwNjM3M19WNA)

### BPF工具

#### Oomkill

跟踪OOM Killer事件，打印平均负载

使用kprobes追踪oom_kill_process()函数，

#### 待补充。。。。。。

## 网络

### 背景知识

#### 网络软件栈

- 网络套接字：发送和接受数据的端点
- TCP
- UDP
- IP
- ICMP负责传送有关路由和错误的信息
- 队列管理器：可选的网络层，可以用于流量分类、调度、数据包修改、流量过滤、流量整形
- 设备驱动程序：驱动程序内部可能有自己的驱动程序内部队列
- NIC（网络接口卡）：包含物理网络端口的设备。可能是虚拟设备，例如隧道接口、veth虚拟网卡、回送接口loopback

![img](https://infracreate.feishu.cn/space/api/box/stream/download/asynccode/?code=YzM2NTdmZTgxNDE1NDBlN2U1MjAwOGM4YWJmZTg5NWFfdWZXRTF6N2tPZEZkQnVsRmZET0ZEOENpVVFSVFJrUXdfVG9rZW46QjlicGJnYVlab3JudjN4aGlhcWM3M3Bkbk51XzE3MjcwMDI3NzM6MTcyNzAwNjM3M19WNA)

#### DPDK

内核绕过技术，使用数据层开发套件这样的技术来绕过内核网络软件栈，可以提高性能，提高网络包处理能力。需要应用程序在用户态实现自己的网络软件栈，使用DPDK软件库和内核用户态I/O驱动或者虚拟驱动（VFIO）来直接向网卡设备驱动发送数据。可以通过直接从网卡内存中读取数据包的技术来避免数据的多次复制。

#### XDP

高速数据路径技术（XDP）为网络数据包提供了另外一条通道：一个可以使用扩展BPF编程的快速处理通道，与现有的内核软件栈可以直接集成，无需绕过

由于这种技术使用网卡驱动中内置的BPF钩子直接访问原始网络帧数据，因而可以避免TCP/IP软件栈处理的额外消耗，而直接告诉网卡是应该传递还是丢弃数据包。有需要时，这种技术还可以回退到正常的网络栈处理过程。

#### 网络栈内部实现

- 数据包在内核使用sk_buff结构体（网络套接字缓冲区）来传递
- 网络套接字是用sock结构体定义的，该结构体在各网络协议结构体的开头部分存放
- 网络协议使用proto结构体挂载到网络套接字结构体上；该结构体上定义了一系列该网络协议需要的回调函数

#### 发送和接受重放

如果不使用某种网络数据包的CPU负载均衡技术的话， 一个单独的网卡一般只会向一个CPU发送中断。这有可能导致该CPU资源全部用于处理中断和进行网络软件栈的处理，成为系统瓶颈。

有很多技术可以通过降低中断频率，以及将网卡中断处理和数据包处理分散给各种CPU分别处理，来提高网络的扩展能力和性能

- 新的API接口（NAPI）
- 接收方缩放技术（RSS）
- 入包导向技术RPS

### BPF工具

#### 事件源

![img](https://infracreate.feishu.cn/space/api/box/stream/download/asynccode/?code=MWU1MzhiZWRlMzM4MTA0MWJiY2EwYWUzYzk5OGE4NmFfMEdCWEZSUnVzUTBKQVFFVXlmT1YwRUw0ZDRPa2tPellfVG9rZW46RnRIV2JNcmlsb0RablV4ZFF0VmN2bHYxbm82XzE3MjcwMDI3NzM6MTcyNzAwNjM3M19WNA)

网络事件的发生频率可能会很高，在某些服务器和负载的情况下，可能超过每秒百万个数量包的量级。

很多观察工作并不需要跟踪每个具体的包，可以通过跟踪一些低频事件来完成。当确实需要跟踪每个数据包时，使用裸跟踪点要比使用kprobes更高效

#### 分析策略

1. 找出低效之处
   1. 使用基于计数的工具来理解基本的网络统计信息
   2. 通过跟踪新TCP连接的建立和时长来定性负载分析，并寻找低效之处
2. 检查各接口限制
   1. 检查是否到达了网络接口吞吐上限
3. 检查延迟源
   1. 跟踪TCP重传和其他不常见的TCP事件
   2. 测量主机DNS延迟
   3. 从各个角度测量网络延迟连接延迟、首字节延迟、软件栈各层之间的延迟等
4. 使用功能负载生成工具来探索主机之间的网络吞吐量上限，同时检查在已知负载情况下发生的网络事件
5. 高级工具：BPF，CPU profile，跟踪点

### BPF

#### sockstat

统计每秒套接字相关的系统调用次数

通过使用内核跟踪点来跟踪关键的套接字相关系统调用

#### Sofamily

通过跟踪accept和connect系统调用来跟踪新的套接字连接，同时展示对应的进程名和协议类型

connect系统调用，所有的信息都在入口处获得。

对于accept系统调用则不同：在入口处将sockaddr结构体指针存入一个哈希表中，在函数出口处在查询以读取地址信息。这是由于sockaddr结构体是在系统调用内部填充的。

#### Soprotocal

按进程名和传输协议来跟踪新套接字建立

#### Soconect

展示了IP协议套接字的connect请求

跟踪了connext系统调用跟踪点。好处是带有进程上下文信息，可以可靠的得到系统调用发起方信息

#### Soaccept

展示IP协议套接字的接受请求

该工具在系统调用出口处处理sockaddr结构体

#### Tcpconnect

可以跟踪新的TCP主动连接。这里使用的是较为底层的TCP网络代码，而非套接字相关的系统调用

该工具跟踪的是TCP连接创建的相关事件，而不是数据包相关事件。追踪的是tcp_v4_connect和tcp_v6_connect内核函数，未来可能改为使用sockaddr：inet_sock_set_state

#### Tcpaccept

追踪新的TCP被动连接

追踪inet_csk_accept函数，这个函数是tcp_prot结构体中accept对应的函数

#### 待补充。。。。。。

# 编程语言

## 背景知识

为了理解如何对一种给定的语言进行插桩，我们需要检查它在执行时是如何转换为机器码的。例如在一个完全插桩的JAVA应用中，可能会碰到编译部分的代码（C++ JVM函数），解释方式执行的部分代码（JAVA方式）和JIT编译后的代码。如何插桩各种函数是有区别的

### 编译型语言

对于编译型语言，函数会被编译为机器码，并且保存在二进制可执行文件中，通常为ELF，且包含以下属性

- 对于用户态软件，符号表被包含在ELF二进制文件中，可以将函数名和对象名与地址进行映射。这些地址在执行过程中标不会发生变化，所以符号表可以随时在映射中被读取。内核态软件不太一样的地方在于它在、proc/kallsyms有自己的动态符号表，该表会伴随着内核模块的加载而增长
- 函数的参数和函数的返回值被保存在寄存器和栈的特定偏移位置，会遵循每个处理器的标准调用规范。一些语言比如Golang使用了不同的调用规范，另一些则根本不使用调用规范
- 帧指针寄存器可以用来便利调用栈，前提是在函数序言这种对编译器进行了初始化。编译器通常会把帧指针寄存器重用为另一个通用寄存器。副作用就是会破坏基于帧指针的调用栈回溯

编译语言一般是比较容易跟踪：对用户态软件使用uprobes，对内核态软件使用kprobes。

1. 对编译语言展开工作时，可以检查一下是否存在符号表。
2. 如果没有符号表，检查是否有一个调试信息的包。如果有，可以提供相关符号信息。
3. 还是没有在检查编译器和构建脚本，看看符号为什么会在编译过程中丢失，可能是被strip系统调用剥离了、
4. 再检查帧指针的调用栈是否生效，这种方式是目前BPF对用户态调用栈回溯的默认方法。如果不生效，就需要开启帧指针重新编译

### 即时编译语言

JIT语言会将代码编译为字节码，在运行时阶段再编译为机器码，通常会从运行时操作中接受反馈来指导编译器优化

- 因为函数是运行时现场编译，所以没有提前构建的符号表。符号映射关系通常存储在JIT运行时的内存中，并且一般用于打印异常发生时的调用栈。这些映射关系也会发生变化，因为运行时会被重新编译，函数也会被转移
- 函数的参数和返回值可能会也可能不会遵循标准调用规范
- JIT运行时可能会也可能不会遵循栈指针寄存器，所以基于栈指针寄存器的回溯可能失败。运行时在出错后进行异常处理时，通常使用自己的方式进行调用栈回溯

跟踪以JIT方式编译的语言是很困难的。二进制文件中没有符号表，因为它是动态生成并存放在内存中的。一些应用可以为JIT提供额外的符号映射（/tmp/perf-PID.map）,然而uprobes不能使用这些信息

- 编译器可能会在内存中直接移动被uprobes插桩过的函数，但不会通知内核。当不再需要这个插桩点时，内核需要将指令恢复为插桩前的指令，但此时会写入错误的内存空间，导致用户空间的内存破坏
- uprobes基于inode，需要对应到一个文件才能工作，然而JIT映射可能存在于匿名的私有映射中

如果运行时对每个函数都提供USDT探针，那么对编译型函数进行跟踪就是可能得，但这种方法会带来高额的额外开销。更有效的方式是对经过选择的USDT探针进行插桩。USDT探针还提供了对函数参数和返回值进行插桩，方法是将它们作为探针的参数。

如果BPF的调用栈已经正常工作了，那么可以用额外提供的符号文件将函数地址转换为函数名字。对于不支持USDT的运行时来说，可以改使用功能这个方法获取正在运行的JIT函数的可见性：通过系统调用，内核事件，或者基于定时采样机制获得调用栈信息，以便观察当前正在运行的JIT函数

当调用栈不可用，考虑使用功能帧指针或者LBR。还有一些方法可以修复调用栈，一种是修改运行时编译器保留帧指针。另一种是添加可以使用语言自身获取调用栈方式的USDT，以字符串参数的方式提供

### 解释型语言  

解释型语言不会将程序函数编译为机器码，而是使用自身内置的子函数进行语法分析和执行，有如下属性

- 二进制符号表展示了解释器的内部符号，但是不包含用户程序中的函数，该函数很可能会被存储在一个负责对解释对象进行映射的内存表中，该表和特定的解释器实现相关
- 函数参数和返回值由解释器进行处理。通常由解释器的函数调用进行传递，并且可能和解释器的对象进行绑定，不是简单的展示类型和字符串
- 如果解释器编译时启用了帧指针，那么基于帧指针的调用栈就可以工作，不过只能在解释器内部运作，不能体现用户程序所提供的程序的函数名字上下文。解释器通常可以知晓用户程序的调用栈。

如果有USDT探针来显示函数的起止位置，这时函数的名字和参数会以探针参数的形式存在。如果语言运行时有动态USDT库，可以用它来定制化指针。

如果没有内置的USDT探针，并且没有包能提供USDT支持，那么可以使用uprobes来对解释器函数进行跟踪，可以得到函数名和参数这样的细节。通过对struct结构成员进行分析

在解释器内存中读取调用栈信息是极其困难的。一种成本高的方案：使用BPF函数跟踪每个函数调用的入口和出口，然后在BPF内存中为每个线程构建一个人工的栈，在需要时可以读取。和JIT方式编译的语言类似，有其他方式可以添加调用栈支持，包括通过定制化USDT探针以及运行时自己的方法来获取一个调用栈，或者通过BPF发信号到用户空间辅助函数。

## bpf工具

### 分析策略

1. 了解语言是如何执行的。对于使用该语言运行的软件，是编译为二进制文件，还是咋运行时即时编译，还是解释执行，还是混合方式
2. 根据BPF工具，理解对于每种语言可以做的事情
3. 搜索是否存在已知的工具和如何使用BPF对语言进行分析
4. 检查该语言是否有USDT探针，看它们是否在发行的二进制版本中激活，这些是稳定接口。
5. 写程序插桩，调用一个有确定名字和确定延迟的函数一定次数，检查这些工具能否识别这些已知量
6. 对于用户态软件使用uprobes来对语言的执行过程进行监控，对内核态的软件使用kprobes

### C

c是最容易进行跟踪的语言

对于内核态的C程序，内核有自己的符号表，而且大部分发行版都会在编译内核时开启帧指针。使得kprobes跟踪内核函数很直接，函数能够被看到和跟踪，参数遵循处理器ABI规范，可以顺利得到调用栈。至少大多数函数可以被看到和跟踪，例外是内联函数，以及那些在内核中被标记为插桩不安全的函数

对于用户态的C程序，如果在编译时没有清楚符号表，而且保留了帧指针，那么采用uprobes进行跟踪也是很直接的：函数可以被跟踪和看到，参数遵循处理器ABI规范，可以顺利得到调用栈。但多数二进制文件会清楚符号表，而且编译器页不使用帧指针，

USDT探针可以在C程序中动态插桩，部分C库，会默认提供USDT探针

#### c函数符号表

可以从ELF符号表中得到函数符号，readelf可以检查符号是否存在

# 容器

## 背景知识

![img](https://infracreate.feishu.cn/space/api/box/stream/download/asynccode/?code=N2M3MGYzMWY3YjM2ODllODJhMWY3MGMzMWVjMDg4YWFfNmxYdTBubDZBWjgxV2tIeW91d00xbVE4VWZKWlpiOW9fVG9rZW46S1lqc2I2czltb012akd4Y1N5UGNVNmg2bnloXzE3MjcwMDI3NzM6MTcyNzAwNjM3M19WNA)

命名空间限制了系统的视图，

cgroup限制了资源的使用。Linux内核有两个版本的cgroups，v1和v2；v1的cgroups包括blkio、cpu、mem......

Cgroups v2解决了v1的各种缺点，