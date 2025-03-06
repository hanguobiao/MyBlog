# DPDK的缺陷

近些年业界流行通过**内核旁路**（kernel bypass）的方式实现 **可编程的包处理过程**（programmable packet processing）。将网络硬件完全交由某个专门的**用户空间应用**（userspace application） 接管，从而避免**内核和用户态上下文切换**的昂贵性能开销。

但是，操作系统被旁路（绕过）之后，它的**应用隔离（application isolation） 和安全机制（security mechanisms）**就都失效了；一起失效的还有各种经过已经 充分测试的**配置、部署和管理工具**。

- **很难与现有系统集成**；
- 上层应用必须要将内核中已经**非常成熟的模块在用户态重新实现一遍**，例如路由表、高层协议栈等；
- 最坏的情况下，这种包处理应用只能工作在一个完全隔绝的环境，因为内核提供的**常见工具和部署方式在这种情况下都不可用了**。
- 导致系统越来越复杂，而且**破坏了操作系统内核在把控的安全边界**。 在基础设施逐渐迁移到 Kubernetes/Docker 等**容器环境的背景下，这一点显得尤其严重**， 因为在这种场景下，**内核担负着资源抽象和隔离的重任**。

# XDP

为解决这个问题，我们提出一种**新的可编程包处理方式**：eXpress Data Path (XDP)。

- XDP 提供了一个**仍然基于操作系统内核**的安全执行环境，在**设备驱动上下文** （device driver context）中执行，可用于定制各种包处理应用。
- XDP 是**主线内核（mainline Linux kernel）的一部分**，与现有的内核 网络栈（kernel’s networking stack）完全兼容，二者协同工作。
- XDP 应用（application）通过 C 等高层语言编写，然后编译成特定字节码；出于安 全考虑，内核会首先对这些字节码执行静态分析，然后再将它们翻译成 **处理器原生指令**（native instructions）。
- 测试结果显示，XDP 能达到 **24Mpps/core** 的处理性能。

具体地，XDP：

1. 与内核网络栈协同工作，**将硬件的控制权完全留在内核范围内**。带来的好处：
   - **保持了内核的安全边界**
   - 无需对网络配置或管理工具做任何修改
2. **无需任何特殊硬件特性**，任何有 Linux 驱动的网卡都可以支持， 现有的驱动只需做一些修改，就能支持 XDP hooks。
3. 可以选择性地**复用内核网络栈**中的现有功能，例如路由表或 TCP/IP 协议栈，在保持配置接口不变的前提下，加速关键性能路径（critical performance paths）。
4. 保证 eBPF 指令集和 XDP 相关的编程接口（API）的稳定性。
5. 与常规 socket 层交互时，**没有从用户态将包重新注入内核的昂贵开销**。
6. **对应用透明**。这创造了一些新的部署场景/方式，例如直接在应用所 在的服务器上部署 DoS 防御（而非中心式/网关式 DoS 防御）。
7. **服务不中断的前提下动态重新编程**（dynamically re-program）， 这意味着可以按需加入或移除功能，而不会引起任何流量中断，也能动态响应系统其他部分的的变化。
8. **无需预留专门的 CPU 做包处理**，这意味着 CPU 功耗与流量高低直接相关，更节能。

## 可编程硬件 vs. XDP

可编程硬件设备也是一种实现高性能包处理的方式。

- 一个例子是 NetFPGA [32]，通过对它暴露的 API 进行编程，能够在这种基于 FPGA 的专 用设备上运行任何包处理任务。
- P4 编程语言 [7] 致力于**将这种可编程能力扩展到更广泛的包处理硬件上** （巧合的是，它还包括了一个 XDP backend [51]）。

某种意义上来说，**XDP 可以认为是一种 offload 方式**：

1. 性能敏感的处理逻辑下放到网卡驱动中，以提升性能；
2. 其他的处理逻辑仍然走内核网络栈；
3. 如果没有用到内核 helper 函数，那整个 XDP 程序都可以 offload 到网卡（目前 Netronome smart-NICs [27] 已经支持）。

## XDP系统架构

XDP 系统，四个主要组成部分：

1. **XDP driver hook**：XDP 程序的主入口，在网卡收到包执行。
2. **eBPF virtual machine**：执行 XDP 程序的字节码，以及对字节码执行 JIT 以提升性能。
3. **BPF maps**：内核中的 key/value 存储，作为图中各系统的主要通信通道。
4. **eBPF verifier**：加载程序时对其执行静态验证，以确保它们不会导致内核崩溃。

![img](https://arthurchiao.art/assets/img/xdp-paper-2018/1.png)

上图是 ingress 流程。网卡收到包之后，**在处理包数据（packet data）之前，会先执行 main XDP hook 中的 eBPF 程序**。 这段程序可以选择：

1. **丢弃（drop）**这个包；或者

2. 通过当前网卡将包再**发送（send）**出去；或者

3. 将包**重定向（redirect）**到其他网络接口（包括虚拟机的虚拟网卡），或者通过 AF_XDP socket 重定向到用户空间；或者

4. **放行（allow）**这个包，如果后面没有其他原因导致的 drop，这个包就会进入常规的内核网络栈。

   如果是这种情况，也就是放行包进入内核网络栈，那接下来在将包放到发送队列之前（before packets are queued for transmission）， 还有一个能执行 BPF 程序的地方：**TC BPF hook**。

此外，图 1 中还可以看出，不同的 eBPF 程序之间、eBPF 程序和用户空间应用之间，都能够**通过 BPF maps 进行通信**。

## XDP driver hook

XDP程序在网络设备驱动中执行，网络设备没收到一个包，程序就执行一次。相关代码实现为一个**内核库函数**（library function），因此程序直接 在设备驱动中执行，**无需切换到用户空间上下文**。

程序在网卡收到包之后**最早能处理包的位置** 执行 —— 此时**内核还没有为包分配 `struct sk_buff` 结构体**， 也没有执行任何解析包的操作。

下图是一个典型的 XDP 程序执行流：

![img](https://arthurchiao.art/assets/img/xdp-paper-2018/2.png)

网卡收到一个包时，XDP 程序依次执行：

1. **提取**包头中的信息（例如 IP、MAC、Port、Proto 等），

   执行到程序时，系统会传递给它一个上下文对象（context object）作为**参赛** （即 **`struct xdp_md \*ctx`**，后面有例子），其中包括了指向原 始包数据的指针，以及描述这个包是从哪个网卡的哪个接口接收上来的等元数据字段。

2. 读取或更新一些资源的**元信息**（例如更新统计信息）；

   解析包数据之后，XDP 程序可以读取 `ctx` 中的包元数据（**packet metadata**） 字段，例如从哪个网卡的哪个接口收上来的（ifindex）。除此之外，`ctx` 对象还允许 程序访问与包数据毗邻的一块**特殊内存区域（cb, control buffer）**， 在包穿越整个系统的过程中，可以将自定义的数据塞在这里。

   除了 per-packet metadata，XDP 程序还可以通过 BPF map 定义和访问自己的**持久数据** ，以及**通过各种 helper 函数访问内核基础设施**。

   - BPF map 使 BPF 程序能与系统的其他部分之间通信；
   - Helpers 使 BPF 程序能**利用到某些已有的内核功能**（例如路由表）， 而**无需穿越整个内核网络栈**。

3. 如果有需要，对这个包进行 **rewrite header** 操作，

   **程序能修改包数据的任何部分，包括添加或删除包头**。这使得 XDP 程序能执行封装/接封装操作，以及重写（rewrite）地址字段然后转发等操作。

   内核 helper 函数各有不同用途，例如修改一个包之后，计算新的校验和（checksum）。

4. 进行最后的**判决**（verdict），确定接下来对这个包执行什么操作；

   判决结果包括：

   - 三种简单返回码：丢弃这个包、通过接收时的网卡将包重新发送出去、允许这个包进入内核网络栈；
   - 第四种返回码 redirect：允许 XDP 程序**指定网卡、CPU、用户态 socket** 等，将包重定向过去。

   **重定向功能的用途**：

   1. 将原始包通过另一个**网卡**（包括虚拟机的虚拟网卡）发送出去；
   2. 转发给指定 **CPU** 做进一步处理；
   3. 转发给 **AF_XDP 类型的 socket** 做进一步处理；

   这些不同的路径，在图 1 对应的是几条实线。

   将**重定向判决（verdict）与重定向目标（target）分开**，使得重定向目标类型很容易扩展； 另外，由于**重定向参数（目标）是通过 BPF map 查询的**，因此无需修 改 XDP 程序，就能动态修改重定向目标。

程序还能通过**尾调用**（tail call），将控制权交给另一个 XDP 程序； 通过这种方式，可以将一个大程序拆分成几个逻辑上的小程序（例如，根据 IPv4/IPv6）。

由于 XDP 程序可包含任意指令，因此前三步（读取包数据、处理元数据、重写包数据） **顺序可以是任意的，而且支持多层嵌套**。 但实际中为了获得高性能，大部分情况下还是将执行结构组织成这顺序的三步。

## eBPF verifier

### 唯一加载入口：`bpf()` 系统调用

由于 eBPF 代码直接**运行在内核地址空间**，因此它能直接访问 —— 也可 能是破坏 —— 任何内存。为防止这种情况发生，内核规定**只能通过唯一入口（ `bpf()` 系统调用）加载 BPF 程序**。

加载 BPF 程序时，位于内核中的校验器首先会对字节码程序进行静态分析，以确保

- 程序中没有任何不安全的操作（例如访问任意内存），
- 程序会终止（terminate）。通过下面这两点来实现：
  - **禁止循环操作**
  - **限制程序最大指令数**

### 校验器工作原理：two-pass DAG

校验器的工作原理：首先根据**程序的控制流**构建一个有向无环图（DAG）， 然后对 DAG 执行如下校验：

- 首先，对 DAG 进行一次**深度优先搜索**（depth-first search），以 确保它是无环的（acyclic），例如，没有循环，也不包含不支持或无法执行到的指令。

- 然后，再扫描一遍，这次会**遍历 DAG 的所有可能路径**。这次扫描的目的是：

  - 确保程序的**内存访问**都是安全的，
  - 调用 **helper 函数**时传的**参数类型**是对的。

  程序执行 `load` 或 `call` 指令时，如果参数不合法，就会在这里被拒绝。参数合法 性是通过在**程序执行期间跟踪所有寄存器和栈变量的状态**（states of registers and stack variables）来实现的。

### 内存越界和空指针检查：职责上移到程序自身/开发者

这种跟踪寄存器状态的机制是为了**在无法预知内存边界的情况下，仍然确保程序 的内存访问不会越界**。无法预知内存边界是因为：

- 包的大小是不固定的；
- map 的内容也无法提前预知，因此也无法判断一次 map 查找操作是否会成功。

为解决这个问题，校验器会检查**已加载的程序自身是否会做如下检查**：

1. 解引用指针前做了内存边界检查，
2. 查询 map 之前是检查了 map 指针是否为空。

这种方式将处理逻辑中的安全检查和遇到错误时如何处理的控制权都 **交给了 BPF 程序的编写者**。

### 跟踪数据访问操作和值范围

为跟踪数据访问，校验器会跟踪

1. **数据类型**
2. **指针偏移**（pointer offsets）
3. 所有**寄存器的可能值范围**

程序开始时，

- **R1** 寄存器中存储的是指向 context metadata 的指针（`struct xdp_md *ctx`）,
- **R10** 是栈指针（stack pointer），
- 其他所有寄存器都是未初始化状态。

接下来程序每执行一步，寄存器状态就会更新一次。当寄存器中存入一个新值时，这个寄存器 还会继承与这个值相关的状态变量（inherits the state variables from the source of the value）。

算术操作会影响标量类型的值的范围（value ranges of scalar types），以及指针类型的 offset。 可能的最大范围（max possible range）存储在**状态变量**中，例如往寄存器中 load 一个字节时， 这个寄存器的可能值范围就设置为 0~255。指令图（instruction graph）中的 **各逻辑分支就会根据操作结果更新寄存器状态**。例如，比较操作 `R1 > 10`，

- 校验器在一个分支 `if R1 > 10` 中会将 R1 最小值设为 11，
- 在另一个 `else` 分支中将其最大值设为 10。

### 不同类型数据的校验信息来源（source of truth）

利用状态变量中存储的范围信息，**校验器就能预测每个 load 指令能访问的所有 内存范围**，确保它执行的都是合法内存访问。

1. 对于**包数据（packet data）**的访问，会与 context 对象中的 `data_end` 变量做比较；
2. 对于 **BPF map 中获取的值**，或用到 map 定义中声明的 data size 信息；
3. 对于**栈上存储的值**，会检查状态变量中记录的值范围；
4. 对于**指针算术操作**（pointer arithmetic）还会施加额外的限制，指针通常不能被转换成整形值。

只要校验器无法证明某个操作是安全，该 **BPF 程序在加载时（load time）就会被拒绝**。 除此之外，校验器还会利用范围信息确保内存的对齐访问（enforce aligned memory access）。

### 校验器的目的

需要说明的是，校验器的目的是**避免将内核内部（the internals of the kernel ）暴露给恶意或有缺陷的 eBPF 程序**，而非确保程序中函数的实现已经是最高效的。

换句话说，如果 XDP 程序中处理逻辑过多，也可能会导致机器变慢 ；如果代码写的有问题，也可能会破坏包数据。**出于这些原因，加载 BPF 程序需要 管理员权限**（root）。避免这些 bug 的责任在程序员，但选择将哪些程序加载 到系统的权限在管理员。

### 一个典型XDP程序

```c
struct bpf_map_def SEC("maps") rxcnt = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(long),
    .max_entries = 256,
};

static void swap_src_dst_mac(void *data)
{
    unsigned short *p = data;
    unsigned short dst[3];
    dst[0] = p[0]; dst[1] = p[1]; dst[2] = p[2];
    p[0] = p[3]; p[1] = p[4]; p[2] = p[5];
    p[3] = dst[0]; p[4] = dst[1]; p[5] = dst[2];
}

static int parse_ipv4(void *data, u64 nh_off, void *data_end)
{
    struct iphdr *iph = data + nh_off;
    if (iph + 1 > data_end)
        return 0;
    return iph->protocol;
}

SEX("xdp1")
int xdp_prog1(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    int rc = XDP_DROP;
    long *value; u16 h_proto; u64 nh_off; u32 ipproto;

    nh_off = sizeof(*eth);
    if (data + nh_off > data_end)
        return rc;
    h_proto = eth->h_proto;

    if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
        struct vlan_hdr *vhdr;

        vhdr = data + nh_off;
        nh_off += sizeof(struct vlan_hdr);
        if (data + nh_off > data_end)
            return rc;
       h_proto = vhdr->h_vlan_encapsulated_proto;
    }

    if (h_proto == htons(ETH_P_IP)) {
        ipproto = parse_ipv4(data, nh_off, data_end);
    } else if (h_proto == htons(ETH_P_IPV6)) {
        ipproto = parse_ipv6(data, nh_off, data_end);
    } else {
        ipproto = 0;
    }

    value = bpf_map_lookup_elem(&rxcnt, &ipproto);
    if (value)
        *value += 1;

    if (ipproto == IPPROTO_TCP) {
        swap_src_dst_mac(data);
        rc = XDP_TX;
    }
    return rc;
}
```

具体地：

- 定义了一个 BPF map 存储统计信息。用户态程序可以 poll 这个 map 来获取统计信息。
- context 对象 `struct xdp_md *ctx` 中有包数据的 start/end 指针，可用于**直接访问包数据**。
- 将数据指针和 `data_end` 比较，确保内存访问不会越界。
- 程序必须自己解析包，包括 VLAN headers 等东西。
- 直接通过指针（direct packet data access）**修改包头**。
- 内核提供的 map lookup helper。这是程序中**唯一的真实函数调用**；其他函数都是内联，包括 `htons()`。
- 最终针对这个包的判决通过程序返回值传递给调用方。

将这段程序安装到网卡接口上时，它首先会被编译成 eBPF 字节码，然后经受校验器检查。 这里的检查项包括：

1. 无循环操作；程序大小（指令数量）；
2. **访问包数据之前，做了内存边界检查**；
3. **传递给 map lookup 函数的参数，类型与 map 定义相匹配**；
4. **map lookup 的返回值（value 的内存地址）在使用之前，检查了是否为 NULL**。