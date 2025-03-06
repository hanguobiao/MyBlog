BPF 是 **Linux 内核中**一个非常灵活与高效的**类虚拟机**（virtual machine-like）组件， 能够在许多内核 hook 点**安全地**执行字节码（bytecode ）。可以在不牺牲原生内核性能的前提下，实现对内核的完全可编程。

**Cilium 在其数据平面（datapath）中重度使用了 BPF 技术**。**本文的目标**是提供一份 BPF 参考指南，这份指南能帮助我们更 深入地理解 BPF、BPF 网络相关的使用方式（例如用 `tc` 加载 BPF 程序，XDP 程序 ），以及更好地开发 Cilium 中的 BPF 模板。

# BPF架构

**BPF 不仅仅是一个指令集，它还提供了围绕自身的一些基础设施**，例如：

1. **BPF map**：高效的 key/value 存储
2. **辅助函数**（helper function）：可以更方便地利用内核功能或与内核交互
3. **尾调用**（tail call）：高效地调用其他 BPF 程序
4. **安全加固原语**（security hardening primitives）
5. 用于 pin/unpin 对象（例如 map、程序）的**伪文件系统**（`bpffs`），实现持久存储
6. 支持 BPF **offload**（例如 offload 到网卡）的基础设施

LLVM提供了BPF后端（back end），因此使用clang这样的工具可以将c代码编译为BPF对象文件（object file），之后再加载到Linux内核。

使用了BPF的内核子系统也是BPF基础设施的一部分，本文主要讨论tc和XDP。

- XDP BPF程序会被attach到网络驱动的最早阶段，驱动收到包之后就会触发BPF程序的执行。从定义上可以取得最好的包处理性能（已经是软件中最早可以处理包的位置）。在这一步，协议栈还没有从包中提取出元数据（XDP无法使用这些元数据）
- tc BPF程序在内核栈中稍后一些的地方执行，能够访问更多的元数据和一些核心功能。

# 1.1 指令集

## 1.1.1 指令集

BPF是一个通用目的的RISC指令集，其设计目标是

1. 用c语言的一个子集编写程序
2. 用一个编译器后端将其编译成BPF指令
3. 稍后内核通过一个内核中的即时编译器（JIT Compiler）将BPF指令映射成处理器的原生指令，以获得内核中的最佳执行性能

这些指令下放到内核中可以带来如下好处：

- **无需再内核/用户空间切换**就可以实现内核的可编程。例如cilium可以无需将包先送到用户空间，处理后再送回内核，可以通过BPF在内核中实现灵活的容器策略、负载均衡等功能
- **可编程datapath**：程序能在编译时将不需要的特性禁用，从而极大优化程序性能。例如，容器不需要IPv4，那编写BPF程序时就可以只处理IPv6的情况。
- 对于网络场景，BPF程序可以在**无需重启**内核、系统服务或者容器的情况下**实现原子更新**，不会导致网络中断。另外，更新BPF map不会导致程序状态（program state）丢失
- BPF给用户空间提供了稳定的ABI，而且不依赖任何三方内核模块。这种保证和系统调用是同一级别的。并且BPF程序在不同平台是可移植的
- BPF与内核协同工作，可以复用已有的内核基础设施（驱动、netdevice、隧道、协议栈和socket）和工具（iproute2），以及内核提供的安全保障。例如XDP可以复用已有的内核驱动，可以直接操作DMA缓冲区中的数据帧，因此XDP可以复用内核协议而不是绕过。可以将BPF程序看做内核设施的“胶水代码”
- BPF程序由内核中的校验器进行校验，以确保它们不会造成内核崩溃、程序终止等

BPF程序在内核的执行总是**事件驱动**的

- 如果网卡的ingress路径上attach了BPF程序，当网卡收到包后就会触发这个BPF的执行
- 如果有个kprobe探测点的内核地址attach了一段BPF程序后，内核执行到这个地址会发生trap，进而唤醒kprobe的回调函数

## BPF寄存器和调用约定

BPF由下面几部分组成：

1. 11个64位寄存器（包含32位子寄存器）
2. 一个程序计数器
3. 一个512字节大小的BPF栈空间

寄存器的名字从r0到r10。默认以64位运行，32位只能通过特殊的ALU访问

r10是唯一只读寄存器，其中存放的是访问BPF栈空间的栈帧指针地址。其余为通用寄存器

BPF程序可以调用核心内核（并非内核模块）预定义的一些辅助函数。BPF调用约定如下：

- r0存放被调用辅助函数的返回值
- R1-r5 存放BPF调用内核辅助函数时传递的参数
- R6-r9 由被调用方（callee）保存，在函数返回后调用方（caller）可以读取

BPF调用足够通用，能够直接映射到x86_64，arm64和其他ABI，因此所有BPF寄存器可以一一映射到硬件CPU寄存器，JIT只需要发出一条调用指令，而不需要额外的放置函数参数动作。这套约定在不牺牲性能的前提下，考虑了尽可能通用的调用场景（目前不支持6个及以上参数的函数调用）。

r0寄存器还用于保存BPF程序的退出值。退出值的语义由程序类型决定。仅当执行权交回内核时，退出值以32位传递

`r1` - `r5` 寄存器是 **scratch registers**，意思是说，如果要在多次辅助函数调用之 间重用这些寄存器内的值，那 BPF 程序需要负责将这些值临时转储（spill）到 BPF 栈上 ，或者保存到被调用方（callee）保存的寄存器中。**Spilling**（倒出/转储） 的意思是这些寄存器内的变量被移到了 BPF 栈中。相反的操作，即将变量从 BPF 栈移回寄 存器，称为 **filling**（填充）。**spilling/filling 的原因是寄存器数量有限**。

BPF 程序开始执行时，**`r1` 寄存器中存放的是程序的上下文**（context）。上下文就是 **程序的输入参数**（和典型 C 程序的 `argc/argv` 类似）。**BPF 只能在单个上下文中 工作**（restricted to work on a single context）。这个**上下文是由程序类型定义的**， 例如，网络程序可以将**网络包的内核表示（`skb`）**作为输入参数。

**BPF 的通用操作都是 64 位的**，这和默认的 64 位架构模型相匹配，这样可以对指针进 行算术操作，以及在调用辅助函数时传递指针和 64 位值；另外，BPF 还支持 64 位原子操 作。

**每个 BPF 程序的最大指令数限制在 4096 条以内**，这意味着从设计上就可以保证**每 个程序都会很快结束**。**对于内核 5.1+，这个限制放大到了 100 万条**。虽然指令集中包含前向和后向跳转，但内核中的 BPF 校验器禁止 程序中有循环，因此可以永远保证程序会终止。

另外，BPF 中有尾调用的概念，允许一 个 BPF 程序调用另一个 BPF 程序。类似地，这种调用也是有限制的，目前上限是 33 层调 用；现在这个功能常用来对程序逻辑进行解耦，例如解耦成几个不同阶段。

## BPF指令格式

BPF指令格式被建模为两操作数指令，这种格式可以在JIT阶段将BPF指令映射为原生指令。每条指令都是64比特编码的。一条 64 位指令在大端机器上的编码格式如下，从重要性最 高比特（most significant bit，MSB）到重要性最低比特（least significant bit，LSB）：

```
op:8, dst_reg:4, src_reg:4, off:16, imm:32
```

`off` 和 `imm` 都是有符号类型。编码信息定义在内核头文件 `linux/bpf.h` 中，这个头 文件进一步 `include` 了 `linux/bpf_common.h`。

`op` 定了将要执行的操作。`op` 复用了大部分 cBPF 的编码定义。操作可以基于寄存器值 ，也可以基于立即操作数（immediate operands）。`op` 自身的编码信息中包含了应该使 用的模式类型：

- `BPF_X` 指基于寄存器的操作数（register-based operations）
- `BPF_K` 指基于立即操作数（immediate-based operations）

对于后者，目的操作数永远是一个寄存器（destination operand is always a register）。 `dst_reg` 和 `src_reg` 都提供了寄存器操作数（register operands，例如 `r0` - `r9`）的额外信息。在某些指令中，`off` 用于表示一个相对偏移量（offset）， 例如，对那些 BPF 可用的栈或缓冲区（例如 map values、packet data 等等）进行寻 址，或者跳转指令中用于跳转到目标。`imm` 存储一个常量/立即值。

所有的 `op` 指令可以分为若干类别。类别信息也编码到了 `op` 字段。`op` 字段分为（ 从 MSB 到 LSB）：`code:4`, `source:1` 和 `class:3`。

- `class` 是指令类型
- `code` 指特定类型的指令中的某种特定操作码（operational code）
- `source` 可以告诉我们源操作数（source operand）是一个寄存器还是一个立即数

可能的指令类别包括：

- `BPF_LD`, `BPF_LDX`：**加载操作**（load operations）

  - `BPF_LD` 用于加载**double word 长度的特殊指令**（占两个指令长度，源于 `imm:32` 的限制），或byte / half-word / word 长度的**包数据**（packet data ）。后者是从 cBPF 中延续过来的，主要为了保证 cBPF 到 BPF 翻译的高效，因为 这里的 JIT code 是优化过的。对于 native BPF 来说，这些包加载指令在今天已经 用的很少了。
  - `BPF_LDX` 用于从内存中加载 byte / half-word / word / double-word，这里的内 存包括栈内存、map value data、packet data 等等。

- `BPF_ST`, `BPF_STX`：**存储操作**（store operations）

  - `BPF_STX` 与 `BPF_LDX` 相对，将某个寄存器中的值存储到内存中，同样，这里的 内存可以是栈内存、map value、packet data 等等。`BPF_STX` 类包含一些 word 和 double-word 相关的原子加操作，例如，可以用于计数器。
  - `BPF_ST` 类与 `BPF_STX` 类似，提供了将数据存储到内存的操作，只不过其源操作 数（source operand）必须是一个立即值（immediate value）。

- `BPF_ALU`, `BPF_ALU64`：**逻辑运算操作**（ALU operations）

  Generally, `BPF_ALU` operations are in 32 bit mode and `BPF_ALU64` in 64 bit mode. Both ALU classes have basic operations with source operand which is register-based and an immediate-based counterpart. Supported by both are add (`+`), sub (`-`), and (`&`), or (`|`), left shift (`<<`), right shift (`>>`), xor (`^`), mul (`*`), div (`/`), mod (`%`), neg (`~`) operations. Also mov (`<X> := <Y>`) was added as a special ALU operation for both classes in both operand modes. `BPF_ALU64` also contains a signed right shift. `BPF_ALU` additionally contains endianness conversion instructions for half-word / word / double-word on a given source register.

- `BPF_JMP`：**跳转操作**（jump operations）

  Jumps can be unconditional and conditional. Unconditional jumps simply move the program counter forward, so that the next instruction to be executed relative to the current instruction is `off + 1`, where `off` is the constant offset encoded in the instruction. Since `off` is signed, the jump can also be performed backwards as long as it does not create a loop and is within program bounds. Conditional jumps operate on both, register-based and immediate-based source operands. If the condition in the jump operations results in `true`, then a relative jump to `off + 1` is performed, otherwise the next instruction (`0 + 1`) is performed. This fall-through jump logic differs compared to cBPF and allows for better branch prediction as it fits the CPU branch predictor logic more naturally. Available conditions are jeq (`==`), jne (`!=`), jgt (`>`), jge (`>=`), jsgt (signed `>`), jsge (signed `>=`), jlt (`<`), jle (`<=`), jslt (signed `<`), jsle (signed `<=`) and jset (jump if `DST & SRC`). Apart from that, there are three special jump operations within this class: the exit instruction which will leave the BPF program and return the current value in `r0` as a return code, the call instruction, which will issue a function call into one of the available BPF helper functions, and a hidden tail call instruction, which will jump into a different BPF program.

**Linux 内核中内置了一个 BPF 解释器**，该解释器能够执行由 BPF 指令组成的程序。即 使是 cBPF 程序，也可以在内核中透明地转换成 eBPF 程序，除非该架构仍然内置了 cBPF JIT，还没有迁移到 eBPF JIT。

**所有的 BPF 操作**，例如加载程序到内核，或者创建 BPF map， **都是通过核心的 `bpf()` 系统调用完成的**。它还用于管理 map 表项（查 找/更新/删除），以及通过 pinning 将程序和 map 持久化到 BPF 文件系统。

## 辅助函数

辅助函数使得BPF能够通过一组内核定义的函数调用从内核查询数据，或者将数据推送到内核。不同类型的BPF程序能够使用的辅助函数可能是不同的。例如与attach到tc层的BPF程序想比，attach到socket的BPF程序只能够调用前者可以调用的辅助函数的子集。轻量级隧道（lightweight tunneling）使用的封装和解封装（Encapsulation and decapsulation）辅助函数，只能被更低的tc层使用，而推送通知到用户态所使用的事件输出辅助函数，既可以被tc程序使用，也可以被XDP函数使用

**所有的辅助函数都共享同一个通用的、和系统调用类似的函数签名**。签名定义如下：

```
u64 fn(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
```

内核将辅助函数抽象成 `BPF_CALL_0()` 到 `BPF_CALL_5()` 几个宏，形式和相应类型的系 统调用类似。下面的例子是从某个辅助函数中抽取出来的，可以看到它通过调用相应 map 的回调函数完成更新 map 元素的操作：

```
BPF_CALL_4(bpf_map_update_elem, struct bpf_map *, map, void *, key,
           void *, value, u64, flags)
{
    WARN_ON_ONCE(!rcu_read_lock_held());
    return map->ops->map_update_elem(map, key, value, flags);
}

const struct bpf_func_proto bpf_map_update_elem_proto = {
    .func           = bpf_map_update_elem,
    .gpl_only       = false,
    .ret_type       = RET_INTEGER,
    .arg1_type      = ARG_CONST_MAP_PTR,
    .arg2_type      = ARG_PTR_TO_MAP_KEY,
    .arg3_type      = ARG_PTR_TO_MAP_VALUE,
    .arg4_type      = ARG_ANYTHING,
};
```

这种方式有很多优点：虽然 cBPF 允许其加载指令（load instructions）进行 **超出范围的访问**（overload），以便从一个**看似不可能的包偏移量**（packet offset，负的）位置 获取数据以唤醒多功能辅助函数，但每个 cBPF JIT 仍然需要为这个 cBPF extension 实现对应的支持。

而在 eBPF 中，JIT 编译器会以一种透明和高效的方式编译新加入的辅助函数，这意味着 JIT 编 译器只需要发射（emit）一条调用指令（call instruction），因为寄存器映射的方式使得 BPF 排列参数的方式（assignments）已经和底层架构的调用约定相匹配了。这使得基于辅 助函数扩展核心内核（core kernel）非常方便。**所有的 BPF 辅助函数都是核心内核的一部分**， 无法通过内核模块（kernel module）来扩展或添加。

前面提到的函数签名还允许校验器执行类型检测（type check）。上面的 `struct bpf_func_proto` 用于存放**校验器必需知道的所有关于该辅助函数的信息**，这 样校验器可以确保辅助函数期望的类型和 BPF 程序寄存器中的当前内容是匹配的。

参数类型范围很广，从任意类型的值，到限制只能为特定类型，例如 BPF 栈缓冲区（stack buffer）的 `pointer/size` 参数对，辅助函数可以从这个位置读取数据或向其写入数据。 对于这种情况，校验器还可以执行额外的检查，例如，缓冲区是否已经初始化过了。

**当前可用的 BPF 辅助函数已经有几十个，并且数量还在不断增加**，例如，写作本文时，tc BPF 程序可以使用38 种不同的 BPF 辅助函数。对于一个给定的 BPF 程序类型，内核的 `struct bpf_verifier_ops` 包含了 `get_func_proto` 回调函数，这个函数提供了从某个 特定的`enum bpf_func_id` 到一个可用的辅助函数的映射。

## Maps

![img](https://arthurchiao.art/assets/img/cilium-bpf-xdp-guide/bpf_map.png)

map是驻留在内核空间的高效键值存储。map中的数据可以被BPF程序访问。如果想在多次BPF程序调用之间保存状态，可以将状态信息放到map。map还可以从用户空间通过文件描述符进行访问，可以在任意BPF程序以及用户空间之间共享。

共享map的BPF程序不要求是相同的程序类型。单个BPF程序最多可以直接访问64个不同map

map的实现由核心内核提供，有per-CPU以及non-perCPU的通用map，这些map可以读、写任意数据，也有一些和辅助函数一起使用的非通用map。

当前可用的 **通用 map** 有：

- `BPF_MAP_TYPE_HASH`
- `BPF_MAP_TYPE_ARRAY`
- `BPF_MAP_TYPE_PERCPU_HASH`
- `BPF_MAP_TYPE_PERCPU_ARRAY`
- `BPF_MAP_TYPE_LRU_HASH`
- `BPF_MAP_TYPE_LRU_PERCPU_HASH`
- `BPF_MAP_TYPE_LPM_TRIE`

以上 map 都使用相同的一组 BPF 辅助函数来执行查找、更新或删除操作，但各自实现了不 同的后端，这些后端各有不同的语义和性能特点。

当前内核中的 **非通用 map** 有：

- `BPF_MAP_TYPE_PROG_ARRAY`
- `BPF_MAP_TYPE_PERF_EVENT_ARRAY`
- `BPF_MAP_TYPE_CGROUP_ARRAY`
- `BPF_MAP_TYPE_STACK_TRACE`
- `BPF_MAP_TYPE_ARRAY_OF_MAPS`
- `BPF_MAP_TYPE_HASH_OF_MAPS`

例如，`BPF_MAP_TYPE_PROG_ARRAY` 是一个数组 map，用于持有（hold）其他的 BPF 程序 。`BPF_MAP_TYPE_ARRAY_OF_MAPS` 和 `BPF_MAP_TYPE_HASH_OF_MAPS` 都用于持有（hold） 其他 map 的指针，这样**整个 map 就可以在运行时实现原子替换**。这些类型的 map 都针对 特定的问题，不适合单单通过一个 BPF 辅助函数实现，因为它们需要在各次 BPF 程序调用 （invoke）之间时保持额外的（非数据）状态。

## 钉住对象（Object Pinning）

![img](https://arthurchiao.art/assets/img/cilium-bpf-xdp-guide/bpf_fs.png)

**BPF map 和 BPF program** 作为内核资源**只能通过文件描述符访问**， 其背后是内核中的**匿名 inode**。这有很多好处，例如：

- 用户空间应用能够使用大部分文件描述符相关的 API，
- 在 Unix socket 中传递文件描述符是透明的，等等。

但同时，也有很多缺点：**文件描述符受限于进程的生命周期**，使得 map 共享之类的操作非常笨重。

因此，这给某些特定的场景带来了很多复杂性，例如 iproute2，其中的 tc 或 XDP 在准备 环境、加载程序到内核之后最终会退出。在这种情况下，从用户空间也无法访问这些 map 了，而本来这些 map 其实是很有用的，例如，在 data path 的 ingress 和 egress 位置共 享的 map（可以统计包数、字节数、PPS 等信息）。另外，第三方应用可能希望在 BPF 程 序运行时监控或更新 map。

**为了解决这个问题，内核实现了一个最小内核空间 BPF 文件系统，BPF map 和 BPF 程序 都可以钉到（pin）这个文件系统内**，这个过程称为 object pinning（钉住对象）。相应 地，BPF 系统调用进行了扩展，添加了两个新命令，分别用于钉住（`BPF_OBJ_PIN`）一个 对象和获取（`BPF_OBJ_GET`）一个被钉住的对象（pinned objects）。

例如，tc 之类的工具可以利用这个基础设施在 ingress 和 egress 之间共享 map。BPF 相关的文件系统**不是单例模式**（singleton），它**支持多挂载实例、硬链接、软连接**等等。

## 尾调用（Tail Calls）

![img](https://arthurchiao.art/assets/img/cilium-bpf-xdp-guide/bpf_tailcall.png)

BPF 相关的另一个概念是尾调用（tail calls）。尾调用的机制是：一个 BPF 程序可以调 用另一个 BPF 程序，并且调用完成后不用返回到原来的程序。和普通函数调用相比，这种 调用方式开销最小，因为它是**用长跳转（long jump）实现的，复用了原来的栈帧** （stack frame）。

BPF 程序都是独立验证的，因此要传递状态，要么使用 per-CPU map 作为 scratch 缓冲区 ，要么如果是 tc 程序的话，还可以使用 `skb` 的某些字段（例如 `cb[]`）。

**类型相同的 BPF 程序才可以尾调用**，而且还要与 JIT 编译器相匹配， 因此一个给定的 BPF 程序 要么是 JIT编译执行，要么是解释器执行（invoke interpreted programs），而不能同时使用两种方式。

尾调用执行涉及**两个步骤**：

1. **设置一个称为“程序数组”（program array）的特殊 map**（map 类型 `BPF_MAP_TYPE_PROG_ARRAY` ），这个 map 可以从用户空间通过 key/value 操作，
2. **调用辅助函数 bpf_tail_call()**。两个参数：一个对程序数组的引用（a reference to the program array），一个查询 map 所用的 key。内核将这个辅助函数调用内联（ inline）到一个特殊的 BPF 指令内。目前，这样的程序数组在用户空间侧是只写模式（ write-only from user space side）。

内核根据传入的文件描述符查找相关的 BPF 程序，自动替换给定的 map slot（槽） 处的 程序指针。如果没有找到给定的 key 对应的 value，内核会跳过（fall through）这一步 ，继续执行 `bpf_tail_call()` 后面的指令。**尾调用是一个强大的功能，例如，可以通 过尾调用结构化地解析网络头**（network headers）。还可以在运行时（runtime）原子地 添加或替换功能，即，动态地改变 BPF 程序的执行行为。

## BPF to BPF Calls

![img](https://arthurchiao.art/assets/img/cilium-bpf-xdp-guide/bpf_call.png)

除了 BPF 辅助函数和 BPF 尾调用之外，BPF 核心基础设施最近刚加入了一个新特性：BPF 到 BPF 调用（BPF to BPF calls）。**在这个特性引入内核之前，典型的 BPF C 程序必须 将所有需要复用的代码进行特殊处理，例如，在头文件中声明为 `always_inline`**。当 LLVM 编译和生成 BPF 对象文件时，所有这些函数将被内联，因此会在生成的对象文件中重 复多次，导致代码尺寸膨胀：

```
#include <linux/bpf.h>

#ifndef __section
# define __section(NAME)                  \
   __attribute__((section(NAME), used))
#endif

#ifndef __inline
# define __inline                         \
   inline __attribute__((always_inline))
#endif

static __inline int foo(void)
{
    return XDP_DROP;
}

__section("prog")
int xdp_drop(struct xdp_md *ctx)
{
    return foo();
}

char __license[] __section("license") = "GPL";
```

之所以要这样做是因为 **BPF 程序的加载器、校验器、解释器和 JIT 中都缺少对函数调用的 支持**。从 `Linux 4.16` 和 `LLVM 6.0` 开始，这个限制得到了解决，BPF 程序不再需 要到处使用 `always_inline` 声明了。因此，上面的代码可以更自然地重写为：

```
#include <linux/bpf.h>

#ifndef __section
# define __section(NAME)                  \
   __attribute__((section(NAME), used))
#endif

static int foo(void)
{
    return XDP_DROP;
}

__section("prog")
int xdp_drop(struct xdp_md *ctx)
{
    return foo();
}

char __license[] __section("license") = "GPL";
```

BPF 到 BPF 调用是一个重要的性能优化，极大减小了生成的 BPF 代码大小，因此**对 CPU 指令缓存（instruction cache，i-cache）更友好**。

BPF 辅助函数的调用约定也适用于 BPF 函数间调用，即 `r1` - `r5` 用于传递参数，返回 结果放到 `r0`。`r1` - `r5` 是 scratch registers，`r6` - `r9` 像往常一样是保留寄 存器。最大嵌套调用深度是 `8`。调用方可以传递指针（例如，指向调用方的栈帧的指针） 给被调用方，但反过来不行。

BPF JIT 编译器为每个函数体发射独立的镜像（emit separate images for each function body），稍后在最后一通 JIT 处理（final JIT pass）中再修改镜像中函数调用的地址 。已经证明，这种方式需要对各种 JIT 做最少的修改，因为在实现中它们可以将 BPF 函数 间调用当做常规的 BPF 辅助函数调用。

内核 5.9 版本之前，**BPF 尾调用和 BPF-to-BPF 调用是互斥的**，只能二选一。 尾调用的缺点是生成的程序镜像大、加载时间长。 **内核 5.10 最终解决了这一问题**，允许同时使用者两种调用类型，充分利用二者各自的优点。

但混合使用者两种调用类型是有限制的，否则会导致内核栈溢出（kernel stack overflow）。 来看下面的例子：

![img](https://arthurchiao.art/assets/img/cilium-bpf-xdp-guide/bpf_tailcall_subprograms.png)

如上图所示，尾调用在真正跳转到目标程序（`func3`）之前，只会展开（unwind）它当前 所处层级的栈帧（stack frame）。也就是说，如果尾调用是从某个子函数发起的（occurs from within the sub-function），例如 `subfunc1 --tailcall--> func2`，那当程序在执行 `func2` 时， 所有 `subfunc1` 之前的栈帧（在这里是 `func1` 的栈帧）都会出现在栈上。只有当最后 一个函数（这里是 `func3`）执行结束时，所有前面的栈帧才将被展开（unwinded），然后控制返回 到 BPF 程序的调用者（BPF program caller）。

内核引入了额外的逻辑来检测这种混用的情况。整个调用链中， **每个子程序的栈空间不能超过 256 字节**（如果校验器检测到 bpf2bpf 调用，那主函数也会被当做 子函数）。有了这个限制，**BPF 程序调用链最多能使用 8KB 的栈空间**，计算方式：256 byte/stack 乘以尾调用数量上限 33。如果没有这个限制，BPF 程序将使用 512 字节栈空 间，最终消耗最多 16KB 的总栈空间，在某些架构上会导致栈溢出。

## JIT

![img](https://arthurchiao.art/assets/img/cilium-bpf-xdp-guide/bpf_jit.png)

64 位的 `x86_64`、`arm64`、`ppc64`、`s390x`、`mips64`、`sparc64` 和 32 位的 `arm` 、`x86_32` 架构都内置了 in-kernel eBPF JIT 编译器，它们的功能都是一样的，可 以用**如下方式打开**：

```
echo 1 > /proc/sys/net/core/bpf_jit_enable
```

JIT 编译器可以极大加速 BPF 程序的执行，因为与解释器相比，它们可以降低每个指令的 开销（reduce the per instruction cost）。通常，指令可以 1:1 映射到底层架构的原生 指令。另外，这也会减少生成的可执行镜像的大小，因此对 CPU 的指令缓存更友好。特别 地，对于 CISC 指令集（例如 `x86`），JIT 做了很多特殊优化，目的是为给定的指令产生 可能的最短操作码（emitting the shortest possible opcodes），以降低程序翻译过程所 需的空间。

## 加固（Hardening）

为了避免代码被损坏，BPF 会在程序的生命周期内，在内核中**将下面两个镜像锁定为只读的**（read-only）：

- 经过 BPF 解释器**解释（翻译）之后的整个镜像**（`struct bpf_prog`）
- **JIT 编译之后的镜像**（`struct bpf_binary_header`）。

在这些位置发生的任何数据损坏（例如某些内核 bug 导致的）会触发通用的保护机制，因 此会造成内核崩溃（crash），而不会让这种损坏静默地发生。

当前，启用加固会在 JIT 编译时**盲化**（blind）BPF 程序中用户提供的所有 32 位和 64 位常量，以防御 **JIT spraying（喷射）攻击**，这些攻击会将原生操作码（native opcodes）作为立即数（immediate values）注入到内核。这种攻击有效是因为：**立即数 驻留在可执行内核内存（executable kernel memory）中**，因此某些内核 bug 可能会触 发一个跳转动作，如果跳转到立即数的开始位置，就会把它们当做原生指令开始执行。

盲化 JIT 常量通过对真实指令进行随机化（randomizing the actual instruction）实现 。在这种方式中，通过对指令进行重写（rewriting the instruction），将原来**基于立 即数的操作**转换成**基于寄存器的操作**。指令重写将加载值的过程分解为两部分：

1. 加载一个盲化后的（blinded）立即数 `rnd ^ imm` 到寄存器
2. 将寄存器和 `rnd` 进行异或操作（xor）

这样原始的 `imm` 立即数就驻留在寄存器中，可以用于真实的操作了。这里介绍的只是加 载操作的盲化过程，实际上所有的通用操作都被盲化了。

## Offloads

![img](https://arthurchiao.art/assets/img/cilium-bpf-xdp-guide/bpf_offload.png)

BPF 网络程序，尤其是 tc 和 XDP BPF 程序在内核中都有一个 offload 到硬件的接口，这 样就可以直接在网卡上执行 BPF 程序。

当前，Netronome 公司的 `nfp` 驱动支持通过 JIT 编译器 offload BPF，它会将 BPF 指令 翻译成网卡实现的指令集。另外，它还支持将 BPF maps offload 到网卡，因此 offloaded BPF 程序可以执行 map 查找、更新和删除操作。

# 工具链



## XDP工作模式

XDP 总共支持三种工作模式（operation mode）

- `xdpdrv`

  `xdpdrv` 表示 **native XDP**（原生 XDP）, 意味着 BPF 程序**直接在驱动的接收路 径上运行**，理论上这是软件层最早可以处理包的位置（the earliest possible point）。这是**常规/传统的 XDP 模式，需要驱动实现对 XDP 的支持**，目前 Linux 内核中主流的 10G/40G 网卡都已经支持。

- `xdpgeneric`

  `xdpgeneric` 表示 **generic XDP**（通用 XDP），用于给那些还没有原生支持 XDP 的驱动进行试验性测试。generic XDP hook 位于内核协议栈的主接收路径（main receive path）上，接受的是 `skb` 格式的包，但由于 **这些 hook 位于 ingress 路径的很后面**，因此与 native XDP 相比性能有明显下降。因 此，`xdpgeneric` 大部分情况下只能用于试验目的，很少用于生产环境。

- `xdpoffload`

  最后，一些智能网卡（例如支持 Netronome’s nfp 驱动的网卡）实现了 `xdpoffload` 模式 ，允许将整个 BPF/XDP 程序 offload 到硬件，因此程序在网卡收到包时就直接在网卡进行 处理。这提供了比 native XDP 更高的性能，虽然在这种模式中某些 BPF map 类型 和 BPF 辅助函数是不能用的。BPF 校验器检测到这种情况时会直 接报错，告诉用户哪些东西是不支持的。除了这些不支持的 BPF 特性之外，其他方面与 native XDP 都是一样的。

执行 `ip link set dev em1 xdp obj [...]` 命令时，内核会**先尝试以 native XDP 模式加载程序，如果驱动不支持再自动回退到 generic XDP 模式**。**无法原子地在不同 XDP 模式之间切换**，例如从 generic 模式切换到 native 模式。

## 加载 tc BPF 对象文件

给定一个为 tc 编译的 BPF 对象文件 `prog.o`， 可以通过 `tc` 命令将其加载到一个网 络设备（netdevice）。但**与 XDP 不同，设备是否支持 attach BPF 程序并不依赖驱动** （即**任何网络设备都支持 tc BPF**）。下面的命令可以将程序 attach 到 `em1` 的 `ingress` 网络：

```
$ tc qdisc add dev em1 clsact
$ tc filter add dev em1 ingress bpf da obj prog.o
```

第一步创建了一个 `clsact` qdisc (Linux 排队规则，Linux **queueing discipline**)。

1. `clsact` 是一个 **dummy qdisc**，和 `ingress` qdisc 类似，用于 **持有（hold）分类器和动作**（classifier and actions），但 **不执行真正的排队**（queueing）。后面 attach `bpf` 分类器需要用到它。
2. `clsact` qdisc 提供了**两个特殊的 hook**：`ingress` and `egress`，分类器可以 attach 到这两个 hook 点。这两个 hook 都位于 datapath 的关键收发路径上，设备 `em1` 的每个包都会经过这两个点。二者的内核调用路径：
   - `ingress` hook：**`__netif_receive_skb_core() -> sch_handle_ingress()`**
   - `egress` hook：**`__dev_queue_xmit() -> sch_handle_egress()`**
3. 类似地，将程序 attach 到 `egress` hook 的命令：`tc filter add dev em1 egress bpf da obj prog.o`
4. `clsact` qdisc **在 ingress 和 egress 方向以无锁（lockless）方式执行**， 而且可以 attach 到**虚拟的、无队列的设备**（virtual, queue-less devices），例如连接容器和宿主机的 **veth 设备**。

第二条命令，`tc filter` 选择了在 **`da`**（direct-action）模式中使用 `bpf`。`da` 是 推荐的模式，并且应该永远指定这个参数。简单来说，`da` 模式表示 **bpf 分类器不需要调用外部的 tc action 模块**。 事实上 `bpf` 分类器也完全不需要调用外部模块，因为所有的 packet mangling、 转发或其他类型的 action 都可以在这单个 BPF 程序内完成，因此执行会明显更快。

> 更多关于 da 模式的信息，可参考： [(译) 深入理解 tc ebpf 的 direct-action (da) 模式（2020）](https://arthurchiao.art/blog/understanding-tc-da-mode-zh/) 译注。

配置了这两条命令之后，程序就 attach 完成了，接下来只要有包经过这个设备，就会触发 这个程序执行。和 XDP 类似，如果没有使用默认 section 名字，那可以在加载时指定，例 如指定 section 为 `foobar`：

# BPF程序类型

## XDP

XDP（eXpress Data Path）提供了一个**内核态、高性能、可编程 BPF 包处理框架**（a framework for BPF that enables high-performance programmable packet processing in the Linux kernel）。这个框架在软件中最早可以处理包的位置（即网卡驱动收到包的 时刻）运行 BPF 程序。

XDP hook 位于网络驱动的快速路径上，XDP 程序直接从接收缓冲区（receive ring）中将 包拿下来，无需执行任何耗时的操作，例如分配 `skb` 然后将包推送到网络协议栈，或者 将包推送给 GRO 引擎等等。因此，只要有 CPU 资源，XDP BPF 程序就能够在最早的位置执 行处理。

XDP 和 Linux 内核及其基础设施协同工作，这意味着 **XDP 并不会绕过（bypass）内核** ；作为对比，很多完全运行在用户空间的网络框架（例如 DPDK）是绕过内核的。将包留在 内核空间可以带来几方面重要好处：

- XDP可以复用所有上游开发的内核网络驱动，用户空间工具，以及其他可用的内核设施，例如调用BPF辅助函数时，可以使用系统路由表、socket等
- 由于驻留内核/用户空间边界，XDP访问硬件时与内核其他部分有相同的安全模型。
- 无需跨内核/用户空间边界，因为被处理的包已经在内核中，可以灵活地将其转发到内核的其他实体，例如容器的命名空间或内核网络栈自身
- 将包从XDP发送到内核中非常简单，可以复用内核中这个健壮、高效、使用广泛的 TCP/IP **协议栈**，而不是像一些用户态框架一样需要自己维护一个独立的 TCP/IP 协 议栈。
- 基于 BPF 可以**实现内核的完全可编程**，保持 ABI 的稳定，保持内核的系统调用 ABI “永远不会破坏用户空间的兼容性”（never-break-user-space）的保证。而且，**与内核 模块（modules）方式相比，它还更加安全**，这来源于 BPF 校验器，它能保证内核操作 的稳定性。
- XDP 轻松地**支持在运行时（runtime）原子地创建（spawn）新程序，而不会导致任何网 络流量中断**，甚至不需要重启内核/系统。
- XDP 允许对负载进行灵活的结构化（structuring of workloads），然后集成到内核。例 如，它可以工作在**“不停轮询”（busy polling）或“中断驱动”（interrupt driven）模 式**。不需要显式地将专门 CPU 分配给 XDP。没有特殊的硬件需求，它也不依赖 hugepage（大页）。
- XDP **不需要任何第三方内核模块或许可**（licensing）。它是一个长期的架构型解决 方案（architectural solution），**是 Linux 内核的一个核心组件，而且是由内核社 区开发**的。
- 作为一个**在驱动中运行 BPF 的框架**，XDP 还保证了**包是线性放置并且可以匹配到单 个 DMA 页面**，这个页面对 BPF 程序来说是可读和可写的。

## tc

从高层看，tc BPF 程序和 XDP BPF 程序有三点主要不同：

#### 1. 输入上下文

**BPF 的输入上下文（input context）是一个 `sk_buff` 而不是 `xdp_buff`**。当内核 协议栈收到一个包时（说明包通过了 XDP 层），它会分配一个缓冲区，解析包，并存储包 的元数据。表示这个包的结构体就是 `sk_buff`。这个结构体会暴露给 BPF 输入上下文， 因此 tc ingress 层的 BPF 程序就可以利用这些（由协议栈提取的）包的元数据。这些元 数据很有用，但在包达到 tc 的 hook 点之前，**协议栈执行的缓冲区分配、元数据提取和 其他处理等过程也是有开销的**。从定义来看，`xdp_buff` 不需要访问这些元数据，因为 **XDP hook 在协议栈之前就会被调用。这是 XDP 和 tc hook 性能差距的重要原因之一**。

#### 2. hook 触发点

tc BPF 程序在数据路径上的 ingress 和 egress 点都可以触发；而 **XDP BPF 程序只能在 ingress 点触发**（不支持 egress XDP）。

内核两个 hook 点：

1. ingress hook `sch_handle_ingress()`：由 **`__netif_receive_skb_core()`** 触发
2. egress hook `sch_handle_egress()`：由 **`__dev_queue_xmit()`** 触发

`__netif_receive_skb_core()` 和 `__dev_queue_xmit()` 是 **datapath 的主要收包/发包函数**， 不考虑 XDP 的话（XDP 可能会拦截或修改，导致不经过这两个 hook 点）， **每个进入或离开系统的包都会经过这两个点**，从而使得 **tc BPF 程序具备完全可观测性**。

#### 3. 是否依赖驱动支持

**tc BPF 程序不需要驱动做任何改动**，因为它们运行在**网络栈通用层**中的 hook 点。 因此，它们**可以 attach 到任何类型的网络设备上**。