# 11_angr_sim_scanf：为什么要自己接管 scanf（外设/库函数建模的一般动机）

本关的关键认识：很多真实程序都会通过“外设/库函数”把外部世界引入到执行当中（例如标准输入、时间/随机数、系统调用、文件/网络等）。对于符号执行而言，默认建模往往不满足你的具体目标（精度、可控性、性能），这时就需要“在边界处自己建模”。本关以 `scanf("%u %u", &a, &b)` 为例：我们希望直接得到两个独立的 32-bit 符号整数并写回传入的指针地址，而不是依赖输入流解析的细节。angr 对 scanf 的多输出格式并非通用支持，因此采用自定义 SimProcedure 替换 `__isoc99_scanf` 是一种更稳、更可复用的方案。

与第 08 关（后置约束）、第 10 关（SimProcedure 替换字符串比较）的经验联动起来看：本关强调“在 I/O 边界处做统一建模”。而第 04 关展示了“在中段逻辑里补丁式地填值”的思路，它适用于单次、可控的输入点；当输入点分散且出现多次时，更推荐在函数边界统一替换。


## 1. 最小实现：用 SimProcedure 接管 `__isoc99_scanf`

目标：当程序调用 `__isoc99_scanf("%u %u", &out0, &out1)` 时，我们生成两个 32-bit 符号变量，按正确字节序写回到这两个地址，并把这两个符号变量“存档”，方便结尾时直接求解。

示例（与 scaffold/solutions 一致，补充必要注释）：

```python
import angr
import claripy

class ReplacementScanf(angr.SimProcedure):
    # 对应 scanf("%u %u", &a, &b)
    # 形参顺序：格式串指针 + 第一个输出地址 + 第二个输出地址
    def run(self, fmt_ptr, out0_addr, out1_addr):
        # 32-bit 无符号整数 → 4 字节 → 32 位
        scanf0 = claripy.BVS('scanf0', 32)
        scanf1 = claripy.BVS('scanf1', 32)

        # 写回内存（大小端与架构一致）
        self.state.memory.store(out0_addr, scanf0, endness=self.state.arch.memory_endness)
        self.state.memory.store(out1_addr, scanf1, endness=self.state.arch.memory_endness)

        # 存档原始符号变量，方便收尾时直接 solver.eval
        self.state.globals['solution0'] = scanf0
        self.state.globals['solution1'] = scanf1

# 按符号名统一替换整个函数（所有调用点生效）
project.hook_symbol('__isoc99_scanf', ReplacementScanf())
```

要点：
- 不必解析 `fmt_ptr`（本关默认是 `"%u %u"`）。如果格式更复杂再扩展。
- 位宽=32、endness 使用 `state.arch.memory_endness`。
- 若存在多次 scanf，需要避免命名冲突（见下方“多次调用”的建议）。


## 1.5 还有哪些典型“必须/通常要 hook/替换”的边界？
下面列出更广义的“需要自定义建模”的高频样例；它们不是必须用 SimProcedure，也可用普通 hook/符号数据注入，取决于你的目标与维护成本：
- 随机与时间源：
  - rand/srand、random/drand48、/dev/urandom、time/gettimeofday/clock_gettime、RDTSC、CPUID 等
- 环境与进程信息：
  - getenv/putenv/setenv、getpid/getppid/getuid、命令行参数 argc/argv、工作目录、locale 等
- 文件与网络 I/O：
  - open/read/write/close、stat/fstat、mmap/munmap、ioctl
  - socket/recv/send/recvfrom/sendto、connect/accept、getaddrinfo
- 标准库解析类接口（格式化/文本到数值）：
  - scanf/sscanf/fscanf、strtol/strtoul/atoi/atol、strtod
- 加密/校验与不可逆黑盒：
  - MD5/SHA*/HMAC/CRC/自定义校验过程（通常以“返回期望结果”或“约束输出”为目的建模）
- 平台/硬件依赖：
  - 特定 syscalls、TLS/线程本地存储、信号、原子操作、内存映射外设寄存器等
- 非确定性或副作用密集的库：
  - 随机容器打乱、排序比较器调用次数依赖输入、日志/错误路径（errno）等

这些边界的共同点：默认建模可能不满足你的约束表达或性能需求；自定义建模能把问题“转译”为对你可控的符号变量与关系。

## 2. 与第 04 关“符号化栈”的关键差异：为何本关应避免 04 的做法

第 04 关的思路是“从 scanf 之后的指令开始执行 + 伪造栈帧 + 直接把两个 BVS 写到局部变量位置（如 [ebp-0xc]、[ebp-0x10]）”。这种做法依赖“单次 scanf 在一段局部逻辑之前”，适合绕开一次性 I/O。

本关的不同点在于：程序中存在“多个双参数 scanf 调用，且调用之间还有逻辑”。若沿用 04 的做法：
- 你要么从第一处 scanf 之后“start”，从而跳过第一处 scanf 之前的流程，且后续仍可能遇到新的 scanf（未被建模），造成缺口；
- 要么需要在每一处 scanf 之后都“择点 start”，这既不现实，也容易遗漏路径条件，难以保证一致性。

替代但更麻烦的选择：使用类似第 9 关（09_angr_hooks）的方式，hook 所有“调用 scanf 的 Callers”，在每个调用点为两个输出地址写入 BVS。这在工程上可行，但维护成本高，且容易漏掉新的调用点。

权衡建议：
- 多处 I/O 分散、希望“一次性覆盖所有调用点”时：优先在函数边界统一替换（按符号名 hook SimProcedure），可复用、维护性好。
- 单点且可控的输入、希望越过部分流程（或需要在函数中段起步）：可采用第 04 关的“中段补丁式”做法，但要确保不遗漏后续 I/O。
- 需要细粒度改变控制流（禁用检查、强制跳转、在 call-site 层面插桩）：可考虑普通 hook 在各调用点处理，工程成本更高但自由度最大。
- 工程实践中常混用：边界替换作为“通用覆盖”，个别点按需补充 call-site hook。


## 3. 为什么使用 `state.globals`？什么时候用？优缺点与替代方案

目的：保留对“原始符号变量”的直接引用，便于在“最终求解/打印解”时无需再追溯地址与拷贝链条。

什么时候用（推荐场景）：
- 当存在多次调用 `__isoc99_scanf` 时，需要为每次调用保留独立引用，避免覆盖/混淆，并便于统一收尾；
- 值在执行过程中可能被复制/变换，收尾时按地址 `load` 容易不精确或需要复杂反查；
- 想把“如何找到这些输入”的复杂度前置在 SimProcedure 中，收尾时只关心求解与打印。

备注（关于本仓 scaffold）：示例用固定键 `solution0/solution1` 保存一对 BVS，这在仅一次 scanf 或后续逻辑只读取这一对值时足够；但若程序会多次调用 scanf，建议改为“列表/字典”组织（见下节），否则后次调用会覆盖前次结果，存在风险。
跨章指引：对于 scanf/printf/snprintf 等可变参数函数在不同调用点的“参数个数/类型/语义差异”，以及“是否符号化”的差异化处理，参见第 10 章中“可变参数/多样原型的影响与差异化策略”。实践中建议采用“格式串驱动 + 可具体性判定 + prefer-concrete 原则”的组合，确保符号化只在必要时引入。

优点：
- 与二进制布局/时序解耦，直接对 BVS 调用 `solver.eval`；
- 多次调用可用分层结构组织，如 `state.globals['scanf'][i] = (a_bv, b_bv)`，更清晰。

缺点：
- `globals` 是“旁路存储”，不属于目标程序语义；过度使用会“污染”状态，需要规范命名与最小化存储；
- BVS 很多时会产生调试噪音（建议统一命名、按需清理）。

替代方案：
- 收尾直接按地址 `memory.load`：当你确信输出地址稳定、未被后续覆盖/迁移时可行。为降低收尾复杂度，也可仅把“地址”存到 `globals`，末尾按地址加载。
- 自定义轻量插件：当需要跨模块共享结构化上下文时可以考虑，但本关不建议引入该复杂度。
- 让过程“返回”信息：对 scanf 这类“输出经由指针”的函数不适用；更适合返回语义简单的函数。

实践建议：
- 输入点多、控制流深、地址不稳定或值会被中途复制时，优先保存 BVS 到 `globals`；
- 仅一次输入且地址稳定时，收尾按地址 `load` 即可（可把地址本身存档到 `globals` 以减少查找开销）。


## 4. 多次调用与命名策略

当存在多次 `scanf("%u %u", ...)` 调用时：
- 使用计数器生成唯一变量名：`scanf0_0/scanf0_1`, `scanf1_0/scanf1_1`, ...
- 或在 `globals` 中组织为列表/字典：
  ```python
  self.state.globals.setdefault('scanf', [])
  self.state.globals['scanf'].append((scanf0, scanf1))
  ```
  或使用字典按调用序号键控：
  ```python
  idx = self.state.globals.get('scanf_count', 0)
  self.state.globals.setdefault('scanf_by_idx', {})
  self.state.globals['scanf_by_idx'][idx] = (scanf0, scanf1)
  self.state.globals['scanf_count'] = idx + 1
  ```
- 收尾时按顺序取回并 `solver.eval`。这样更不易覆盖、也方便定位是第几次输入（或根据字典键选择性读取）。


## 5. 与“普通 hook / 后置约束”的简要对比

- 普通 hook：自由度最高，可以直接改变控制流或跳过检查；若你的目标是“统一替换 scanf 的输入建模”，SimProcedure 更规范、低维护。
- 后置约束：适用于“到检查点再绑定条件”；但不论如何，首先要把“输入”稳健地做成符号（本关仍推荐在 scanf 边界替换来完成这一步）。


## 6. 常见坑与建议（与本关强相关）

- 位宽与大小端：无符号 32-bit → `claripy.BVS(..., 32)`；`endness=self.state.arch.memory_endness`。
- 多次调用避免覆盖：命名或 `globals` 组织要清晰。
- 不必解析格式串：默认假设 `"%u %u"`；若格式复杂，再扩展 `run()` 逻辑。
- 替换粒度：优先 `project.hook_symbol('__isoc99_scanf', ReplacementScanf())`，覆盖所有调用点，避免漏挂。
- 平台差异：若目标平台/构建差异导致符号名称不同（不叫 `__isoc99_scanf`），请先用反汇编/符号表确认再替换。

——

本关的 takeaway：把“外设/库函数”视为“程序与外界的边界”，当默认建模不能满足你的目标时，用 SimProcedure 在边界处做统一建模，直接产出你需要的符号输入，这比在函数中段补丁式写值（或重复 hook 所有 call-site）更可维护、更不易漏。scanf 只是其中一个代表，思路是普适的。
