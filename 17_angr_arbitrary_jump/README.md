# 17_angr_arbitrary_jump：任意跳转（覆写 RET）与 angr 的 Unconstrained State

本关是典型的“栈溢出 → 覆写返回地址（RET）→ 跳到 print_good”的利用模型。与第 16 关“任意写”不同，这里关注的是指令指针（EIP）可控后在 angr 中出现的“Unconstrained State（非约束状态）”，以及两条解题路线的对比：
- 主动控制（Hook + 约束注入）
- 被动发现（保留 unconstrained state 后再约束）

建议先阅读 taint_detect.py 感知可控点，再参考 exploit.py 或 solutions/17_angr_arbitrary_jump/solve17.py 的两种策略。

## 1. 场景与目标

- 漏洞形态：read_input 调用 `__isoc99_scanf` 将数据写入栈上固定大小的缓冲区，未做长度限制，导致溢出覆盖 saved EBP 与返回地址（RET）。
```c
void read_input(void)
{
  byte buffer [25];
  __isoc99_scanf("%s",buffer);
  return;
}
```
- 目标：将 RET 覆写为 `print_good` 的地址，函数返回时跳转执行，打印 “Good Job!”。

## 2. 栈布局与精确定义的偏移

以 32 位 x86 为例（栈向低地址生长），函数栈帧的关键区段如下（低地址 → 高地址）：

```
低地址  ───────────────────────────────────────────▶ 高地址
| 25B buffer | 4B saved EBP | 4B RET |
  0 .. 24        25 .. 28      29 .. 32   （按“字节索引”从 0 开始计数）
```

- 第 0–24 字节：覆盖局部缓冲区（buffer）
- 第 25–28 字节：覆盖 saved EBP
- 第 29–32 字节：覆盖 RET（返回地址）

结论（避免歧义）：从第 29 字节（即“第 30 个字节”）开始，已经在改写返回地址的内容。利用时按小端序写入目标函数地址的 4 个字节。

## 3. 关键指令序列与溢出发生的原因

read_input 的关键流程可抽象为：

1) 在栈上分配 25 字节缓冲区
2) `call __isoc99_scanf` 将用户输入写入该缓冲区（无长度限制）
3) `ret`：从栈顶弹出 4 字节到 EIP，转移控制流

当输入长度 > 25 + 4 时，RET 所在的 4 字节将被覆盖。函数 `ret` 时，EIP 将取用我们写入的值。若 angr 在此时跟踪到 EIP 完全由用户输入决定，它会将该执行状态视为“Unconstrained State”（详见下一节）。

## 4. 何为 Unconstrained State（重点）

- 定义：当关键控制量（例如 EIP、内存访问地址）完全符号化，导致下一步“可能的分支/目标”不唯一且几乎无穷时，angr 会将该状态标记为 unconstrained。
- angr 在 [8.18.10.5](https://docs.angr.io/en/latest/appendix/changelog.html#angr-8-18-10-5) 之前的默认行为是：丢弃 unconstrained 状态（因为执行引擎无法“选择”下一条指令去哪儿）。
- 本关触发点：栈溢出覆盖返回地址后，RET 指令弹出符号值到 EIP。当 angr 检测到 EIP 的可能取值超过阈值（默认 256），会将该状态标记为 unconstrained
- 正确做法：在创建 SimulationManager 时启用 `save_unconstrained=True`（[8.18.10.5](https://docs.angr.io/en/latest/appendix/changelog.html#angr-8-18-10-5)之后默认开启），将这类状态保留下来（放入 `simulation.unconstrained`）。随后把它们迁移到可供我们处理的 `found` 栈中，并对 `regs.eip` 施加“等于 print_good 地址”的约束，再回溯出满足约束的输入。

简化示例（solutions/17_angr_arbitrary_jump/solve17.py 思路）：
```python
from angr.storage.file import SimPackets
symbolic_input = claripy.BVS("input", 8 * 33)  # 25 + 4 + 4
input_packets = SimPackets(name='input_packets', content=[(symbolic_input, 33)])
state = project.factory.entry_state(
    stdin=input_packets,  # 使用 SimPackets 而非直接传 BVS
    add_options={...}
)

simgr = project.factory.simgr(state, save_unconstrained=True)

while simgr.active or simgr.unconstrained:
    # 将 unconstrained 状态挪到 found
    for s in simgr.unconstrained:
        simgr.move('unconstrained', 'found')
    simgr.step()

if simgr.found:
    s = simgr.found[0]
    # 关键：把 EIP 约束到 print_good
    tgt = project.loader.find_symbol('print_good').rebased_addr
    s.add_constraints(s.regs.eip == tgt)
    model = s.solver.eval(symbolic_input, cast_to=bytes)
```

要点与注意：
- “探索”接口 `simgr.explore(find=...)` 对 unconstrained 状态并不会触发 find 回调，所以需要像上面这样“手动搬运”与约束。
- 对 State Options-“未约束的内存/寄存器”如何初始化-会影响路径规模：
  - `SYMBOL_FILL_UNCONSTRAINED_*`：未初始化数据→符号值(更易检测控制流漏洞)
  - `ZERO_FILL_UNCONSTRAINED_*`：未初始化数据→0(更贴近实际,但可能漏检)
  - 本题用 SYMBOL_FILL 非强制,关键是符号输入能污染到 EIP
- 注意: SYMBOL_FILL 让**未初始化内存读取**产生符号值，若该值流向 IP → unconstrained
- ZERO_FILL 则让未初始化读取返回 0，流向 IP 时通常只会 deadended(跳转到 0x0)

## 5. 两条解题路线对比

本仓库给出了两种思路，二者并非互斥，而是“主动控制”与“被动发现”的互补。

### A. Hook + 约束注入（主动控制）

参考 17_angr_arbitrary_jump/exploit.py：在 scanf 处挂自定义 `SimProcedure`，立即构造长度为 25+4+4=33 的符号输入，并注入约束：
- 前 29 字节限制为可打印字符（便于复制）
- 后 4 字节（从第 29 字节开始）按小端序等于 `print_good` 地址

示意（与 exploit.py 对齐）：
```python
class ScanfHook(SimProcedure):
    def run(self, fmt_ptr, buf_ptr):
        size = 25 + 4 + 4
        sym_var = claripy.BVS("user_input", 8 * size)
        # 0..28 可打印
        for i in range(25 + 4):
            b = sym_var.get_byte(i)
            self.state.solver.add(b >= 0x41)   # 'A'
            self.state.solver.add(b <= 0x7a)   # 'z'
        # 29..32 写入 print_good 地址（小端）
        tgt = self.project.loader.find_symbol('print_good').rebased_addr
        for i in range(4):
            b = sym_var.get_byte(25 + 4 + i)
            self.state.solver.add(b == ((tgt >> (i * 8)) & 0xff))
        return 1
```

- 优点：确定性强、收敛快、对练习/教学友好
- 缺点：需要预先知道栈布局与偏移，侵入性强、可移植性相对差

### B. Unconstrained State（被动发现）

参考 solutions/17_angr_arbitrary_jump/solve17.py：
让程序“自然”跑到 EIP 被污染的瞬间（状态进入 `unconstrained`），再把它迁移到 `found`，对 `regs.eip` 注入约束并回溯输入。

- 优点：通用性强、无需先验缓冲区大小/精确偏移
- 缺点：性能与不确定性，依赖引擎启发式；需要自己维护 `unconstrained` → `found` 的流转

简表对比：

| 维度 | Hook 方法 | Unconstrained 方法 |
| --- | --- | --- |
| 约束时机 | 早期（scanf 调用处） | 晚期（EIP 完全符号化） |
| 依赖先验 | 高（需精确偏移） | 低（黑盒友好） |
| 收敛速度 | 快 | 可能较慢 |
| 自动化程度 | 低 | 高 |

实战建议：
- 已知漏洞利用 → 首选 Hook（快速稳定）
- 自动挖掘/泛化框架 → 利用 Unconstrained（更通用）

## 6. 两个关键陷阱

### 陷阱 1：直接传 BVS 到 stdin 在 Unconstrained State 场景失效

**问题**：直接传递符号变量到 `stdin` 参数时，angr 自动创建 `SimFile` 并设置 `has_end=True`，导致输入被限制为固定大小。在 buffer overflow 等需要检测 unconstrained state 的场景中，这会阻止正确触发符号化的指令指针。

**症状**：`simulation.unconstrained`/`simulation.found` 始终为空，无法找到可利用的状态。

**正确做法**：
```python
# ❌ 错误 - 会失败
symbolic_input = claripy.BVS("input", (25 + 4 + 4) * 8)
initial_state = project.factory.entry_state(stdin=symbolic_input)

# ✅ 正确 - 使用 SimPackets
from angr.storage.file import SimPackets
symbolic_input = claripy.BVS("input", (25 + 4 + 4) * 8)
input_packets = SimPackets(
    name='input_packets',
    content=[(symbolic_input, 25 + 4 + 4)]
)
initial_state = project.factory.entry_state(stdin=input_packets)
```

**原理**：SimPackets 支持流式读取和 short reads，不会强制限制输入边界，允许 overflow 正确传播到指令指针。

**警告**：angr 会输出以下警告信息，提示你使用了错误的方式：
```
WARNING | angr.simos.simos | stdin is constrained to N bytes (has_end=True).
If you are only providing the first N bytes instead of the entire stdin,
please use stdin=SimFileStream(name='stdin', content=your_first_n_bytes, has_end=False).
```
这个警告表明直接传 BVS 导致 stdin 被限制，在 unconstrained state 检测场景会失效。

### 陷阱 2：Hook 中重算 CFG 破坏控制流

**问题**：在 Hook 回调内调用 `proj.analyses.CFGFast()` 会将 Hook 地址识别为新的基本块边界，改变 CFG 结构，导致 Hook 返回后模拟器无法继续执行。

**症状**：执行在 Hook 后卡住或中断。

**正确做法**：
```python
# 主流程：预先计算一次
cfg = proj.analyses.CFGFast()

def get_prev_instruction_addr(proj, addr):
    global cfg  # 复用全局 CFG
    node = cfg.model.get_any_node(addr, anyaddr=True)
    # ... 查询逻辑

def my_hook(state):
    # ❌ 禁止：cfg = proj.analyses.CFGFast()
    # ✅ 正确：使用全局 cfg
    prev_addr = get_prev_instruction_addr(proj, state.addr)
```

**规避原则**：
- CFG 仅在主流程中计算一次并全局缓存
- 所有 Hook 和工具函数复用外部 CFG，严禁内部重算

## 7. 运行与验证

- 污点检测（验证返回地址可控点）：
  ```
  python 17_angr_arbitrary_jump/taint_detect.py ./binary/x32/17_angr_arbitrary_jump
  ```
  你将看到 read_input 的调用与返回处的提示，以及栈顶若干槽位与寄存器值输出（用于校验偏移与可控性）。

- 主动 Hook 利用（快速达成 “Good Job!”）：
  ```
  python 17_angr_arbitrary_jump/exploit.py ./binary/x32/17_angr_arbitrary_jump
  ```

- Unconstrained 路线（官方模板思路）：
  ```
  python solutions/17_angr_arbitrary_jump/solve17.py ./binary/x32/17_angr_arbitrary_jump
  ```

提示：exploit.py 中为了便于复制，通常会把输入限制为可打印范围；回溯出的字节序应为“小端”。

## 8. 与 09 / 10 / 15 / 16 的关联

- 09（Hooks）：继续使用 `project.hook`/`hook_symbol` 定点修改语义，快速绕复杂路径。
- 10（SimProcedure）：通过自定义 SimProcedure 精确替换库函数，方便植入约束与构造输入。
- 15（任意读）：需约束“读出的数据”与目标字符串一致（面向读取侧）。
- 16（任意写）：需具体化/约束“写入目的地址”等于敏感缓冲区（面向写入侧）。
- 17（任意跳）：EIP 完全可控 → 引入 angr 的“Unconstrained State”处理范式，保留并约束指令指针。

本关没有再赘述那些已在前几关反复出现的通用坑位（如重定位地址、端序读取等），只强调本关独有的“Unconstrained + CFG 复用”两点。

## 9. FAQ（精简）

- 为什么 `simgr.explore(find=...)` 找不到？
  因为 `find` 不会对 `unconstrained` 状态触发，需要你手动把 `unconstrained` 迁到 `found`，再在 `found[0]` 上添加 `regs.eip == print_good` 约束并求解。

- 何时用 `SYMBOL_FILL_*`，何时用 `ZERO_FILL_*`？
  前者更“黑盒”，能保留潜在影响但会放大求解空间；后者更“保守”，利于收敛。根据场景选择，或两者混用。

## 参考

- angr 文档：Unconstrained State / Stashes / Options
- 栈溢出 & ret2func 资料
- 本目录：taint_detect.py（全局 CFG 复用与返回地址可控性检测）、exploit.py（Hook 快速利用）、solutions/17_angr_arbitrary_jump/solve17.py（Unconstrained 模板）
