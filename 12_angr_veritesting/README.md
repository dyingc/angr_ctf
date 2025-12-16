# 12_angr_veritesting：Veritesting 的利与弊，对比更稳的“局部约束 + 单路径”解法

本关的核心目标：当循环中存在“指数级分支爆炸”时，如何选择合适的缓解策略。程序循环 32 次，每次在 `CMP EBX, EAX`（0x080492a1）处比较 `buf[i]` 与 `complex_function` 返回值，若匹配则累加计数；全部匹配才输出 "Good Job."。

Veritesting（`simgr(..., veritesting=True)`）是 angr 的“自动合并相似分支路径”机制，旨在减少状态空间；但它有启发式局限。本关提供“纯 veritesting”与“非 veritesting + 钩子约束”两解法，后者在本题上更稳定、性能更好。


## TL;DR

- Veritesting = angr 的“路径合并”技术，自动识别循环内相似分支并合并，减少状态爆炸。
- 但它有启发式局限：合并边界、函数调用、I/O 检查等会影响稳定性，导致同一环境下“有时出解、有时无解/超时”。
- 本关推荐解法：不在 CMP 分支点 hook，添加等价约束 `EBX == EAX`，跳过 CMP/JNZ，保持单路径执行 32 次；保留对 `complex_function` 的真实调用。
- 实测对比：非 Veritesting + 钩子稳定；纯 Veritesting 不稳定。


## 1. 程序结构与关键点

- 伪代码（从 Pcode 总结）：
  ```c
  for (i=0; i<32; i++) {
    orig_chr = buf[i];
    checker_i = complex_function(0x4c, i + 0x23);
    if (orig_chr == checker_i) n_matched++;
  }
  if (n_matched == 32) puts("Good Job.");
  ```
- 汇编关键：`CMP EBX, EAX` at 0x080492a1（buf[i] vs checker_i）；匹配则 `ADD [n_matched], 1` at 0x080492a5。
- 问题：每次循环 2 条路径（匹配/不匹配），32 次得 2^32 ≈ 4e9 路径，直接爆炸。


## 2. 非 Veritesting 解法（推荐，本关更优先）

思路：在“爆炸点”CMP 处加约束并跳转，模拟“总是匹配”的语义，保持单一路径执行 32 次循环；保留 `complex_function` 调用保证程序语义完整。

### 核心实现（来自 non_veritesting_solution.py）

```python
comparion_addr = 0x080492a1  # CMP EBX, EAX
matched_inc_addr = 0x080492a5  # ADD [n_matched], 1

def hook_check_logic(s: SimState) -> List[SimState]:
    # 添加等价约束：buf[i] 必须等于 checker_i
    s.solver.add(s.regs.ebx == s.regs.eax)
    # 跳过 CMP/JNZ，直接到累加逻辑
    new_state = s.copy()
    new_state.regs.ip = matched_inc_addr  # x86 下用 ip (或 pc)
    new_state.scratch.guard = claripy.true()  # 必须设
    new_state.history.jumpkind = 'Ijk_Boring'  # 文档误写 scratch.jumpkind，实际读取 history.jumpkind
    return [new_state]

project.hook(comparion_addr, hook_check_logic)
simgr.explore(find=success_func, avoid=fail_func)
```

要点：
- **约束语义**：`EBX == EAX` 等价于“每次比较都匹配”，但不强制所有字节相同（solver 会根据 `complex_function` 逻辑求解出具体值）。
- **返回 successor**：hook 返回“后继状态列表”时，必须设置三个字段（否则执行器报错）：
  - `regs.ip`（或 pc）：下一指令地址。
  - `scratch.guard`：分支条件（通常 `claripy.true()`）。
  - `history.jumpkind`：跳转类型（如 'Ijk_Boring'；文档错误描述 `scratch.jumpkind`，实际代码读取 `history.jumpkind`）。
- **性能**：`copy()` 使用 COW，仅 1 个 successor，路径不扩散；可选 hook `complex_function` 替换为符号公式加速。
- **稳定性**：你实测中“启用/禁用 Veritesting 都稳定”，且禁用 Veritesting 略快。

### 拓展：两钩子“人工续帧”模式（文件内新提，本题未用但通用）

若 hook 需“调用原函数”并处理返回值，可用“两钩子”：
- 第一钩子：设函数参数、压续点地址、跳转到目标函数。
- 第二钩子：设在续点，取返回值（RAX/EAX）、处理结果、跳转到原代码。

本题因“约束 + 跳转”已足够，不需该复杂模式；但适用于“需要中断/恢复控制流”的场景（见文件内详解）。

### find/avoid 建议
- 优先用 stdout 匹配（如 `b'Good Job.' in state.posix.dumps(1)`），避免 Veritesting 合并后 addr 不可靠。


## 3. Veritesting 解法（展示但标注“不稳定”）

做法：`simgr = project.factory.simgr(initial_state, veritesting=True)`，以 stdout 或 block addr 为 find。

### 实测现象（你提供的复现实验）
```bash
$ i=0 ; export PYTHONHASHSEED=0; while [ 1 ] ; do echo ${i}; gtimeout 5 python 12_angr_veritesting/scaffold12.py 2>/dev/null ; i=$((i+1)); done
```
- 输出：有时出解（如 `Solution: DFHJLNPRTVXZBDFHJLNPRTVXZBDFHJLN`），有时无解/超时；同一环境下随机交替。
- 原因（信息性，非修复建议）：Veritesting 的合并启发式受合并边界/函数调用/I/O 检查/SMT 求解交互影响；表达式规模与时间片敏感，导致不可预测性。

### 总结
- 本题 Veritesting 可用于“演示合并效果”，但不稳定；不推荐作为首选方案。


## 4. 两解法对比：何时用 Veritesting，何时用钩子约束

- **Veritesting**：
  - 适合：循环体规整、无外部复杂调用、分支易合并时“可尝试但不强依赖”。
  - 优势：无需手动干预，自动优化。
  - 劣势：启发式不稳定，调试难；本题表现差。

- **钩子 + 约束**：
  - 适合：已知爆炸点（如逐字节比较）且能等价替代分支逻辑，追求稳定/可复现。
  - 优势：控制精确、性能可控；本题表现更好。
  - 劣势：需分析汇编定位分支点。

- **选择原则**：稳定优先选钩子；若合并效果好，可叠加 Veritesting 加速。


## 5. 复现实验与注意事项

- **地址确认**：因 seed/编译差异，地址可能漂移。用 r2 定位：
  ```bash
  r2 -q -c 'aaa; afl~complex_function' binary/x32/12_angr_veritesting  # 找函数
  r2 -q -c 'aaa; iz~Good; axt @ str.Good_Job.' binary/x32/12_angr_veritesting  # 反查成功路径
  ```
- **配置**：`auto_load_libs=False`、`ZERO_FILL_UNCONSTRAINED_*` 仅信息披露，不作为“修复 Veritesting”的调参建议。
- **调试**：在 hook 内打印 `len(s.solver.constraints)` 观察约束累积（文件内示例每 100 次打印）。


## 6. 常见坑位

- **successor 返回**：未设置 `history.jumpkind` 或 `scratch.guard` 导致路径丢失。
- **regs.pc vs regs.ip**：x86 下用 `ip`（通用）；保持一致避免混淆。
- **find/avoid**：Veritesting 后用 stdout 更稳；block addr 可能因合并变化。
- **约束过多**：32 条约束一般可解；若爆炸，考虑 hook `complex_function` 为符号版本加速。

——

本关 takeaway：Veritesting 是强大的“自动化优化”，但启发式局限导致不稳定；对关键分支，更稳的做法是手动 hook + 等价约束，保持单路径执行。非 Veritesting + 钩子在本题上更优先，兼顾稳定与性能。
