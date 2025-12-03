# 09_angr_hooks CTF 挑战：Hook 函数/调用点与“无 Hook”两阶段解法对比

> 本关的核心在于：`check_equals_<REF>` 是逐字节比较循环，直接跟到 “Good Job.” 容易路径爆炸。
> 我们用 Hook 或“后置约束”把等式直接交给 SMT，绕过昂贵分支，快速拿到两段输入。

---

## 1 程序概览与目标

关键流程（简化）：
1) 读取 16 字节输入，逐字节经 `complex_function(c, 0x12 - i)` 变换写回 `buffer`
2) 调用 `check_equals_JVFWZKBIAFZNPNXN(buffer, 16)` 判断变换后的 `buffer` 是否等于 “JVFWZKBIAFZNPNXN”
3) 将 `password="JVFWZKBIAFZNPNXN"` 也按 `complex_function(c, j+9)` 逐字节变换
4) 再次 `scanf("%16s", buffer)`，要求第二次输入与变换后的 `password` 完全相同 → “Good Job.”

r2 重要符号（示例）：
- `check_equals_JVFWZKBIAFZNPNXN`: 0x08049230（函数），调用点示例：0x0804933e
- `password`: 0x0804c040（长度 16）
- `buffer`: 0x0804c02c（长度 17，含 0 终止）
- `complex_function`: 0x080491d4

---

## 2 三种可行思路（本关三脚本均可过关）

| 方法 | 是否 Hook | 约束时机 | 探索阶段 | 性能 | 适用场景 |
|------|----------|----------|----------|------|----------|
| A. `solution.py` | ✅ Hook 函数本体 | Hook 内即刻 `state.solver.add(...)` 并 `eax=1` | 单阶段直达 Good Job. | 最快（通常只保留 1 个状态） | 函数符号可定位、函数大小可得 |
| B. `solution_two_phses.py` | ❌ 不 Hook | Phase-1 到达 `check_equals` 调用点后添加后置约束，手动跳过 CALL，再 Phase-2 找 Good Job | 两阶段探索 | 中等 | 不改执行流、便于分步调试；更贴近“后置约束”教学 |
| C. `scaffold09.py` 参考 | ✅ Hook 调用点 | Hook 中加约束/或用 claripy.If 设置返回 | 单阶段 | 居中 | 只想替换 CALL 指令，且需要保持栈简单时 |

> 性能说明：差异的主要来源在于是否引入“额外状态”（例如使用 `claripy.If(...)` 造成分支，或拆为多阶段导致多次搜索），而非 Hook 在函数本体还是调用点本身。

---

## 3 方案 A（Hook 函数本体）要点：`solution.py`

核心片段（节选）：
```python
# stdin 两段输入：必须用同一个 SimPackets 的两段内容模拟两次 scanf
simpackets = SimPackets(name='simfile', write_mode=False,
    content=[(sym_input1, 16), (sym_input2, 16)])
state = project.factory.full_init_state(stdin=simpackets, add_options={...})

# 定位符号并 Hook 函数本体
check_sym = [s for s in project.loader.symbols if re.match(r'^check_equals_.*', s.name)][0]
bytes_to_skip = check_sym.size - 1  # -1：保留函数尾部 ret 指令，避免返回地址无法弹栈
@project.hook(check_sym.rebased_addr, length=bytes_to_skip)
def hook_check_equals(state: SimState):
    esp = state.regs.esp
    # 函数本体：esp+0 是 ret，esp+4 第一个参数 buffer，esp+8 第二个参数 length
    length = state.memory.load(esp + 8, 4, endness=state.arch.memory_endness)
    buf_ptr = state.memory.load(esp + 4, 4, endness=state.arch.memory_endness)
    mutated = state.memory.load(buf_ptr, length)
    ref = state.memory.load(project.loader.find_symbol('password').rebased_addr, length)

    # 建议逐字节相等（经验上比一次性 128-bit 等式更快）
    for i in range(length.concrete_value):
        state.solver.add(mutated.get_byte(i) == ref.get_byte(i))

    # 直接设置返回值，避免分支
    state.regs.eax = claripy.BVV(1, 32)
```

关键注意：
- “函数本体 Hook”与“调用点 Hook”栈布局不同：
  - 函数本体：`[ret][arg0(buf)][arg1(len)]` → 读取 `esp+4/esp+8`
  - 调用点（CALL 前）：此时 ret 尚未入栈，`esp` 指向第一个实参
- `length=check_sym.size-1` 保留 `ret`，让引擎照常弹出返回地址。不保留会破坏返回流程
- 读取 4 字节整数/指针必须指明字节序：`endness=state.arch.memory_endness`（x86 小端）
- 直接把 `eax=1` 优于 `claripy.If(...)`，后者会引入额外分支

附：调用点 Hook 参数偏移示例（CALL 之前）
```python
@project.hook(check_equals_called_address, length=5)  # x86 常见 CALL 指令 5 字节
def hook_at_call_site(state):
    esp = state.regs.esp
    # 注意：此时返回地址尚未入栈，esp 指向第一个参数
    buf_ptr = state.memory.load(esp + 0, 4, endness=state.arch.memory_endness)
    length  = state.memory.load(esp + 4, 4, endness=state.arch.memory_endness)
    mutated = state.memory.load(buf_ptr, length)
    ref     = state.memory.load(project.loader.find_symbol('password').rebased_addr, length)

    for i in range(state.solver.eval(length).to_bytes(4, 'little')[0]):  # 或直接 state.solver.eval(length)
        state.solver.add(mutated.get_byte(i) == ref.get_byte(i))
    state.regs.eax = claripy.BVV(1, 32)  # 返回真
```

---

## 4 方案 B（无 Hook，两阶段探索）要点：`solution_two_phses.py`

Phase-1：
```python
# 仍然用 SimPackets 两段内容模拟两次 scanf
simgr_phase_1 = project.factory.simulation_manager(state)
# 找到第一次对等检查的“调用点”
simgr_phase_1.explore(find=0x0804933e)

phase_1_state = simgr_phase_1.found[0]
ref = claripy.BVV(b'JVFWZKBIAFZNPNXN', 16*8)
mutated = phase_1_state.memory.load(0x0804c02c, 16)  # buffer 的全局地址
for i in range(16):
    phase_1_state.solver.add(mutated.get_byte(i) == ref.get_byte(i))

# 手动跳过 CALL，假设检查成功（eax=1），直接从下一条指令继续 Phase-2
phase_1_state.regs.eip = 0x08049343  # CALL 之后的地址
phase_1_state.regs.eax = 1
```

Phase-2：
```python
simgr_phase_2 = project.factory.simulation_manager(phase_1_state)
simgr_phase_2.explore(find=0x080493f0)  # “Good Job.” 附近地址
# 从 found_state.solver.eval 提取第一、第二段输入
```

优点：
- 不改变二进制指令节（便于逐步教学/验证），容易观察状态和约束
- 可清晰展示“后置约束”的思路：到达检查点 → 添加等式 → 继续执行

---

## 5 方案 C（参考脚本 scaffold09）要点

- Hook **调用点**，`@project.hook(check_equals_called_address, length=CALL大小)`
- 取出目标 buffer 内容、与引用字符串比较；可在 Hook 内直接 `solver.add(...) + eax=1`
- 性能介于 A/B：省去了二次 simgr，但仍需小心跳过长度与栈布局

---

## 6 共同关键技巧

- stdin 两段输入必须匹配两次 `scanf`：
  `SimPackets(name, content=[(bv1,16),(bv2,16)])`。分成两个数据包，分别被两次 `scanf` 消费
- Endness：
  读取 4 字节长度与指针，用 `endness=state.arch.memory_endness`（x86=LE）。字符串逐字节访问则不需要指定 endness（避免顺序被翻转）
- 约束粒度：
  实测逐字节 `==` 更稳定；一次性 `mutated == ref` 也可，但有时约束求解开销更大
- 返回值：
  用 `state.regs.eax = claripy.BVV(1,32)` 明确返回成功，避免再次分支
- 栈布局小抄：
  - Hook 函数：`esp+0=ret, esp+4=arg0(buf), esp+8=arg1(len)`
  - Hook 调用点（CALL 前）：`esp=arg0(buf), esp+4=arg1(len)`（ret 尚未入栈）

---

## 7 何时选哪种方法？

- 函数符号清晰 → 选 A（Hook 函数）
- 需要演示“后置约束”/不想改指令节 → 选 B（无 Hook 两阶段）
- 只想替换 CALL、保持栈简单 → 选 C（Hook 调用点）
- 追求极致性能 → 选添加约束，而不是 claripy.If 从而导致额外的状态增加

---

## 8 实操步骤（建议）

1) 用 r2 定位符号/地址
```bash
r2 -q -c 'aaa; iz~Good; axt @ str.Good_Job.' binary/x32/09_angr_hooks
r2 -q -c 'aaa; afl~check_equals' binary/x32/09_angr_hooks
r2 -q -c 'aaa; is~buffer; is~password' binary/x32/09_angr_hooks
```
2) 确认 `buffer=0x0804c02c`、`password=0x0804c040`、`check_equals` 的函数地址与调用点
3) 选择 A/B/C 任一脚本运行，对比性能与输出；注意 SimPackets 与 endness

---

## 9 常见错误

- Hook length 设置错误：
  - Hook 函数跳过了 `ret` → 返回破坏，程序乱跳
  - Hook 调用点 length 未覆盖完整 CALL 指令 → PC 同一处重复执行
- 栈偏移取参搞错（函数 vs 调用点差异）
- 第二次 `scanf` 无数据（未使用 SimPackets 两段输入）
- 忘记 endness 读取指针/整数（x86 小端）
- 额外使用 `claripy.If` 造成多一层分支，拖慢求解

---

## 10 结论

- 本关展示了三种等价但风格不同的解法：
  Hook 函数（最快）、无 Hook 两阶段（教学友好）、Hook 调用点（折中）。
- 关键在于：用 Hook 或后置约束，直接把“等式”交给 SMT，绕开昂贵的逐字节分支。
- 模型 stdin 为两段、正确取参与 endness、以及正确的跳过长度，是保证稳定性的三块基石。
- 性能主要取决于是否引入“额外状态”：如 `claripy.If(...)` 会产生分支，或两阶段多一次搜索；Hook 在函数本体还是调用点对性能影响相对次要。

---

## 11 进一步优化与注意事项

- `length` 的具体化
  - 示例中 `length` 实际为常数 16，但稳妥做法是 `n = state.solver.eval(length)` 再用 `for i in range(n):`，避免符号长度带来不确定分支。
- CALL 跳过长度的确认
  - x86 常见 `CALL rel32` 为 5 字节，但不同编译器/指令前缀可能导致差异。用反汇编确认 `length`，确保 Hook 后落点正确（fallthrough）。
- SimPackets 的正确建模
  - 两次 `scanf` → 必须两个 packet：`content=[(bv1,16),(bv2,16)]`。反例：把两段输入拼成一个 packet 会导致第二次 `scanf` 读空。
- Endness 复盘
  - 读取指针/整型时务必 `endness=state.arch.memory_endness`（x86=LE）；字符串逐字节存取不应设置 `endness`，避免顺序被翻转。
- 约束写法的取舍
  - “逐字节相等”通常比一次性 128-bit 等式更稳定；且避免 `claripy.If(...)` 引入额外状态，直接 `solver.add(...) + eax=1` 更高效。
- 调试建议
  - 打印 `simgr.stashes` 观察状态规模；打印 `len(state.solver.constraints)` 监控约束增长；必要时插入 `state.history.recent_description` 追踪执行路径片段。
