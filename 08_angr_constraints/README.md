# 08_angr_constraints CTF 挑战：后置约束（post-hoc constraints）消除路径爆炸

> 本关的关键认知：很多“约束”并不是必须在 `explore()` 之前加。
> 更高效的做法是：先用 `explore()` 抵达“对你有利的检查点”（如对比函数入口），再在该状态上**添加约束**并直接让 SMT 求解器解出输入。
> 这能有效回避因逐字节比较带来的指数级路径爆炸。

---

## 1 挑战概述

程序流程（简化）：
1) 预设 `password[16]`（全局 16 字节目标）
2) 读取用户输入到 `buffer`
3) `for (i=0..15) buffer[i] = complex_function(buffer[i], 0xF-i)`
4) `check_password(buffer, 0x10)`：逐字节统计相等数，若等于 16 → Good Job.

难点：`check_password` 逐字节比较 → 每个字节“相等/不等”两条分支，16 次循环导致 2^16 条路径，直接找 Good Job 地址会非常慢。

核心技巧：
- 不再以 “Good Job.” 的地址为 `find` 目标
- 而是以 `check_password`（或其变种）函数入口为 `find` 目标
- 到达后，在该 `found_state` 上，强制“比较的两串字节逐个相等”，让约束解出“原始用户输入”。

---

## 2 逆向要点（Ghidra + r2）

来自反编译（变量名略有修改）：
```c
// main
password[0] = 0x4b555353;
password[1] = 0x574b4a44;
password[2] = 0x4f475a53;
password[3] = 0x594a4f4f;
memset(buffer,0,0x11);
scanf("%16s", buffer);
for (i=0; i<0x10; ++i) {
  buffer[i] = complex_function((int)buffer[i], 0xF - i);
}
if (check_password(buffer, 0x10)) puts("Good Job."); else puts("Try again.");
```

```c
// complex_function：限定大写字母，并以 (x + k*0x35) mod 26 变换
int complex_function(int ch, int k) {
  if (0x40 < ch && ch < 0x5b) {
    return (ch - 0x41 + k*0x35) % 0x1a + 0x41;
  }
  puts("Try again."); exit(1);
}
```

```c
// check_password：逐字节计数，是否全部匹配
bool check_password(char *mutated, uint n) {
  uint i, matched = 0;
  for (i=0; i<n; ++i) {
    if (mutated[i] == ((char*)password)[i]) matched++;
  }
  return matched == n;
}
```

r2 关键定位：
- 起跳（`scanf` 之后）：`0x80492e0`
- 变换循环后调用：`call sym.check_equals_SSUKDJKWSZGOOOJY`
  - 即 `check_password` 的具体符号名（每次生成不同）。
- “Good Job.” 地址：`0x804934c`（本关不用它做 find）
- 快速命令：
  ```bash
  r2 -q -c 'aaa; afl~check_equals' binary/x32/08_angr_constraints
  # 或从字符串反查
  r2 -q -c 'aaa; iz~Good; axt @ str.Good_Job.' binary/x32/08_angr_constraints
  ```

---

## 3 核心概念：为何“后置约束”更优？

- 问题来源：`check_password` 循环里每次比较都产生一个分叉（相等/不等），16 次得到 2^16 条可能路径。
- 传统做法：以 “Good Job.” 为 `find` 地址探索，angr 需要穿越所有分叉，极易超时。
- 后置约束：以 `check_password` 入口为 `find`，抵达后在该状态读取“被比较的两串字节”（变换后的 `buffer` 与全局 `password`），逐字节添加“必须相等”的约束，一步让 SMT 求解器解出“原始输入”。

示意图：
```
entry ──▶ transform loop ──▶ check_password (find) ──▶ exit
               ▲ 2^16 分支↑    ↓在此添加“逐字节相等”的约束
               └──────────────┘
```

### 3.1 何时使用
- 比较/校验函数导致指数爆炸（逐字节 if/分支）
- 你知道目标预期状态（如“变换后等于某串”）
- 能找到合适的检查点地址（函数入口/调用点）

### 3.2 优势
- 避免路径爆炸，极大缩短搜索时间
- 无需 Hook/重写二进制逻辑，兼容性强

### 3.3 局限
- 需要人工逆向分析得出“期望状态”
- 若期望值本身复杂未知，仍需完整符号执行
- 约束过多/过强可能导致 SMT 求解困难

### 3.4 与其他技术对比
- Veritesting：自动合并路径，适合循环内部无 I/O；后置约束更“定点”，人工可控
- Hooks（SimProcedures）：可重写函数减少分支，但需保证语义正确；后置约束无需改代码

---

## 4 解法步骤（对应 `08_angr_constraints/solution.py`）

1) 起点：`blank_state(addr=0x80492e0)`（跳过 `scanf`）
2) 正确写入全局 `password[16]`：
   - 使用 4×4 字节写入（小端），因为写的是整数值（必须显式 endness）
   ```python
   password_addr = project.loader.find_symbol('password').rebased_addr
   state.memory.store(password_addr + 0,  0x4b555353, size=4, endness=state.arch.memory_endness)
   state.memory.store(password_addr + 4,  0x574b4a44, size=4, endness=state.arch.memory_endness)
   state.memory.store(password_addr + 8,  0x4f475a53, size=4, endness=state.arch.memory_endness)
   state.memory.store(password_addr + 12, 0x594a4f4f, size=4, endness=state.arch.memory_endness)
   ```
3) 构造 16 字符输入（末尾 0 终止），无需预先限制 A-Z（到达检查点的路径会自动蕴含该约束）：
   ```python
   input_size = 17
   user_input = claripy.BVS('user_input', 16*8)
   user_input = claripy.Concat(user_input, claripy.BVV(b'\x00'))
   ```
   > 说明：`complex_function` 对每个字节做 `'A'..'Z'` 检查，任何能成功到达 `check_password` 入口（find 地址）的路径都会隐式满足该条件。
   > 预先添加 A-Z 约束属于可选的“剪枝优化”，可以减少搜索空间，但并非求解必要条件。
4) 将其写入全局 `buffer`：
   ```python
   buffer_addr = project.loader.find_symbol('buffer').rebased_addr
   # 字符串是逐字节访问，通常不需 endness；若指定，常用 Iend_BE 以保持高位字节先写到低地址
   state.memory.store(buffer_addr, user_input)  # 建议省略 endness
   ```
5) `explore(find=check_password入口)`：
   ```python
   # 通过枚举符号名匹配 check_equals_* 获取其 rebased_addr
   [...]
   simgr.explore(find=pwd_compare_func_addr)
   ```
6) 在 `found_state` 上添加“逐字节相等”的约束，并解出原始输入：
   ```python
   found_state = simgr.found[0]
   desired = found_state.memory.load(password_addr, size=16)
   mutated = found_state.memory.load(buffer_addr,   size=16)
   for i in range(16):
     found_state.solver.add(mutated.get_byte(i) == desired.get_byte(i).concrete_value)
   solution = found_state.solver.eval(user_input, cast_to=bytes)[:-1]  # 去掉末尾 \x00
   print("Solution:", solution.decode())
   ```

注意：
- “约束必须加在 found_state 上”，而不是 initial_state，否则无效。
- 写入整数/指针必须显式 `endness`；写入字符串建议省略（或选 BE 保字节顺序）。
- 若从 `desired.get_byte(i)` 得到的是符号 BV，需 `solver.eval` 或 `.concrete_value` 取得具体字节值。

---

## 5 scaffold08.py 填空思路

- `start_address`：`0x80492e0`（scanf 之后）
- `password = claripy.BVS('password', 16*8)`（若你想以 BVS 形式加载/比较）
- `password_address`：符号 `password` 的重定位地址
- `address_to_check_constraint`：`check_equals_*` 函数入口
- `constrained_parameter_address`：该函数第一个参数（即“被比较的串”的指针）
  - 在 x86 cdecl：位于栈上 `[ebp+8]`；或直接根据调用点已知传入的是 `buffer`
- `constrained_parameter_size_bytes`：16
- `constrained_parameter_desired_value`：从全局 `password` 取出 16 字节，或直接用 `claripy.BVV(b'....', 16*8)`
- `solution = solution_state.solver.eval(password, cast_to=bytes)` 或对你加载的 bitvector 求解

---

## 6 更多“后置约束”范例

1) 未知长度字符串 + CRC/哈希后置约束
```python
crc_val = state.memory.load(crc_addr, 4)
found_state.solver.add(crc_val == claripy.BVV(0xDEADBEEF, 32))
```

2) 数组元素和为常量
```python
arr = state.memory.load(arr_addr, 10)
total = claripy.Sum(*[arr.get_byte(i).zero_extend(24) for i in range(10)])
found_state.solver.add(total == 200)
```

3) XOR 混淆累加寄存器
```python
# 跑到循环结束处，再绑定最终寄存器值
found_state.solver.add(found_state.regs.eax == 0x1337)
```

4) 结构体字段约束（偏移精确到字节）
```python
s_addr = struct_addr  # 假设事先解析
field_b = state.memory.load(s_addr+4, 2)  # uint16_t b
found_state.solver.add(field_b == claripy.BVV(0x1234, 16))
```

---

## 7 常见错误与调试

- 约束加错对象：必须在 `found_state` 添加
- BV 与 bytes 类型混用：比较时确保二者位宽一致；需要时用 `claripy.BVV()` 包装
- 忘记大小端：整数/指针一定要 `endness=state.arch.memory_endness`
- 约束过强：逐字节相等足够，避免一次性把整个 128bit 拼成一个等式造成求解困难
- 观测输出：`state.posix.dumps(fd)`，或打印 `solver.constraints` 排查是否包含预期符号

---

## 8 实践步骤

```bash
# 1) 生成二进制
cd 08_angr_constraints
python generate.py 2025 08_angr_constraints

# 2) 确认符号与地址
r2 -q -c 'aaa; afl~check_equals' binary/x32/08_angr_constraints
r2 -q -c 'aaa; is~password; is~buffer' binary/x32/08_angr_constraints

# 3) 运行解题脚本
python 08_angr_constraints/solution.py
# 输出 16 字节大写密码
```

---

## 9 延伸阅读

- angr：States / Solver / Constraints
  https://docs.angr.io/en/latest/core-concepts/solver.html
- Veritesting：路径合并
  https://docs.angr.io/en/latest/advanced-topics/veritesting.html
- Claripy：BitVectors 与表达式
  https://docs.angr.io/en/latest/advanced-topics/claripy.html
