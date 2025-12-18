# 16_angr_arbitrary_write：任意写 (strncpy) + 符号地址具体化策略 (Concretization)

本关模拟"通过溢出覆盖指针 → 达成任意写 → 篡改校验位"的利用模型。

## 1. 漏洞分析与栈布局

### 1.1 栈布局图

```
高地址
├─────────────┤
│   saved EBP │  ebp+0x00
├─────────────┤
│     key     │  ebp-0x08  (4 bytes, scanf 第 1 参数)
├─────────────┤
│    dest     │  ebp-0x0c  (4 bytes, 指针) ← 溢出目标！
├─────────────┤
│user_input_2 │  ebp-0x10
│  (16 bytes) │  ebp-0x14
│             │  ebp-0x18
│             │  ebp-0x1c  ← scanf 第 2 参数起始
├─────────────┤
低地址
```

**关键**：`user_input_2` 缓冲区 16 字节，`scanf("%20s")` 允许写入 20 字节，溢出 4 字节正好覆盖 `dest` 指针。

### 1.2 初始化陷阱

```asm
0x080491e5  mov dword [dest], obj.unimportant_buffer
```

这会误导你认为所有 `strncpy` 都写向 `unimportant_buffer`。

## 2. 关键指令序列

### 2.1 溢出发生

```asm
0x08049229  lea    eax, [ebp-0x1c]        ; eax = &user_input_2
0x08049237  call   __isoc99_scanf         ; scanf("%u %20s", &key, user_input_2)
```

**溢出机制**：
- `user_input_2` 只有 16 字节
- `%20s` 允许 20 字节 → 溢出 4 字节覆盖 `dest`
- `input2[0:15]` → 缓冲区，`input2[16:19]` → dest 指针
- 栈上 `dest` 紧随 `user_input_2` 之后，二者相距 16 字节，因此第 16~19 字节会按小端序写入指针值（覆盖 `ebp-0x0c` 处的 `dest`）。

简单映射（偏移从 0 开始）：
```
偏移(十进制):   0 .......... 15 | 16  17  18  19 | 20 ..
内容:           user_input_2     |  覆盖 dest 指针 | 其余被忽略/未读
写入到内存:     [ebp-0x1c .. -0x11] | [ebp-0x0c .. -0x09]
```

### 2.2 漏洞触发（第三次 strncpy）

```asm
0x0804926c  mov    eax, dword [ebp-0x0c]  ; 读取被覆盖的 dest
0x08049278  push   eax                     ; 作为 dest 参数
0x08049279  call   strncpy                 ; strncpy(被控制的dest, user_input_2, 16)
```

**四次 strncpy 对比**：

| 次数 | 地址 | dest 来源 | 可控？ |
|-----|------|-----------|-------|
| 1 | 0x0804920e | 立即数 `password_buffer` | ❌ |
| 2 | 0x08049262 | 立即数 `unimportant_buffer` | ❌ |
| **3** | **0x08049279** | **从 `[ebp-0x0c]` 加载** | **✅** |
| 4 | 0x08049291 | 立即数 `unimportant_buffer` | ❌ |

**Ghidra 陷阱**：反编译显示 `strncpy(unimportant_buffer, ...)` 但实际汇编是 `mov eax, [dest]`！

### 2.3 校验点

```asm
0x080492a9  call   strncmp  ; strncmp(password_buffer, "IDGNGCXX", 8)
0x080492b3  jz     Good_Job
```

## 3. 核心难点：符号地址具体化

### 3.1 问题

即使 `dest` 被符号化，为什么 `simgr.explore()` 找不到解？

**原因**：angr 对符号写地址采用保守策略——**默认选择最大可能值**。

### 3.2 angr 的默认行为

根据[官方文档](https://docs.angr.io/en/stable/advanced-topics/concretization_strategies.html)，默认写入策略链：

1. **SimConcretizationStrategyRange(128)** - 仅对带特殊标记的变量生效
2. **SimConcretizationStrategyMax** - 选择最大值（兜底策略）

**具体到本题**：
```python
# angr 内部执行：
concrete_dest = state.solver.max(dest)  # 选最大值，通常是栈地址 0xbfxxxxxx
state.add_constraints(dest == concrete_dest)

# 问题：password_buffer 在 0x0804xxxx（全局区），远小于栈地址
# 结果：写到错误位置，strncmp 失败
```

### 3.3 为什么需要手动约束？

**矛盾**：
- 求解器：选最大值（满足"内存可访问"约束）
- 利用目标：需要特定的小地址（`password_buffer`）

**解决**：显式告诉求解器选择目标地址，覆盖默认策略。

### 3.4 scanf 中整数 key 的具体化（至关重要）

本题中第一段输入为 `%u`（无符号整数，文中称为 `key`）。该整数经常参与分支判断，决定后续是否会执行到“第 3 次 strncpy”（即使用我们覆写后的 `dest` 指针的那次调用）。如果不对 `key` 做好具体化策略，可能出现：
- 路径爆炸：大量无关分支被探索，迟迟无法触达目标调用点；
- 约束冲突：在添加“`dest==password_buffer` 且 `src=="IDGNGCXX"`”约束后，`key` 的取值空间与既有路径条件不相容。

常用的两种做法：

1) 早期具体化（在 scanf Hook 内直接收敛）
```python
class ReplacementScanf(angr.SimProcedure):
    def run(self, fmt, key_ptr, str_ptr):
        scanf0 = claripy.BVS('scanf0', 32)         # key
        scanf1 = claripy.BVS('scanf1', 20*8)       # user_input_2
        # 可选：限制 key 的取值范围，减少爆炸（如 0..1000）
        # self.state.solver.add(scanf0 >= 0, scanf0 <= 1000)

        # 直接设置关键路径所需的 key（来自逆向/调试经验）
        # self.state.solver.add(scanf0 == TARGET_KEY)

        # 约束 scanf1 为可见 ASCII
        for ch in scanf1.chop(bits=8):
            self.state.add_constraints(ch >= 0x20, ch <= 0x7e)

        self.state.memory.store(key_ptr, scanf0, endness=self.arch.memory_endness)
        self.state.memory.store(str_ptr, scanf1)
        self.state.globals['input1'] = scanf0
        self.state.globals['input2'] = scanf1
        return 2
```
- 适合“已知关键分支条件”的场景，能显著减少搜索空间；
- 若不确定具体值，可先限定区间，待到命中检查点后再 `eval` 求出确切数值。

2) 惰性具体化（在检查点与其它关键约束一并判定）
在 `check_strncpy` 命中时统一判断“`dest==password_buffer` 且 `src=="IDGNGCXX"`”是否可满足；若可满足，再一次性具体化 `key`：
```python
def check_strncpy(state):
    ...
    constraint_dest = (strncpy_dest == password_buffer_addr)
    constraint_src  = (src_contents == b'IDGNGCXX')

    if state.satisfiable(extra_constraints=(constraint_dest, constraint_src)):
        state.add_constraints(constraint_dest, constraint_src)
        # 这时再对 key 进行具体化，得到一个满足路径与目标的稳定取值
        key_val = state.solver.eval(state.globals['input1'], cast_to=int)
        state.globals['concrete_key'] = key_val
        return True
    return False
```
- 优点：不需要预先知道 `key` 的精确取值；
- 建议仍然给 `key` 添加适度范围约束，避免无界整数导致的路径爆炸。

实践建议：
- 如果通过静态分析已知“只有某些 key 会走到第 3 次 strncpy”，优先在 scanf Hook 中直接具体化；
- 若不清楚取值，则先保持 `key` 符号化，在命中检查点时统一具体化，并可打印 `key` 便于后续固定。

## 4. 解法 A：Hook strncpy 添加约束

### 4.1 核心代码

```python
def check_strncpy(state):
    # 读取参数（x86 cdecl 调用约定）
    strncpy_dest = state.memory.load(state.regs.esp + 4, 4, endness=project.arch.memory_endness)
    strncpy_src = state.memory.load(state.regs.esp + 8, 4, endness=project.arch.memory_endness)
    src_contents = state.memory.load(strncpy_src, 8)

    # 检查双重可控：dest 指针 + src 内容
    if state.solver.symbolic(strncpy_dest) and state.solver.symbolic(src_contents):
        password_string = b"IDGNGCXX"
        buffer_address = 0x0804A048  # 从 radare2 获取

        # 使用 extra_constraints 预检查
        if state.satisfiable(extra_constraints=(
            src_contents == password_string,
            strncpy_dest == buffer_address
        )):
            state.add_constraints(src_contents == password_string, strncpy_dest == buffer_address)
            return True
    return False

# Hook strncpy 入口
simulation.explore(find=lambda s: s.addr == 0x08049070 and check_strncpy(s))
```

### 4.2 关于 strncpy 地址的坑

```python
# ❌ 错误：符号表地址可能是 GOT 表项
strncpy_addr = project.loader.find_symbol('strncpy').rebased_addr  # 0x47500010？

# ✅ 正确：使用 PLT 地址（从 radare2 获取）
strncpy_addr = 0x08049070
```

**原因**：`find_symbol` 可能返回 GOT 而非 PLT stub，需要手动确认。

## 5. 解法 B：污点检测（自动化审计）

### 5.1 污点标记

```python
def _is_controlled(s: SimState, var: claripy.ast.bv.BV) -> bool:
    """检查变量是否受用户输入控制"""
    if s.solver.symbolic(var):
        return any('input1' in name or 'input2' in name for name in var.variables)
    return False
```

### 5.2 Hook scanf 注入污点

```python
class Scanf(SimProcedure):
    def run(self, fmt, input1_ptr, input2_ptr):
        input1 = self.state.solver.BVS("input1", 32)
        input2 = self.state.solver.BVS("input2", 20 * 8)  # 20 字节，会溢出！

        # 约束为可见 ASCII
        for i in range(20):
            char = input2.get_byte(i)
            self.state.add_constraints(char >= 0x20, char <= 0x7e)

        self.state.memory.store(input1_ptr, input1, endness=self.arch.memory_endness)
        self.state.memory.store(input2_ptr, input2)

        self.state.globals['input1'] = input1
        self.state.globals['input2'] = input2
        return 2
```

### 5.3 监控 strncpy

```python
def hook_strncpy(proj):
    def _hook(s):
        dest_buf = s.memory.load(s.regs.esp + 4, 4, endness=s.arch.memory_endness)
        src_buf = s.memory.load(s.regs.esp + 8, 4, endness=s.arch.memory_endness)
        src_contents = s.memory.load(src_buf, 8)

        if _is_controlled(s, dest_buf) and _is_controlled(s, src_contents):
            print("[*] Arbitrary write detected!")
            password_buffer_addr = proj.loader.find_symbol('password_buffer').rebased_addr
            s.add_constraints(dest_buf == password_buffer_addr, src_contents == b'IDGNGCXX')
    return _hook

project.hook(0x08049070, hook_strncpy(proj), length=0)  # length=0 表示监控型
```

## 6. 常见坑位

### 6.1 栈布局计算

```python
# ❌ 混淆 scanf 限制和缓冲区大小
overflow_offset = 20  # 错误！

# ✅ 正确
buffer_size = 16
dest_offset = 16  # dest 在缓冲区后 16 字节处
```

### 6.2 Bitvector 索引

```python
# ✅ 推荐：直接比较
src_contents == b"IDGNGCXX"

# ⚠️ 位索引（如果需要）：记住高位在左
# password[63:56] == ord('I')  # 第 1 个字节
# password[7:0]   == ord('X')  # 第 8 个字节
```

### 6.3 约束时机

```python
# ✅ 推荐：先检查再添加
if state.satisfiable(extra_constraints=(constraint1, constraint2)):
    state.add_constraints(constraint1, constraint2)

# ⚠️ 次优：分开添加（可能浪费求解时间）
state.add_constraints(constraint1)
state.add_constraints(constraint2)
```

### 6.4 Hook 长度

```python
# length=0  → 监控型，执行 hook 后继续原函数
project.hook(addr, hook_func, length=0)

# length=N  → 替换型，跳过接下来 N 字节
project.hook(addr, hook_func, length=5)
```

## 7. 调试技巧

```python
def debug_state(state):
    print(f"Address: {hex(state.addr)}, Constraints: {len(state.solver.constraints)}")
    print(f"SAT: {state.satisfiable()}")

    # 检查符号变量
    if 'input2' in state.globals:
        input2 = state.globals['input2']
        print(f"input2 symbolic: {state.solver.symbolic(input2)}")
```

## 8. 总结

**核心知识点**：
1. **栈溢出**：16 字节缓冲区 + 20 字节输入 = 覆盖指针
2. **符号指针传播**：污点分析追踪用户控制的变量
3. **Concretization**：理解默认"选最大值"策略的局限
4. **手动约束**：在符号写之前引导求解器

**关键技术对比**：

| 关卡 | 核心 | 符号对象 | Concretization |
|-----|------|---------|---------------|
| 15 | 任意读 | 源地址（读从哪） | 读地址具体化 |
| 16 | 任意写 | **目标地址（写到哪）** | **写地址具体化** |

**实战要点**：
- 自动化工具需要人工引导（添加约束）
- 使用 PLT 地址而非符号表地址
- 污点分析适合通用漏洞检测
- `satisfiable(extra_constraints=...)` 优于分步添加约束

**扩展阅读**：
- [angr Concretization Strategies](https://docs.angr.io/en/stable/advanced-topics/concretization_strategies.html)
- [Mayhem: Automatic Exploit Generation](https://users.ece.cmu.edu/~aavgerin/papers/mayhem-oakland-12.pdf)
- [angr CTF](https://github.com/jakespringer/angr_ctf)
