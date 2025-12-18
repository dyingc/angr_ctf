看了你提供的代码后,我发现之前的文档有几处需要修正和补充。让我改进文档:

# 16_angr_arbitrary_write：任意写 (strncpy) + 符号地址具体化策略 (Concretization)

本关模拟一个"通过溢出覆盖指针 → 达成任意写 → 篡改校验位"的利用模型。
程序流程：`scanf("%u %20s")` -> 多次 `strncpy` -> `strncmp` -> `puts("Good Job.")`。

## 1. 漏洞分析与栈布局

### 1.1 栈布局图

通过 `radare2` 或 `Ghidra` 分析 `main` 函数，栈布局如下：

```
高地址
├─────────────┤
│   saved EBP │  ebp+0x00
├─────────────┤
│  return addr│  ebp-0x04
├─────────────┤
│     key     │  ebp-0x08  (4 bytes, scanf 的第 1 个参数)
├─────────────┤
│    dest     │  ebp-0x0c  (4 bytes, 指针变量) ← 溢出目标！
├─────────────┤
│             │  ebp-0x10
│user_input_2 │  ebp-0x14
│  (16 bytes) │  ebp-0x18
│             │  ebp-0x1c  ← scanf 的第 2 个参数起始地址
├─────────────┤
低地址
```

**关键观察**：
- `user_input_2` 起始于 `ebp-0x1c`，大小 16 字节（占据 `ebp-0x1c` 到 `ebp-0x0d`）
- `dest` 指针位于 `ebp-0x0c`，大小 4 字节
- 两者**紧邻**，无 padding
- `scanf("%20s", user_input_2)` 允许写入 20 字节 + null terminator，会溢出覆盖 `dest`

### 1.2 初始化陷阱

程序在 `0x080491e5` 处初始化了 `dest`：
```asm
mov dword [dest], obj.unimportant_buffer  ; dest = &unimportant_buffer
```

这会让逆向者误以为所有 `strncpy` 都写向 `unimportant_buffer`，**但这是个陷阱**！

## 2. 关键指令序列详解

### 2.1 溢出发生点

```asm
0x08049229  lea    eax, [ebp-0x1c]         ; eax = &user_input_2
0x0804922c  push   eax
0x0804922d  push   0x474e4230              ; 格式串地址 "%u %20s"
0x08049237  call   __isoc99_scanf          ; scanf("%u %20s", &key, user_input_2)
```

**为什么溢出发生在这里？**

1. **格式串 `%20s`** 允许写入最多 **20 个非空白字符**（不包括 null terminator）
2. `user_input_2` 缓冲区只有 **16 字节**
3. 写入超过 16 字节的数据会向高地址溢出：
   ```
   user_input_2[0..15]  → ebp-0x1c ~ ebp-0x0d  (16 bytes)
   user_input_2[16..19] → ebp-0x0c ~ ebp-0x09  (4 bytes, 覆盖 dest 指针！)
   user_input_2[20]     → ebp-0x08             (null terminator 覆盖 key 低字节)
   ```

4. **结果**：`dest` 指针的 4 个字节被我们输入的第 17-20 个字符替换，变成**符号值**

**代码中的体现**：
```python
# 在 Scanf SimProcedure 中
input2 = self.state.solver.BVS("input2", 20 * 8)  # 20 字节，160 位

# input2 的布局：
# [0:127]   → user_input_2 缓冲区 (16 bytes)
# [128:159] → 溢出部分，覆盖 dest 指针 (4 bytes)
```

### 2.2 漏洞触发点（任意写）

第三次 `strncpy` 是关键：

```asm
0x0804926c  mov    eax, dword [ebp-0x0c]   ; eax = dest（已被溢出覆盖！）
0x0804926f  push   0x10                     ; n = 16
0x08049274  lea    edx, [ebp-0x1c]         ; edx = &user_input_2
0x08049277  push   edx                      ; src
0x08049278  push   eax                      ; dest（来自被覆盖的指针）
0x08049279  call   strncpy                  ; strncpy(被控制的dest, user_input_2, 16)
```

**四次 `strncpy` 调用对比**：

| 调用次数 | 地址 | dest 参数 | 能否控制 | 汇编指令 |
|---------|------|-----------|---------|----------|
| 第 1 次 | 0x0804920e | `password_buffer` | ❌ 硬编码 | `push obj.password_buffer` |
| 第 2 次 | 0x08049262 | `unimportant_buffer` | ❌ 硬编码 | `push obj.unimportant_buffer` |
| **第 3 次** | **0x08049279** | **从 `[ebp-0x0c]` 加载** | **✅ 可控** | **`mov eax, [dest]` + `push eax`** |
| 第 4 次 | 0x08049291 | `unimportant_buffer` | ❌ 硬编码 | `push obj.unimportant_buffer` |

**Ghidra 反编译陷阱**：
```c
// Ghidra 显示（误导性的）：
strncpy(unimportant_buffer, user_input_2, 0x10);  // 第 3 次

// 实际上：
strncpy(dest, user_input_2, 0x10);  // dest 已被溢出篡改！
```

### 2.3 校验点

```asm
0x0804929d  push   0x8                      ; n = 8
0x080492a2  push   0x47424e58              ; "IDGNGCXX"
0x080492a7  push   password_buffer_addr
0x080492a9  call   strncmp                  ; strncmp(password_buffer, "IDGNGCXX", 8)
0x080492ae  add    esp, 0x10
0x080492b1  test   eax, eax
0x080492b3  jz     LAB_080492c7             ; if (result == 0) goto Good Job
```

要通过这个检查，必须让 `password_buffer` 的前 8 字节等于 `"IDGNGCXX"`。

## 3. 核心难点：符号地址具体化 (Concretization)

### 3.1 问题根源

即使我们知道 `dest` 已被符号化，为什么直接 `simgr.explore()` 搜不到解？

**原因**：angr 对**符号化内存写入 (Symbolic Write)** 采取保守的默认策略。

### 3.2 angr 的默认具体化行为

根据 [angr 官方文档](https://docs.angr.io/en/stable/advanced-topics/concretization_strategies.html)：

> angr 在符号地址被用作写入目标时，会对其进行**具体化 (Concretize)**。

**默认写入具体化策略链**（按顺序尝试）：
1. **SimConcretizationStrategyRange(128, filter=multiwrite)**
   - 仅对带 `MultiwriteAnnotation` 标记的符号变量生效
   - 如果范围 ≤ 128，枚举所有可能地址并生成 ITE 表达式

2. **SimConcretizationStrategyMax**
   - 选择符号变量的**最大可能值**
   - 这是**兜底策略**，确保总能得到一个具体地址

### 3.3 具体到本题的情况

在第三次 `strncpy` 调用点（`0x08049279`）：

1. **`dest` 是符号值**（来自 `input2[128:159]`，即溢出的 4 字节）
2. angr 执行到 `strncpy(dest, user_input_2, 16)` 时触发符号写
3. **MultiwriteAnnotation 策略**不满足（我们没有标记）
4. **Max 策略**生效：
   ```python
   concrete_dest = state.solver.max(dest)  # 选择最大可能值
   state.add_constraints(dest == concrete_dest)  # 锁定这个值
   ```

5. **问题**：`max(dest)` 在满足约束的前提下，极大概率返回**栈空间内的某个高地址**
   原因：
   - `dest` 的 4 字节来自 `input2[16:19]`（字节索引），初始无约束
   - 求解器倾向于选择最大的 32 位地址
   - 由于要保证"内存可访问"（angr 会隐式检查页表），实际会落在已映射区域的高端
   - 栈区域通常在 `0xbfxxxxxx`（32 位程序），是合法地址中较大的
   - `password_buffer`（全局变量）通常在 `0x0804xxxx`，远小于栈地址

6. **结果**：
   ```
   strncpy(0xbfxxxxxx, user_input_2, 16)  // 写到栈的某个随机位置
   password_buffer 仍然是 "PASSWORD"
   strncmp 失败 → 路径被剪枝
   ```

### 3.4 为什么需要手动约束？

**核心矛盾**：
- **求解器视角**：`dest` 可以是任何满足约束的 4 字节地址，默认选最大值
- **利用视角**：我们需要 `dest == password_buffer` 这个**特定的小地址**

**结论**：必须显式告诉求解器："不要选最大值，选这个特定地址"。

### 3.5 验证：输出调试信息

在提供的代码中，hook 函数会输出调试信息：

```python
def _hook_strncpy(s: SimState):
    dest_buf = s.memory.load(dest_buf_stack_loc, 4, endness=s.arch.memory_endness)

    if _is_controlled(s, dest_buf) and _is_controlled(s, src_buf_contents):
        print("[*] strncpy called with a symbolic source buffer!")
        # 此时 dest_buf 是符号值，受 input2 控制
        # 如果不添加约束，angr 会自动具体化为最大值
```

## 4. 解法 A：Hook strncpy 添加约束（模板解法）

### 4.1 核心思路

在 **所有** `strncpy` 调用点检查是否同时满足：
1. **dest 参数是符号值**（可被我们控制）
2. **src 内容是符号值**（可被我们控制）

如果同时满足，这就是任意写漏洞！此时添加约束：
- `dest == password_buffer`
- `src[:8] == b"IDGNGCXX"`

### 4.2 关键代码解析

```python
def check_strncpy(state):
    # 栈布局（x86 cdecl）：
    # [esp+0]  = return address
    # [esp+4]  = dest (参数0)
    # [esp+8]  = src  (参数1)
    # [esp+12] = len  (参数2)

    strncpy_dest = state.memory.load(
        state.regs.esp + 4, 4,
        endness=project.arch.memory_endness
    )
    strncpy_src = state.memory.load(
        state.regs.esp + 8, 4,
        endness=project.arch.memory_endness
    )
    strncpy_len = state.memory.load(
        state.regs.esp + 12, 4,
        endness=project.arch.memory_endness
    )

    # 加载 src 指向的内容（需要知道长度）
    # 这里我们只关心前 8 字节（密码长度）
    src_contents = state.memory.load(strncpy_src, 8)

    # 检查是否同时可控
    if state.solver.symbolic(strncpy_dest) and state.solver.symbolic(src_contents):
        password_string = b"IDGNGCXX"
        buffer_address = 0x0804A048  # password_buffer 的地址（从 radare2 获取）

        # 构造约束（注意位索引）
        # bitvector 索引是从右到左，且是位索引
        # 对于 64 位 bitvector（8 字节）：
        #   b[63:56] = 第 1 个字节
        #   b[55:48] = 第 2 个字节
        #   ...
        #   b[7:0]   = 第 8 个字节
        #
        # 或者用负数索引（更直观）：
        #   b[-1:-9]   = 前 8 位（不对！）
        #   b[63:0]    = 全部 8 字节
        does_src_hold_password = src_contents == password_string
        does_dest_equal_buffer_address = strncpy_dest == buffer_address

        # 使用 extra_constraints 预检查
        if state.satisfiable(extra_constraints=(
            does_src_hold_password,
            does_dest_equal_buffer_address
        )):
            state.add_constraints(does_src_hold_password, does_dest_equal_buffer_address)
            return True
        else:
            return False
    else:
        return False

# Hook 方式 1：在 strncpy 调用时检查
simulation = project.factory.simgr(initial_state)

def is_successful(state):
    strncpy_address = 0x08049070  # strncpy 函数入口（PLT）
    if state.addr == strncpy_address:
        return check_strncpy(state)
    else:
        return False

simulation.explore(find=is_successful)
```

**为什么 Hook strncpy 而不是特定调用点？**

模板解法采用"通用检测"策略：
- Hook `strncpy` 函数本身（PLT 入口）
- 每次调用都检查参数是否可控
- 优点：不需要预先知道哪次调用有漏洞
- 缺点：会检查所有调用（性能较低）

### 4.3 关于 strncpy 地址的坑

```python
# ❌ 错误：使用符号表地址
strncpy_sym = project.loader.find_symbol('strncpy')
strncpy_addr = strncpy_sym.rebased_addr  # 可能是 GOT 表地址，不是 PLT！

# ✅ 正确：使用 PLT 地址（从 radare2 获取）
strncpy_addr = 0x08049070  # strncpy@plt
```

**为什么会有这个问题？**
- `find_symbol('strncpy')` 可能返回 GOT 表项或其他符号位置
- 我们需要的是 **PLT stub**（过程链接表）地址
- PLT 是实际被 `call` 指令跳转的目标

**如何找到正确地址？**
```bash
# 使用 radare2
$ r2 -A binary
[0x08048xxx]> afl | grep strncpy
0x08049070    6 48           sym.imp.strncpy

# 使用 objdump
$ objdump -d binary | grep strncpy
08049070 <strncpy@plt>:
```

## 5. 解法 B：污点检测与自动化审计（工作版本）

### 5.1 思路

这是一种更智能的方法：
1. **Hook scanf**：注入带标记的符号变量 `input1` 和 `input2`
2. **Hook strncpy**：检测参数是否受这些符号变量影响
3. **Hook strncmp**：监控校验点的输入

### 5.2 完整实现解析

#### 5.2.1 污点判断

```python
def _is_controlled(s: SimState, var: claripy.ast.bv.BV) -> bool:
    """检查变量是否受用户输入控制（污点分析）"""
    if s.solver.symbolic(var):
        # 获取变量名集合
        sym_names = var.variables
        # 检查是否包含我们注入的标记
        return any('input1' in name or 'input2' in name for name in sym_names)
    return False
```

这是一个简化的污点追踪：
- 在 scanf 处注入 `BVS("input1", ...)` 和 `BVS("input2", ...)`
- 后续所有依赖这些变量的表达式都会继承这些名字
- 通过检查变量名就能判断是否受用户控制

#### 5.2.2 Hook scanf

```python
class Scanf(SimProcedure):
    def run(self, fmt: str, input1_ptr: claripy.BVV, input2_ptr: claripy.BVV):
        # 第一个输入：无符号整数（32 位）
        input1 = self.state.solver.BVS("input1", 32)
        self.state.memory.store(input1_ptr, input1, endness=self.arch.memory_endness)

        # 第二个输入：字符串（最多 20 字节）
        input2 = self.state.solver.BVS("input2", 20 * 8)  # 160 位

        # 约束 input2 为可见 ASCII 字符
        for i in range(20):
            char = input2.get_byte(i)  # 获取第 i 个字节
            self.state.add_constraints(char >= 0x20)  # ' '
            self.state.add_constraints(char <= 0x7e)  # '~'

        # 存储到内存
        self.state.memory.store(input2_ptr, input2)

        # 保存到全局变量供后续提取
        self.state.globals['input1'] = input1
        self.state.globals['input2'] = input2

        return 2  # scanf 返回成功读取的项目数
```

**关键点**：
- `input2` 是 **20 字节**，会溢出覆盖 `dest` 指针
- 使用 `BVS` 的名字作为污点标记
- 存储到 `state.globals` 供后续求解

#### 5.2.3 Hook strncpy（监控版）

```python
def hook_strncpy(proj: angr.Project):
    def _hook_strncpy(s: SimState):
        # 读取参数
        dest_buf = s.memory.load(s.regs.esp + 4, 4, endness=s.arch.memory_endness)
        src_buf = s.memory.load(s.regs.esp + 8, 4, endness=s.arch.memory_endness)
        src_buf_contents = s.memory.load(src_buf, 8)

        # 检查是否同时可控
        if _is_controlled(s, dest_buf) and _is_controlled(s, src_buf_contents):
            print("[*] strncpy called with symbolic dest and src!")

            # 添加约束
            password_buffer_addr = proj.loader.find_symbol('password_buffer').rebased_addr
            s.add_constraints(dest_buf == password_buffer_addr)
            s.add_constraints(src_buf_contents == b'IDGNGCXX')

            # 立即检查是否可满足
            if s.solver.satisfiable():
                key = s.solver.eval(s.globals['input1'], cast_to=int)
                pwd = s.solver.eval(s.globals['input2'], cast_to=bytes)
                print(f"    [*] Found satisfiable: key={key}, pwd={pwd.decode()}")

    return _hook_strncpy

# 安装 hook（长度为 0，表示不替换原函数）
project.hook(0x08049070, hook_strncpy(project), length=0)
```

**为什么 `length=0`？**
- 表示这是一个"监控 hook"，不替换原函数
- angr 会先执行 hook 函数，然后继续执行原始的 strncpy
- 如果 `length > 0`，会跳过接下来的 N 个字节，相当于替换原函数

#### 5.2.4 Hook strncmp（可选监控）

```python
def hook_strncmp(s: SimState):
    src_buf = s.memory.load(s.regs.esp + 4, 4, endness=s.arch.memory_endness)
    length_val = s.memory.load(s.regs.esp + 0xc, 4, endness=s.arch.memory_endness)
    src_buf_contents = s.memory.load(src_buf, length_val)

    if _is_controlled(s, src_buf) or _is_controlled(s, src_buf_contents):
        print("[*] strncmp called with controlled input!")
        # 可以在这里添加额外的约束或记录
```

### 5.3 两种解法的对比

| 特性 | 模板解法（scaffold） | 污点检测解法（工作版） |
|------|---------------------|----------------------|
| **Hook 点** | strncpy 函数入口（PLT） | strncpy PLT |
| **检测方式** | 检查参数是否 symbolic | 检查参数是否包含特定污点标记 |
| **scanf 处理** | SimProcedure 替换 | SimProcedure 替换 |
| **约束时机** | 在 `is_successful` 判断中 | 在 strncpy hook 中立即添加 |
| **调试输出** | 较少 | 详细（打印每次触发） |
| **适用场景** | 教学示例 | 实际审计/漏洞挖掘 |

## 6. 与前几关的对比

| 关卡 | 核心技术 | 重点 API | 内存操作 | 符号化对象 | Concretization |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **09** | Hook | `project.hook` | ❌ | 返回值 | ❌ |
| **10** | SimProcedure | `hook_symbol` | ❌ | 函数参数 | ❌ |
| **15** | 任意读 | `symbolic_read` | ✅ 读取 | **源地址** | ✅ 读地址 |
| **16** | 任意写 | `concretization` | ✅ 写入 | **目标地址** | ✅ **写地址** |

**技术演进**：
- **15 关**：符号化"读取的源地址" → 约束读出的**内容**
- **16 关**：符号化"写入的目标地址" → 约束写入的**位置**（更难！）

## 7. 常见坑位与解决方案

### 7.1 栈布局计算错误

```python
# ❌ 错误：混淆缓冲区大小和 scanf 限制
user_input_2_size = 20  # scanf 允许的最大长度
dest_offset = user_input_2_size  # 错误！dest 在 16 字节后

# ✅ 正确：基于实际布局
user_input_2_buffer_size = 16  # 实际分配的缓冲区大小
dest_offset = 16  # dest 在 ebp-0x0c，user_input_2 在 ebp-0x1c
overflow_bytes = 20 - 16  # 溢出 4 字节
```

### 7.2 地址未 Rebase

```python
# ❌ 错误：使用静态分析工具显示的地址
password_buffer_addr = 0x0804a048  # 在模板中写死

# ✅ 正确：动态获取（推荐）
password_buffer_sym = project.loader.find_symbol('password_buffer')
if password_buffer_sym is None:
    raise Exception("password_buffer symbol not found")
password_buffer_addr = password_buffer_sym.rebased_addr

# 🔍 调试：检查地址是否正确
print(f"[DEBUG] password_buffer @ {hex(password_buffer_addr)}")
```

### 7.3 strncpy 地址问题

你的代码中提到的问题：

```python
# ❌ 为什么这个不工作？
strncpy_sym = project.loader.find_symbol('strncpy')
strncpy_addr = strncpy_sym.rebased_addr  # 可能是 0x47500010（错误的地址）

# ✅ 使用 radare2 找到的 PLT 地址
strncpy_addr = 0x08049070  # 这是正确的 PLT stub 地址
```

**原因分析**：
1. `find_symbol('strncpy')` 可能返回：
   - GOT 表项（Global Offset Table）
   - 外部符号的占位符
   - 或者其他非 PLT 的地址

2. 我们需要的是 **PLT stub**（Procedure Linkage Table）：
   ```asm
   08049070 <strncpy@plt>:
   8049070:	ff 25 xx xx xx xx    jmp    *GOT_entry
   8049076:	68 xx xx xx xx       push   reloc_index
   804907b:	e9 xx xx xx xx       jmp    _dl_runtime_resolve
   ```

3. **解决方案**：
   ```python
   # 方法 1：手动从 radare2/objdump 获取
   strncpy_plt = 0x08049070

   # 方法 2：使用 angr 的 PLT API（如果支持）
   plt = project.loader.main_object.plt
   if 'strncpy' in plt:
       strncpy_plt = plt['strncpy']
   ```

### 7.4 Hook 时机与长度

```python
# ❌ 错误：Hook 错误的位置
project.hook_symbol('strncpy', my_hook)  # 可能 hook 到 GOT 表

# ✅ 正确：Hook PLT stub（函数入口）
project.hook(0x08049070, my_hook, length=0)

# ⚠️ 注意 length 参数：
# length=0  → 监控型 hook，执行 hook 后继续执行原函数
# length=5  → 替换型 hook，跳过接下来的 5 字节（通常是 call 指令长度）
```

### 7.5 Bitvector 索引陷阱

```python
# 对于 8 字节（64 位）bitvector：
password = claripy.BVV(b"IDGNGCXX", 64)  # 64 位

# ❌ 错误：Python 切片风格（不适用）
# password[0:8]  # 这不是你想的那样！

# ✅ 正确：直接比较（最简单）
src_contents == b"IDGNGCXX"

# ✅ 正确：位索引（如果需要部分比较）
# password[63:56] == ord('I')  # 第 1 个字节
# password[7:0]   == ord('X')  # 第 8 个字节

# 🎯 记忆技巧：bitvector 的"最左边"是高位（MSB）
```

### 7.6 约束添加时机

```python
# ⚠️ 次优：分开添加约束
state.add_constraints(dest == target_addr)
state.add_constraints(src_content == b"IDGNGCXX")
# 问题：第一个约束可能导致状态变为 unsat，浪费求解时间

# ✅ 推荐：先用 satisfiable 检查，再一次性添加
if state.satisfiable(extra_constraints=(
    dest == target_addr,
    src_content == b"IDGNGCXX"
)):
    state.add_constraints(dest == target_addr, src_content == b"IDGNGCXX")
else:
    return False  # 提前剪枝
```

### 7.7 污点标记丢失

```python
# ❌ 问题：创建新的 BVV 会丢失污点
new_var = claripy.BVV(state.solver.eval(input2), 160)  # 污点标记丢失！

# ✅ 正确：直接使用原始符号变量
# 不要具体化除非必要
if state.solver.symbolic(var):
    # 保持符号状态
    state.add_constraints(var == target_value)
```

## 8. 调试技巧

### 8.1 打印约束信息

```python
def debug_state(state):
    print(f"[DEBUG] Current address: {hex(state.addr)}")
    print(f"[DEBUG] Number of constraints: {len(state.solver.constraints)}")

    # 打印最近添加的约束
    if len(state.solver.constraints) > 0:
        print(f"[DEBUG] Last constraint: {state.solver.constraints[-1]}")

    # 检查可满足性
    if state.satisfiable():
        print("[DEBUG] State is SAT ✓")
    else:
        print("[DEBUG] State is UNSAT ✗")
```

### 8.2 追踪符号变量传播

```python
def trace_symbolic_var(state, var_name):
    """追踪某个符号变量在内存和寄存器中的位置"""
    print(f"\n[TRACE] Searching for '{var_name}':")

    # 检查寄存器
    for reg_name in state.arch.register_names.values():
        try:
            reg_val = state.registers.load(reg_name)
            if state.solver.symbolic(reg_val) and var_name in str(reg_val):
                print(f"  Found in register {reg_name}: {reg_val}")
        except:
            pass

    # 检查栈（示例）
    esp = state.solver.eval(state.regs.esp)
    for offset in range(0, 64, 4):
        try:
            stack_val = state.memory.load(esp + offset, 4)
            if state.solver.symbolic(stack_val) and var_name in str(stack_val):
                print(f"  Found at [esp+{offset}]: {stack_val}")
        except:
            pass
```

### 8.3 比较不同路径的约束

```python
def compare_states(state1, state2):
    """比较两个状态的约束差异"""
    constraints1 = set(str(c) for c in state1.solver.constraints)
    constraints2 = set(str(c) for c in state2.solver.constraints)

    only_in_1 = constraints1 - constraints2
    only_in_2 = constraints2 - constraints1

    print(f"State1 unique constraints: {len(only_in_1)}")
    for c in list(only_in_1)[:5]:  # 只打印前 5 个
        print(f"  {c}")

    print(f"State2 unique constraints: {len(only_in_2)}")
    for c in list(only_in_2)[:5]:
        print(f"  {c}")
```

## 9. 扩展阅读

### 9.1 官方文档
- [angr Concretization Strategies](https://docs.angr.io/en/stable/advanced-topics/concretization_strategies.html)
- [angr Memory Model](https://docs.angr.io/en/stable/core-concepts/states.html#memory)
- [angr Solver API](https://docs.angr.io/en/stable/core-concepts/solver.html)
- [angr Hook System](https://docs.angr.io/en/stable/core-concepts/hooks.html)

### 9.2 学术论文
- [Mayhem: Automatic Exploit Generation](https://users.ece.cmu.edu/~aavgerin/papers/Mayhem-Oakland-12.pdf)
  → angr 符号内存模型的理论基础
- [Under-Constrained Symbolic Execution](https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-ramos.pdf)
  → 处理部分符号化程序的技术
- [MemSight: Rethinking Pointer Reasoning in Symbolic Execution](http://season-lab.github.io/papers/memsight-ase17.pdf)
  → 改进的符号指针处理方法

### 9.3 实战案例
- [angr CTF](https://github.com/jakespringer/angr_ctf) - 官方练习题库
- [Cyber Grand Challenge](https://github.com/CyberGrandChallenge) - DARPA 自动化漏洞挖掘竞赛
- [angr Examples](https://github.com/angr/angr-doc/tree/master/examples) - 官方示例集合

## 10. 总结

**本关核心知识点**：
1. **栈溢出机制**：理解局部变量布局，精确计算溢出距离（16→20 字节覆盖 4 字节指针）
2. **符号指针传播**：追踪哪些指针受用户输入控制（污点分析）
3. **Concretization 策略**：理解 angr 默认选择最大值的原因及其局限性
4. **手动约束引导**：学会在关键点（符号写之前）注入约束引导求解器
5. **Hook 技巧**：
   - 选择正确的 hook 点（PLT vs GOT vs 调用点）
   - 使用 `length=0` 实现监控型 hook
   - 在 hook 中访问函数参数（通过栈偏移）

**实战启示**：
- 自动化工具（angr）+ 人工智能（你的领域知识）= 成功
- 了解工具内部机制 > 盲目调参
- 符号执行不是万能的，需要辅以：
  - 静态分析（找到关键路径）
  - 动态调试（验证假设）
  - 人工约束（引导搜索）

**进阶方向**：
1. 实现更智能的污点分析（跨函数追踪）
2. 自动识别栈溢出点（模式匹配）
3. 使用 `SYMBOLIC_WRITE_ADDRESSES` 选项（需要理解性能影响）
4. 结合 fuzzing 和符号执行（hybrid analysis）