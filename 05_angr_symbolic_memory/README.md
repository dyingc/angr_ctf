# 05_angr_symbolic_memory CTF 挑战：符号化静态内存（.bss 全局缓冲区）

> 本关延续上一关“符号化栈变量”的思路，进一步学习 **如何直接在全局/静态内存区域创建符号变量**。
> 目标是跳过 `scanf` 调用，将 32 字节未知口令写入 `.bss` 段中的 `user_input` 数组，并让程序输出 **“Good Job.”**。

---

## 1 挑战概述

| 关卡 | 关键技术 | 读取位置 | 写入 API |
|------|----------|----------|----------|
| 03   | 符号化寄存器 | `eax/ebx/edx` | `state.regs.*` |
| 04   | 符号化栈变量 | `ebp-0xc/-0x10` | `state.memory.store()` |
| **05** | **符号化静态内存** | `.bss:user_input` | `state.memory.store()` |

本程序一次性执行
```c
__isoc99_scanf("%8s %8s %8s %8s", user_input.input0, … input3);
```
将四段各 8 字节共 **32 字节** 数据保存到 **全局结构体 `user_input`**。随后通过：

* 逐字节调用 `complex_function(ch, idx)` 变换
* 与硬编码字符串 **`"DOFCLSTWXVMUMVEOVWQHNCEWQLTZUAYH"`** 做 `strncmp`

若相同打印 *Good Job.*，否则 *Try again.*。
手工逆向 32 轮字符混淆几乎不可能，因此采用 angr 符号执行。

---

## 2 反汇编&关键地址

| 作用 | 地址 | 说明 |
|------|------|------|
| 跳过 scanf 后的第一条指令 | **`0x804928c`** | 作为 `blank_state` 起点 |
| 输出 Good Job. | **`0x80492f5`** (`push str.Good_Job.`) | `find` |
| 输出 Try again. | **`0x80492e3`** (`push str.Try_again.`) | `avoid` |
| 全局缓冲区 `user_input` | 由符号表定位 | 见下节 |

### 2.1 Ghidra 伪代码片段

```c
for (int i = 0; i < 0x20; i++) {
    user_input[i] = complex_function(user_input[i], i);
}
if (strncmp(user_input, "DOFCLSTWXVMUMVEOVWQHNCEWQLTZUAYH", 0x20) == 0) {
    puts("Good Job.");
} else {
    puts("Try again.");
}
```

该伪代码展示了程序的核心密码校验逻辑：先逐字节变换，再一次性比较 32 字节结果。

### 2.2 Radare2 汇编片段

```asm
; 0x08049293
mov dword [var_ch], 0          ; i = 0
loop_start:
mov eax, dword [var_ch]
add eax, obj.user_input
movzx eax, byte [eax]          ; eax = user_input[i]
movsx eax, al
push dword [var_ch]            ; 第二个参数 i
push eax                       ; 第一个参数 ch
call sym.complex_function
add esp, 0x10
mov edx, eax
mov eax, dword [var_ch]
add eax, obj.user_input
mov byte [eax], dl             ; 写回 user_input[i]
add dword [var_ch], 1
cmp dword [var_ch], 0x1f
jle loop_start                 ; 重复 32 次

; strncmp 比较
push 0x20
push str.DOFCLSTWXVMUMVEOVWQHNCEWQLTZUAYH
push obj.user_input
call sym.imp.strncmp
test eax, eax
je 0x80492f5                   ; Good Job.
```

通过该汇编片段可以直观看出 **循环体** 与 **成功跳转 (`je 0x80492f5`)** 的地址，
因此在脚本中将 `0x80492f5` 设为 `find`，把打印 *Try again.* 的
`0x80492e3` 设为 `avoid`。

---

## 3 核心知识

### 3.1 静态/全局变量地址

angr 加载 ELF 时会解析符号表：
```python
userinput_addr = project.loader.find_symbol('user_input').rebased_addr
```
该地址位于 `.bss`，可直接写入。

### 3.2 一次写入 32 字节

```python
sym0 = claripy.BVS('in0', 8*8)
sym1 = claripy.BVS('in1', 8*8)
sym2 = claripy.BVS('in2', 8*8)
sym3 = claripy.BVS('in3', 8*8)
symbolic_input = claripy.Concat(sym0, sym1, sym2, sym3)   # 256 bits
state.memory.store(userinput_addr, symbolic_input, size=32, endness='Iend_BE')
```
也可直接 `claripy.BVS('all', 32*8)` — 但拆分更方便求解与格式化输出。

### 3.3 跳过 scanf 的 2 种思路
1. **指定起始地址**（本关做法）： `blank_state(addr=start_addr)`
2. **Hook scanf 为空函数**（将在 10 SimProcedures 中系统介绍）

### 3.4 为什么不能直接符号化 stdin？

`scanf("%8s %8s %8s %8s")` **一次读取四段字符串并按空格分隔**。
angr 自带的 `SimProcedure scanf` 在解析 *多格式、多空格* 的复杂输入时有两大局限：

* **单包假设**：它把一次 `scanf` 视为读取 _一个_ `SimPackets` 包，无法在同一包中自动插入 3 个空格分隔符，导致解析失败。
* **不能自动拆分符号变量**：即使手动构造带空格的字节流，也只能得到 *一个* 大符号变量，而程序需要 **4 个独立缓冲区**；后续按索引写回时就会触发“跨界”约束，求解极其困难。

因此本关采用 **绕过输入→直接写内存** 的策略：
1. 跳过 `scanf` 指令，自己建立初始状态；
2. 在 `.bss:user_input` 连续 32 字节位置一次性 `store` 四段拼接好的符号变量。

这既避免了复杂输入格式，又保持了变量的独立性，极大地简化了约束求解。

---

## 4 完整解决脚本（精简版）

```python
import angr, claripy

BIN = "./binary/x32/05_angr_symbolic_memory"
proj = angr.Project(BIN, auto_load_libs=False)

# ① 创建 blank_state，直接跳到 scanf 之后
start = 0x804928c
st = proj.factory.blank_state(
        addr=start,
        add_options={angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                     angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS})

# ② 定位全局缓冲区并写入符号变量
uaddr = proj.loader.find_symbol('user_input').rebased_addr
bv = claripy.Concat(*[claripy.BVS(f'in{i}', 8*8) for i in range(4)])
st.memory.store(uaddr, bv, size=32)

# ③ 启动符号执行
simgr = proj.factory.simulation_manager(st)
simgr.explore(find=0x80492f5, avoid=0x80492e3)

if simgr.found:
    s = simgr.found[0]
    raw = s.solver.eval(bv, cast_to=bytes)          # 32 bytes
    print("Solution:", b" ".join(raw[i:i+8] for i in range(0,32,8)).decode())
```

---

## 5 实践步骤

1. 生成二进制
   ```bash
   cd 05_angr_symbolic_memory
   python generate.py 2025 05_angr_symbolic_memory
   ```
2. 在 **radare2** / **Ghidra** 中定位关键地址
   * **查找 `user_input` 全局符号**
     ```bash
     r2 -q -c 'aaa; is~user_input' binary/x32/05_angr_symbolic_memory
     ```
     `is` 列出符号表，`~user_input` 过滤得到其 *vaddr*（即 `.bss:user_input`）。
   * **确认打印字符串及其引用**
     ```bash
     r2 -q -c 'aaa; iz~Good; axt @ str.Good_Job.' binary/x32/05_angr_symbolic_memory
     ```
     `iz` 罗列只读字符串，`axt` 查看引用位置，可得 `0x80492f5`、`0x80492e3`。
   * **Ghidra**：在 *Symbol Tree ➜ Labels* 搜索 `user_input`；
     选中字符串后按 `X` 查看交叉引用，即可得到相同地址。

3. 运行上方脚本（或 `scaffold05.py` 完整注释版），得到四段口令，例如
   ```
   Solution: QJCTEQWK SFWMJRXO ZDPOENBH CXEUEFVP
   ```
4. 将其输入程序，观察 **Good Job.**

---

## 6 常见问题

| 症状 | 可能原因 |
|------|----------|
| `AttributeError: 'NoneType' object has no attribute 'rebased_addr'` | 未编译带符号表；请使用本仓库的 `generate.py` 重新生成 |
| 求解卡住耗时长 | 未设置 `avoid`，路径爆炸；或遗漏 `SYMBOL_FILL_UNCONSTRAINED_*` |
| 结果乱码 | 忘记分段或字节序错误；`endness` 对于多字节写入很关键 |

---

## 7 延伸阅读

* [angr States – memory.store/load](https://docs.angr.io/en/latest/core-concepts/states.html#low-level-interface-for-memory)
* [ELF Sections & .bss](https://en.wikipedia.org/wiki/.bss)
* 下一关 **06_angr_symbolic_dynamic_memory**：符号化 `malloc` 返回的堆内存
