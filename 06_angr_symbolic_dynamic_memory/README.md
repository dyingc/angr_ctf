# 06_angr_symbolic_dynamic_memory CTF 挑战：符号化 **堆内存** 与字节序陷阱

> 本关在前几关基础上，进一步演示 **动态内存 (malloc) 上的符号变量** 创建方式。
> 关键难点是：**在 x86 小端架构下写入“指针数值”必须显式指定 `endness`**，否则约束无法传播，导致求解失败。

---

## 1 关卡概述

| 关卡 | 输入位置 | 关键 API | 主要坑点 |
|------|----------|---------|---------|
| 04   | 栈帧 (`ebp - n`) | `state.memory.store()` | 手动建立栈帧 |
| 05   | `.bss : user_input` | `store` 全局缓冲区 | 跳过 `scanf` |
| **06** | **堆指针 -> 动态缓冲区** | `state.heap.allocate()` + `store(ptr)` | **指针写回需 endness** |

程序逻辑：

1. `buffer0 = malloc(9); buffer1 = malloc(9);`
2. `scanf("%8s %8s", buffer0, buffer1);`
3. 8 次循环：`complex_function` 变换两个缓冲区各 8 字节
4. `strncmp(buffer0,"WPZHAGQE",8)` 与 `strncmp(buffer1,"YFJWGPGQ",8)`
   均为 0 → *Good Job.* 否则 *Try again.*
5. `free(buffer0); free(buffer1);`

---

## 2 快速逆向

### 2.1 Ghidra 伪代码（核心部分）

```c
for (i = 0; i < 8; i++) {
    buffer0[i] = complex_function(buffer0[i], i);
    buffer1[i] = complex_function(buffer1[i], i + 0x20);
}
if (!strncmp(buffer0,"WPZHAGQE",8) &&
    !strncmp(buffer1,"YFJWGPGQ",8))
        puts("Good Job.");
else   puts("Try again.");
```

### 2.2 Radare2 关键地址

| 功能 | 地址 |
|------|------|
| 跳过 `scanf` 后第一条指令 | **`0x80492e3`** (起始) |
| Good Job. | **`0x80493a6`** (`push str.Good_Job.`) |
| Try again. | **`0x8049394`** |
| 全局指针 `buffer0` / `buffer1` | `is~buffer0` / `buffer1` |

---

## 3 核心学习点

### 3.1 符号化堆内存

```python
heap_buf0 = state.heap.allocate(9)
heap_buf1 = state.heap.allocate(9)
```

* angr 自带 **toppage allocator**，地址稳定可重现
* 需手动写入 `\x00` 终止符

### 3.2 **指针写回必须指定字节序**

| 操作对象 | `endness` 可省略? | 错误后果 |
|----------|-----------------|---------|
| **数据字节串** | 理论可省，angr 会自动 `Reverse()` | 性能下降，但可求解 |
| **指针/多字节整数** | **绝不可省** | 程序读取到错误地址 → 约束永远不含目标变量 → Z3 解为 0 |

```python
state.memory.store(ptr_slot, heap_buf0,
                   endness=project.arch.memory_endness)  # 小端
```

调试技巧：若 `solver.constraints` 中完全看不到 `input0` 符号，首先检查此处字节序。

> ⚠️ **字符串无需指定 `endness`**
> `char` 数组是逐字节读写，若在 `state.memory.store()` 时强行加上小端翻转，
> `"ABC"` 会被写成 `"CBA"`，破坏原始顺序；因此只有写入 **指针或多字节整数** 时才必须显式声明 `endness`。

---

## 4 参考解脚本（节选）

```python
proj = angr.Project('./binary/x32/06_angr_symbolic_dynamic_memory', auto_load_libs=False)
start = 0x80492e3
st = proj.factory.blank_state(addr=start,
        add_options={angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                     angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS})

# 1. 创建符号变量 (8 字节 + 终止符)
in0 = claripy.BVS('input0', 8*8)
in1 = claripy.BVS('input1', 8*8)

# 2. 申请堆并写入
buf0 = st.heap.allocate(9)
buf1 = st.heap.allocate(9)
st.memory.store(buf0, in0)
st.memory.store(buf1, in1)
st.memory.store(buf0+8, claripy.BVV(0,8))
st.memory.store(buf1+8, claripy.BVV(0,8))

# 3. 把指针写回全局变量
g_buf0 = proj.loader.find_symbol('buffer0').rebased_addr
g_buf1 = proj.loader.find_symbol('buffer1').rebased_addr
st.memory.store(g_buf0, buf0, endness=proj.arch.memory_endness)
st.memory.store(g_buf1, buf1, endness=proj.arch.memory_endness)

# 4. Solver
sm = proj.factory.simulation_manager(st)
sm.explore(find=0x80493a6, avoid=0x8049394)
if sm.found:
    s = sm.found[0]
    pwd0 = s.solver.eval(in0, cast_to=bytes)
    pwd1 = s.solver.eval(in1, cast_to=bytes)
    print(pwd0, pwd1)
```

---

## 5 实践步骤

1. **生成二进制**

```bash
cd 06_angr_symbolic_dynamic_memory
python generate.py 2025 06_angr_symbolic_dynamic_memory
```

2. **radare2 获取符号与地址**

```bash
r2 -q -c 'aaa; is~buffer' binary/x32/06_angr_symbolic_dynamic_memory
r2 -q -c 'aaa; iz~Good; axt @ str.Good_Job.' binary/x32/06_angr_symbolic_dynamic_memory
```

3. **运行 script / scaffold06.py**
   得到两段 8 字节口令，空格分隔输入，即可看到 *Good Job.*。

---

## 6 常见错误

| 症状 | 诊断 |
|------|------|
| 约束里找不到 `input0/1` | 指针写回时漏写 `endness` |
| Z3 求解全 0 | 同上；或忘写 `\x00` 终止符 |
| State 卡在 `free()` | 起始地址应在循环前，且避开 `free`，建议 `find/avoid` 如上 |

---

## 7 延伸阅读

* **angr Heap 模型**：<https://docs.angr.io/en/latest/core-concepts/memory.html#the-heap>
* **字节序与 `Reverse()` AST**：查看 Claripy 输出
* 下一关 **07_angr_symbolic_file**：符号文件对象技巧
