# 05_angr_symbolic_memory CTF 挑战：符号化静态内存

## 挑战概述

`05_angr_symbolic_memory` 是 angr CTF 系列中一个关于**符号化静态内存**的重要挑战。在之前的挑战中，我们学会了如何符号化标准输入、CPU 寄存器以及栈上的局部变量。本关将聚焦于更深层次的内存操作：**直接对程序数据段或 BSS 段中的全局变量进行符号化**。

在这个挑战中，程序会从用户处读取 32 个字符的密码，并将其存储在一个**全局数组**中。我们的任务是绕过 `scanf` 的默认行为，直接在内存中创建符号变量，并将它们放置在全局数据区的正确位置，以模拟 `scanf` 的执行结果。

这个挑战将教会您如何：

*   **理解程序内存布局**：特别是数据段（.data）和未初始化数据段（.bss）的作用，以及全局变量的存储方式。
*   **定位全局变量的绝对地址**：学习如何使用反汇编工具（如 Rizin）来查找全局变量在内存中的固定地址。
*   **在任意绝对内存地址写入符号值**：使用 `state.memory.store()` 或 `state.mem[...]` 这一核心功能，将符号变量精确地注入到全局数据区的特定位置。
*   **处理字符串分段输入**：理解 `scanf("%8s %8s %8s %8s")` 如何将一个 32 字节的输入拆分为 4 个 8 字节的字符串进行处理。

掌握这些技能对于分析更复杂的二进制文件至关重要，特别是那些涉及全局配置、共享数据结构或需要直接操作特定内存区域的程序。

## 关键学习要点

为了成功解决 `05_angr_symbolic_memory` 挑战，请重点学习以下概念和 angr 官方文档：

1.  **创建空白状态 (`project.factory.blank_state`)**
    *   **学习目标**：理解 `blank_state` 的用途。与从程序入口点开始的 `entry_state` 不同，`blank_state` 允许我们创建一个“空白”的、可完全自定义的初始状态。我们可以指定执行的起始地址 (`addr`)，并配置寄存器和内存的初始值。这对于跳过 `scanf` 调用并直接进入核心逻辑至关重要。
    *   **推荐阅读**：[States](https://docs.angr.io/en/latest/core-concepts/states.html) - 了解不同类型的 `SimState` 以及如何创建它们。

2.  **符号化未初始化内存 (`angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY`)**
    *   **学习目标**：理解此选项的作用。当 angr 遇到未初始化的内存区域时，此选项会指示 angr 自动用符号值填充这些区域。这对于处理全局变量（通常位于 `.bss` 段，默认初始化为零）非常有用，因为它允许 angr 在不明确指定每个字节为符号的情况下，将其视为符号。
    *   **推荐阅读**：[Options](https://docs.angr.io/en/latest/core-concepts/options.html)

3.  **在内存中读写 (`state.memory.store`, `state.mem[...]`)**
    *   **学习目标**：这是本挑战最核心的技能。学习如何使用 `state.memory.store(address, value)` 将一个符号变量（或具体值）写入到模拟内存的任意地址。同时，了解如何使用 `state.memory.load` 来读取值。
    *   **`state.mem[...]` 的便利性**：angr 提供了更 Pythonic 的内存访问接口，例如 `state.mem[address].uint32_t = symbolic_value`。这种方式在底层与 `state.memory.store` 等价，但语法更简洁，并能自动处理字节序和位宽。
    *   **关键参数 `endness`**: 理解字节序（Endianness）的重要性。在 x86 架构中，数据以小端序（Little-Endian）存储，因此在写入多字节数据（如一个32位整数）时，可能需要指定 `endness='Iend_LE'` 以确保 angr 按正确的字节顺序存储它。对于 `state.mem[...]` 接口，angr 通常会根据类型推断。
    *   **推荐阅读**：[Low level interface for memory](https://docs.angr.io/en/latest/core-concepts/states.html#low-level-interface-for-memory) - 这篇文档详细介绍了如何与 angr 的模拟内存进行交互。

4.  **通过标准输出检查状态 (`state.posix.dumps`)**
    *   **学习目标**：学习一种更灵活的、不依赖于特定代码地址的成功/失败判断方法。通过 `state.posix.dumps(sys.stdout.fileno())` 可以获取到该状态下模拟的标准输出内容。我们可以检查这个输出中是否包含 "Good Job." 或 "Try again." 字符串来引导符号执行的 `explore`。
    *   **推荐阅读**：[Exploring and analysing states](https://docs.angr.io/en/latest/appendix/cheatsheet.html#exploring-and-analysing-states)

## 背景知识：符号化静态内存

要理解本挑战的解法，我们首先需要回顾程序在内存中的布局，特别是静态数据区。

### 什么是静态内存？

在 C 语言中，全局变量和静态变量（包括函数内的静态变量）通常存储在程序的**静态数据区**。这个区域在程序加载时就被分配，并在整个程序生命周期内都存在。它主要分为两个部分：

*   **`.data` 段**：存储已初始化的全局变量和静态变量。
*   **`.bss` 段**：存储未初始化的全局变量和静态变量。这些变量在程序启动时会被操作系统自动清零。

本挑战中的 `user_input` 数组就是一个未初始化的全局变量，它将位于 `.bss` 段。

### 静态内存与动态内存/栈内存的区别

| 内存类型 | 分配时机 | 生命周期 | 存储内容 | 地址特性 |
| :------- | :------- | :------- | :------- | :------- |
| **静态内存** | 程序加载时 | 整个程序运行期间 | 全局变量、静态变量 | 固定不变（若无 PIE） |
| **栈内存** | 函数调用时 | 函数执行期间 | 局部变量、函数参数、返回地址 | 相对 `ebp/rsp` 偏移，随函数调用动态变化 |
| **堆内存** | 运行时动态分配（`malloc`/`new`） | 从分配到释放 | 动态数据结构 | 运行时确定，不固定 |

### 与上一关（04 符号栈）的差异与联系

*   **04 关（符号栈）**：目标数据位于函数栈帧内部。我们通过 `blank_state` 跳入函数中间，并手动模拟 `ebp` 和 `esp` 的设置，然后利用 `ebp` 的相对偏移 (`ebp - 0xc`, `ebp - 0x10`) 来定位局部变量，并使用 `state.memory.store` 或 `state.mem[...]` 写入符号值。这里的关键是**我们控制了栈的起始地址和布局**。
*   **05 关（符号静态内存）**：目标数据位于程序的 `.bss` 段（全局未初始化数据区）。这些全局变量的地址在编译时就已经固定（因为禁用了 PIE）。我们无需关心栈的布局，也无需模拟 `ebp` 或 `esp`。只需找到全局变量的**绝对地址**，然后直接使用 `state.memory.store` 或 `state.mem[...]` 将符号值写入该绝对地址。这里的关键是**目标地址是固定的全局地址**。
*   **共同点**：两关都通过 `blank_state` 跳过 `scanf` 的默认处理，并直接向内存中注入符号数据。都使用了 `state.memory.store` 或 `state.mem[...]` 这种强大的内存操作功能。

## C 代码分析

为了高效地使用 angr，我们首先需要理解目标程序的行为。以下是 `05_angr_symbolic_memory` 的 C 代码核心逻辑分析：

1.  **全局变量 `user_input`**：
    ```c
    char user_input[32+1]; // 32 bytes for input, 1 for null terminator
    ```
    这是一个 33 字节的全局字符数组，用于存储用户输入。它位于 `.bss` 段。

2.  **输入方式 `scanf`**：
    ```c
    scanf("%8s %8s %8s %8s", user_input, &user_input[8], &user_input[16], &user_input[24]);
    ```
    程序通过 `scanf` 读取 4 个 8 字节的字符串，分别写入 `user_input` 数组的 `0`、`8`、`16`、`24` 偏移处。这意味着用户需要输入 4 个由空格分隔的 8 字符字符串，总共 32 个有效字符。

3.  **复杂变换 `complex_function`**：
    ```c
    int complex_function(int value, int i) {
    #define LAMBDA 9
      if (!('A' <= value && value <= 'Z')) {
        printf("Try again.\n");
        exit(1);
      }
      return ((value - 'A' + (LAMBDA * i)) % ('Z' - 'A' + 1)) + 'A';
    }

    for (int i=0; i<32; ++i) {
      user_input[i] = (char) complex_function(user_input[i], i);
    }
    ```
    程序对 `user_input` 数组中的每个字符进行循环处理。`complex_function` 接收一个字符 `value` 和其索引 `i`。它执行一个基于 `LAMBDA` (固定为 9) 和索引 `i` 的 Caesar 密码变种变换。输入字符必须是大写字母 'A'-'Z'，否则程序会退出。

4.  **成功条件**：
    ```c
    if (strncmp(user_input, USERDEF, 32)) {
      printf("Try again.\n");
    } else {
      printf("Good Job.\n");
    }
    ```
    经过 `complex_function` 变换后的 `user_input` 数组，会与一个编译时随机生成的 32 字节字符串 `USERDEF` 进行比较。只有当两者完全匹配时，程序才会打印 "Good Job."。

## 生成脚本 (`generate.py`) 解析

`generate.py` 脚本负责生成 CTF 挑战的二进制文件。它使用 `jinja2` 模板引擎来填充 C 源代码中的占位符：

*   `USERDEF`：一个 32 字节的随机大写字母字符串，作为目标密码。
*   `padding0`, `padding1`：随机大小的填充数组，用于混淆 `user_input` 在内存中的相对位置，但由于禁用了 PIE，其绝对地址仍是固定的。

编译命令：
```bash
gcc -fno-pie -no-pie -m32 -o <output_file> <temp_c_file>
```
*   `-fno-pie -no-pie`：禁用位置无关可执行文件（PIE）和位置无关代码（PIC）。这使得程序加载到内存中的地址是固定的，特别是全局变量的地址将是绝对的、可预测的，这对于我们直接定位 `user_input` 的地址至关重要。
*   `-m32`：编译为 32 位程序。

## 原理如何导向解决方案

本节将详细解释为什么我们选择特定的 angr 方法来解决这个挑战，以及这些原理如何具体地指导我们的解决方案。

1.  **为什么要跳过 `scanf`？**
    *   **原理**：angr 内置的 `scanf` 模拟程序（SimProcedure）对于复杂格式字符串（如 `%8s %8s %8s %8s`）的处理能力有限。它难以自动生成符合这种多段、带空格格式的符号输入，并将其正确解析到多个目标内存区域。
    *   **解决方案**：我们选择完全跳过 `scanf` 的执行。这意味着我们需要找到 `scanf` 调用**之后**的指令地址作为符号执行的起点。

2.  **为什么要用 `blank_state`？**
    *   **原理**：`blank_state` 允许我们从程序的任意地址开始符号执行，并完全控制初始状态（包括寄存器和内存）。这与 `entry_state`（从程序入口点开始）不同。
    *   **解决方案**：通过 `project.factory.blank_state(addr=start_address, ...)`，我们能够精确地将符号执行的起点设置在 `scanf` 调用之后，从而避免了 `scanf` 的复杂性。

3.  **为什么能直接写 `.bss` 段的全局变量？**
    *   **原理**：由于编译时使用了 `-fno-pie -no-pie` 选项，生成的二进制文件是**非位置无关**的。这意味着程序加载到内存中的基地址是固定的，因此全局变量（如 `user_input` 数组，位于 `.bss` 段）的绝对内存地址在每次运行时都是相同的，并且可以在编译后通过静态分析工具（如 Rizin）确定。
    *   **解决方案**：我们不需要像上一关那样模拟栈帧或计算相对偏移。我们只需通过 Rizin 找到 `user_input` 数组的**绝对地址**，然后直接使用 `state.memory.store` 或 `state.mem[...]` 将符号值写入这个固定地址。

4.  **为什么用 32×8-bit BVS 分四块？**
    *   **原理**：C 代码中的 `scanf("%8s %8s %8s %8s", ...)` 明确指示了输入将被解析为 4 个独立的、每个最大长度为 8 个字符的字符串。虽然它们最终都写入 `user_input` 数组，但这种分段读取的语义在符号化时需要体现。
    *   **解决方案**：我们创建 4 个独立的 `claripy.BVS` 变量，每个代表 8 个字符（即 8 * 8 = 64 位）。例如：
        ```python
        password0 = claripy.BVS('password0', 8 * 8) # 8 characters * 8 bits/char
        password1 = claripy.BVS('password1', 8 * 8)
        password2 = claripy.BVS('password2', 8 * 8)
        password3 = claripy.BVS('password3', 8 * 8)
        ```
        然后，我们将这些符号变量分别存储到 `user_input` 数组的正确偏移地址：`user_input`、`user_input + 8`、`user_input + 16`、`user_input + 24`。

5.  **为什么用 stdout “Good Job.”/“Try again.” 判断 `find/avoid`？**
    *   **原理**：程序通过打印 "Good Job." 或 "Try again." 来指示执行结果。直接检查标准输出比尝试定位特定的成功/失败代码地址更稳定、更通用，尤其是在程序逻辑复杂或地址可能变化的情况下。
    *   **解决方案**：在 `is_successful` 和 `should_abort` 函数中，我们使用 `state.posix.dumps(sys.stdout.fileno())` 来获取当前状态的标准输出内容，然后检查其中是否包含 "Good Job.".encode() 或 "Try again.".encode()。

## 破解思路概览

1.  **静态分析**：
    *   使用 Rizin 等工具分析生成的二进制文件。
    *   确定 `scanf` 调用后的下一条关键指令的地址，这将是 angr 符号执行的 `start_address`。
    *   查找全局变量 `user_input` 在 `.bss` 段中的绝对内存地址。

2.  **angr 脚本构造**：
    *   初始化 `angr.Project`。
    *   使用 `project.factory.blank_state` 创建初始状态，指定 `start_address` 和 `angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY` 选项。
    *   创建四个 8 字节（64 位）的 `claripy.BVS` 符号变量，分别对应 `scanf` 的四段输入。
    *   使用 `initial_state.memory.store()` 或 `initial_state.mem[...]` 将这四个符号变量分别写入 `user_input` 数组的起始地址及其 `+8`、`+16`、`+24` 偏移处。
    *   创建 `angr.SimulationManager`。
    *   定义 `is_successful` 和 `should_abort` 函数，通过检查 `state.posix.dumps(sys.stdout.fileno())` 来判断路径是否成功或失败。
    *   调用 `simulation.explore(find=is_successful, avoid=should_abort)` 进行符号执行。
    *   如果找到成功路径，从 `solution_state` 中使用 `solution_state.solver.eval(symbolic_variable, cast_to=bytes).decode()` 解出每个符号变量的具体值。
    *   将解出的四个 8 字符字符串拼接起来，中间用空格分隔，形成最终的 32 字符密码。

## 实战步骤 / Rizin 指令示例

1.  **生成 `05_angr_symbolic_memory` 可执行文件**：
    ```bash
    python generate.py 1337 05_angr_symbolic_memory
    ```
    （您可以使用任何种子，例如 `1337`）

2.  **获取 `start_address`**：
    *   使用 Rizin 分析 `main` 函数，找到 `scanf` 调用后的下一条指令地址。
    ```bash
    rizin -q -c 'aaa; pdf @ main' 05_angr_symbolic_memory
    ```
    查找类似 `call sym.imp.__isoc99_scanf` 的指令，并记录其后的指令地址。例如，如果 `scanf` 在 `0x08048613`，其后可能是 `0x08048618`。

3.  **获取 `user_input` 的绝对地址**：
    *   使用 Rizin 查找 `user_input` 符号的地址。
    ```bash
    rizin -q -c 'is~user_input' 05_angr_symbolic_memory
    ```
    输出中会显示 `user_input` 的地址，例如 `vaddr=0x0804a040`。

4.  **修改 `scaffold05.py`**：
    *   将 `path_to_binary` 设置为 `argv[1]`。
    *   填入正确的 `start_address`。
    *   创建四个 `claripy.BVS` 变量，每个 64 位（8 字节）。
    *   填入 `user_input` 的绝对地址，并使用 `initial_state.memory.store()` 或 `initial_state.mem[...]` 将符号变量写入。
    *   实现 `is_successful` 和 `should_abort` 函数，检查标准输出。
    *   在找到 `solution_state` 后，使用 `solver.eval()` 分别解析出四个符号变量的值，并拼接成最终密码。

    ```python
    import angr
    import claripy
    import sys

    def main(argv):
      path_to_binary = argv[1]
      project = angr.Project(path_to_binary)

      # 替换为实际的 start_address
      start_address = 0x8048618 # Example: Address after scanf call

      initial_state = project.factory.blank_state(
        addr=start_address,
        add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                        angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
      )

      # The binary is calling scanf("%8s %8s %8s %8s").
      # Create 4 symbolic bitvectors, each representing 8 characters (8 bytes * 8 bits/byte = 64 bits)
      password0 = claripy.BVS('password0', 8*8)
      password1 = claripy.BVS('password1', 8*8)
      password2 = claripy.BVS('password2', 8*8)
      password3 = claripy.BVS('password3', 8*8)

      # Determine the absolute address of the global variable 'user_input'
      # Replace with the actual address found via Rizin (e.g., 0x0804a040)
      user_input_base_address = 0x0804a040 # Example: Base address of user_input array

      # Store the symbolic values into the global memory locations
      # Option 1: Using state.memory.store
      initial_state.memory.store(user_input_base_address, password0)
      initial_state.memory.store(user_input_base_address + 8, password1)
      initial_state.memory.store(user_input_base_address + 16, password2)
      initial_state.memory.store(user_input_base_address + 24, password3)

      # Option 2: Using the more Pythonic state.mem[...] interface (equivalent to Option 1)
      # initial_state.mem[user_input_base_address].string = password0
      # initial_state.mem[user_input_base_address + 8].string = password1
      # initial_state.mem[user_input_base_address + 16].string = password2
      # initial_state.mem[user_input_base_address + 24].string = password3


      simulation = project.factory.simgr(initial_state)

      def is_successful(state):
        stdout_output = state.posix.dumps(sys.stdout.fileno())
        return b'Good Job.' in stdout_output

      def should_abort(state):
        stdout_output = state.posix.dumps(sys.stdout.fileno())
        return b'Try again.' in stdout_output

      simulation.explore(find=is_successful, avoid=should_abort)

      if simulation.found:
        solution_state = simulation.found[0]

        # Solve for the symbolic values. We are trying to solve for a string.
        # Therefore, we will use eval, with named parameter cast_to=bytes
        # which returns bytes that can be decoded to a string instead of an integer.
        solution0 = solution_state.solver.eval(password0, cast_to=bytes).decode().rstrip('\x00')
        solution1 = solution_state.solver.eval(password1, cast_to=bytes).decode().rstrip('\x00')
        solution2 = solution_state.solver.eval(password2, cast_to=bytes).decode().rstrip('\x00')
        solution3 = solution_state.solver.eval(password3, cast_to=bytes).decode().rstrip('\x00')

        # Concatenate the solutions with spaces as per scanf format
        solution = ' '.join([solution0, solution1, solution2, solution3])

        print(solution)
      else:
        raise Exception('Could not find the solution')

    if __name__ == '__main__':
      main(sys.argv)
    ```

5.  **运行解决方案**：
    ```bash
    python scaffold05.py 05_angr_symbolic_memory
    ```
    脚本将输出需要输入到程序的 32 字符密码（由 4 个 8 字符子串组成，以空格分隔）。

6.  **验证**：
    *   运行生成的二进制文件，并输入脚本给出的密码。
    ```bash
    ./05_angr_symbolic_memory
    Enter the password: <粘贴脚本输出的密码>
    ```
    如果一切正确，程序将打印 "Good Job."。

祝您在探索静态内存符号化的旅程中取得成功！
