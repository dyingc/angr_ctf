# 03_angr_symbolic_registers CTF 挑战：符号化寄存器

## 挑战概述

`03_angr_symbolic_registers` 是 angr CTF 系列中的一个关键挑战，它引入了一个核心概念：**直接对 CPU 寄存器进行符号化**。在之前的挑战中，我们的输入通常是通过标准输入（stdin）读取数据到 **内存缓冲区** 中。而在这个挑战中，程序将直接从用户处读取三个独立的十六进制值，并将它们分别加载到 `eax`、`ebx` 和 `edx` **寄存器** 中。

这个挑战将教会您如何脱离对内存缓冲区的依赖，直接控制和符号化寄存器的状态，这是解决更复杂二进制问题的基础技能。例如：

*   **处理自定义调用约定**：在某些二进制程序中，函数参数可能不按照标准的调用约定（如System V AMD64 ABI）通过栈或通用寄存器传递，而是通过特定的寄存器或非常规的方式传递。通过符号化寄存器，angr 可以模拟这些非标准参数的传入，并对函数行为进行分析。
*   **分析无输入的代码逻辑**：有时，您可能需要分析一段不接受任何外部输入的代码，但其行为依赖于某些预先存在于寄存器中的值（例如，从其他函数或硬件读取的值）。在这种情况下，将这些寄存器符号化，可以帮助 angr 探索所有可能的执行路径并发现潜在的漏洞或行为。

您可以通过[这里](https://www.tjc.im/reverse_engineering/angr_ctf/03_angr_symbolic_registers/)查看一篇别人写的笔记。

## C 代码分析

为了有效地使用 angr，我们首先需要理解目标程序的行为。以下是 `03_angr_symbolic_registers` 的 C 代码核心逻辑分析：

1.  **输入**：程序通过 `get_user_input` 函数中的 `scanf("%x %x %x", &first, &second, &third);` 从用户处获取三个以空格分隔的十六进制整数。
2.  **寄存器赋值**：这三个整数被直接赋值给 `eax`、`ebx` 和 `edx` 寄存器。
    ```c
    register int eax asm("eax");
    register int ebx asm("ebx");
    register int edx asm("edx");
    // ...
    eax = first;
    ebx = second;
    edx = third;
    ```
3.  **复杂转换**：
    *   程序将这三个寄存器的值分别传递给三个独立的、由 `generate.py` 脚本随机生成的复杂函数：`complex_function_1`、`complex_function_2` 和 `complex_function_3`。
    *   在 `03_angr_symbolic_registers.c.jinja` 中，这些函数被定义为：
        ```c
        int complex_function_1(int input) {
        {{ complex_function_1 }}
          return input;
        }

        int complex_function_2(int input) {
        {{ complex_function_2 }}
          return input;
        }

        int complex_function_3(int input) {
        {{ complex_function_3 }}
          return input;
        }
        ```
    *   `generate.py` 的 `randomly_modify` 函数负责生成这些 `complex_function` 的内容。它会随机选择 `+=` 或 `^=` 操作符，并生成一个随机的 32 位整数作为操作数。例如：
        ```python
        # generate.py 中的 randomly_modify 函数示例
        def randomly_modify(var):
          operator = random.choice(['+=', '^='])
          random_int = random.randint(0, 0xFFFFFFFF)
          return var + operator + str(random_int) + ';'

        # 实际生成的 C 代码片段可能看起来像这样：
        # input += 12345678;
        # input ^= 0xABCDEF01;
        # input += 98765432;
        # ...
        ```
    *   每个 `complex_function` 内部都包含 16 到 48 个随机的 `+=` (加法) 和 `^=` (异或) 操作。这些操作的序列和操作数都是随机生成的。
    *   **为什么手动逆向几乎不可能？**
        *   **随机性与复杂性**：由于每个 `complex_function` 都包含几十个随机生成的加法和异或操作，这些操作会相互影响，使得最终的输出与初始输入之间形成极其复杂的非线性关系。
        *   **缺乏模式**：每次生成二进制文件时，这些函数的具体逻辑都会根据随机种子而变化，这意味着无法通过观察或经验来推断其行为模式。
        *   **计算量巨大**：即使对于一个单一的 `complex_function`，手动计算其逆运算以找到使结果为零的输入也是极其繁琐且容易出错的。更何况这里有三个独立的、相互影响的函数需要同时满足条件。
    *   **angr 如何介入？**
        *   **符号化**：angr 通过将输入的寄存器（`eax`, `ebx`, `edx`）处理为**符号变量**，避免了对具体数值的依赖。
        *   **约束传播**：当程序执行这些 `complex_function` 时，angr 会自动跟踪这些符号变量的每次操作，并将这些操作转化为一系列数学**约束**。
        *   **SMT 求解**：最终，angr 将“三个函数的返回值必须全部为 0”这一成功条件也转化为约束，并利用强大的 SMT (Satisfiability Modulo Theories) 求解器（如 Z3）来寻找一组满足所有这些约束的符号变量的具体值。
        *   **强大之处**：这意味着 angr 无需理解 `complex_function` 的具体算法细节，也无需人工逆向。它只需要执行程序并收集约束，然后让求解器自动找到满足条件的输入。这正是符号执行在处理复杂、未知或混淆代码时的强大体现。

4.  **成功条件**：
    *   程序检查三个复杂函数转换后的结果。
    *   只有当三个函数的返回值**全部为 0** 时，程序才会打印 "Good Job."。
    ```c
    if (non_eax || non_ebx || non_edx) {
      printf("Try again.\n");
    } else {
      printf("Good Job.\n");
    }
    ```

**这对我们意味着什么？**
我们不能再像以前一样提供一个符号化的字符串。相反，我们需要创建三个独立的符号变量，将它们分别注入到 `eax`、`ebx` 和 `edx` 寄存器中，然后让 `angr` 的符号执行引擎找到能使三个复杂计算的结果同时为零的三个具体数值。

## 核心学习重点

为了成功解决 `03_angr_symbolic_registers` 挑战，请重点学习以下概念和 angr 官方文档：

1.  **状态与寄存器交互 (`state.regs`)**
    *   **学习目标**：理解 `SimState` 对象不仅包含内存信息，还包含了完整的 CPU 状态。学习如何通过 `state.regs` 属性来读取和写入寄存器的值，例如 `state.regs.eax`、`state.regs.rip` 等。
    *   **关于 angr 中的“寄存器”**：在 angr 中，`state.regs` 提供的寄存器并非真实的物理 CPU 寄存器，而是 `SimState` 对象中对程序执行状态的一种抽象模型。它们通常以位向量（BitVector）的形式存储在内存中，可以包含具体值（BVV），也可以是符号值（BVS）。这种抽象使得 angr 能够灵活地在模拟环境中进行符号执行、跟踪数据流和管理程序状态，而无需与底层硬件直接交互。
    *   **推荐阅读**：[Review: Reading and writing memory and registers](https://docs.angr.io/en/latest/core-concepts/states.html#review-reading-and-writing-memory-and-registers) - 这篇文档详细介绍了如何与程序状态（包括寄存器和内存）进行交互。

2.  **Claripy 与符号位向量 (`claripy.BVS`)**
    *   **学习目标**：学习使用 `claripy`，即 angr 的解算器抽象层。掌握如何创建符号变量，特别是 `claripy.BVS('variable_name', bit_length)`，它用于创建一个指定位宽的“位向量符号”（Bit-Vector Symbol），代表一个未知的数值。
    *   **推荐阅读**：
        *   [Symbolic Expressions and Constraint Solving with angr](https://docs.angr.io/en/latest/core-concepts/solver.html) - 解释了如何创建和使用符号变量及约束，是本挑战的核心技术。
        *   [Claripy: The Solver Engine](https://docs.angr.io/en/latest/advanced-topics/claripy.html) - 为希望深入了解解算器后端的学习者提供更详细的背景信息。

3.  **约束求解 (`solver.eval`)**
    *   **学习目标**：理解当 `angr` 找到一个满足条件的路径（成功状态）后，其内部的解算器（solver）已经为所有符号变量找到了一组可行的具体值。学习如何使用 `found_state.solver.eval(symbolic_variable)` 来提取这些具体值。
    *   **推荐阅读**：[Symbolic Expressions and Constraint Solving with angr](https://docs.angr.io/en/latest/core-concepts/solver.html) - 该文档同样清晰地演示了如何求解和评估符号变量。

## 技术要点详解

*   **`eax_symbol = claripy.BVS('eax_val', 32)`**：
    *   这行代码创建了一个名为 `eax_val` 的 32 位符号变量。这个变量是“自由”的，它可以代表任何 32 位的值。我们需要为 `eax`、`ebx` 和 `edx` 分别创建这样的变量。
*   **`initial_state.regs.eax = eax_symbol`**：
    *   这是本挑战最关键的一步。我们将刚刚创建的符号变量 `eax_symbol` 赋值给初始状态的 `eax` 寄存器。angr 在后续的符号执行中，会跟踪这个符号变量如何被程序操作。
*   **寻找 `find` 和 `avoid` 地址**：
    *   与之前的挑战类似，您需要使用反汇编工具（如 `objdump -d`）来找到打印 "Good Job." 和 "Try again." 的代码地址，并将它们分别用作 `explore()` 方法的 `find` 和 `avoid` 参数。
*   **`simulation.explore(find=find_address, avoid=avoid_address)`**：
    *   启动符号执行，angr 会探索所有可能的路径，直到找到一个状态其 `rip` (指令指针) 等于 `find_address`。
*   **`solution_state = simulation.found[0]`**：
    *   当探索成功后，满足条件的 `SimState` 会被存储在 `simulation.found` 列表中。我们取第一个即可。
*   **`found_eax = solution_state.solver.eval(eax_symbol)`**：
    *   在 `solution_state` 中，解算器已经拥有了一组能使其到达成功地址的解。我们使用 `solver.eval()` 并传入我们之前创建的符号变量 `eax_symbol`，来查询 `eax` 在这种解下的具体数值。

## 实践步骤

1.  **生成 `03_angr_symbolic_registers` 可执行文件**：
    *   `python generate.py 1234 03_angr_symbolic_registers` (您可以使用任何种子)。
2.  **获取 Find/Avoid 地址**：
    *   运行 `objdump -d -M intel 03_angr_symbolic_registers/03_angr_symbolic_registers`。
    *   找到打印 "Good Job." 之前 `call` 指令的地址作为 `find_address`。
    *   找到打印 "Try again." 之前 `call` 指令的地址作为 `avoid_address`。
3.  **修改 `scaffold03.py`**：
    *   将 `path_to_binary` 设置为正确的二进制文件路径。
    *   创建三个 32 位的 `claripy.BVS` 符号变量，分别用于 `eax`、`ebx` 和 `edx`。
    *   在 `initial_state` 中，将这三个符号变量分别赋值给 `initial_state.regs.eax`、`initial_state.regs.ebx` 和 `initial_state.regs.edx`。
    *   设置正确的 `find_address` 和 `avoid_address`。
    *   在找到 `solution_state` 后，使用 `solver.eval()` 分别解析出三个符号变量的具体值。
4.  **运行解决方案**：
    *   执行您的 Python 脚本：`python scaffold03.py`
    *   脚本将输出需要输入到程序的三个十六进制密码。

祝您在符号化寄存器的探索中学习愉快！
