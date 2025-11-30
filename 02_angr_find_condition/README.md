# 02_angr_find_condition CTF 挑战：自定义探索条件

## 挑战概述

`02_angr_find_condition` 是 angr CTF 系列的第三个挑战，它将 `simgr.explore()` 方法的灵活性提升到了新的水平。与前两个挑战不同，您不再需要精确地知道成功或失败的地址。相反，您将学习如何通过**自定义 Python 函数**来定义探索的成功和规避条件。

这个挑战将帮助您掌握如何编写谓词（predicate）函数，这些函数能够检查 `SimState` 的当前状态（特别是程序的标准输出），并据此指导 angr 的符号执行引擎。

您可以通过[这里](https://www.tjc.im/reverse_engineering/angr_ctf/02_angr_find_condition/)查看一篇别人写的笔记。

## 学习前置知识

在解决此挑战之前，请确保您已理解并掌握 `00_angr_find` 和 `01_angr_avoid` 挑战中的所有概念和技术。特别是：

*   angr 项目的创建和加载。
*   `SimState` 的基本操作。
*   `SimulationManager` 的基本使用和 `explore()` 方法的 `find` 和 `avoid` 参数。
*   如何使用反汇编工具查找目标地址。

## C 代码分析

为了有效地使用 angr，首先需要理解目标程序的行为。以下是 `02_angr_find_condition` 的 C 代码核心逻辑分析：

1.  **输入**：程序通过 `scanf("%8s", buffer);` 从用户处获取一个最多 8 个字符的输入。
2.  **密码转换**：
    *   程序内部有一个硬编码的密码字符串 `USERDEF`。用户输入的密码字符串，在经过一系列复杂转换后，会与这个硬编码的 `USERDEF` 进行比较，以此判定用户输入的密码是否正确。
    *   `for` 循环遍历用户输入的每个字符，并将其传递给 `complex_function` 进行转换：
        ```c
        for (int i=0; i<LEN_USERDEF; ++i) {
          buffer[i] = complex_function(buffer[i], i+8);
        }
        ```
    *   `complex_function` 是一个关键函数，它对每个字符进行基于其位置的数学转换。这意味着，即使您知道那个硬编码的 `USERDEF`，也无法直接输入它来通过检查。
        ```c
        int complex_function(int value, int i) {
          #define LAMBDA 31
          if (!('A' <= value && value <= 'Z')) {
            printf("Try again.\n");
            exit(1);
          }
          return ((value - 'A' + (LAMBDA * i)) % ('Z' - 'A' + 1)) + 'A';
        }
        ```
        *   **输入验证**：该函数首先检查输入字符 `value` 是否为大写字母。如果不是，程序将打印 "Try again." 并退出。
        *   **核心转换逻辑**：`((value - 'A' + (LAMBDA * i)) % ('Z' - 'A' + 1)) + 'A'` 是一个经典的凯撒密码变体。它将字符转换为 0-25 之间的数字，加上一个基于其位置 `i` 和常量 `LAMBDA` 的偏移量，然后通过取模运算确保结果仍在 0-25 的范围内，最后再转换回 'A'-'Z' 的字符。
3.  **比较**：
    *   程序通过 `strcmp(buffer, password)` 比较转换后的 `buffer` 和硬编码的 `password`。
    *   如果两者相同，程序将打印 "Good Job."。
    *   如果不同，程序将打印 "Try again."。

**这对我们意味着什么？**
我们无法通过简单的逆向工程来找到正确的输入。我们需要 `angr` 来符号化执行程序，并找到一个输入，使得经过 `complex_function` 转换后，它与内部密码匹配。

## 核心学习重点

为了成功解决 `02_angr_find_condition` 挑战并深入理解 angr，请重点学习以下概念和 angr 文档章节：

1.  **自定义探索条件**
    *   **学习目标**：理解 `angr.SimulationManager` 的 `explore()` 方法不仅可以接受地址作为 `find` 和 `avoid` 参数，还可以接受**自定义的 Python 函数**。这些函数接收一个 `SimState` 对象作为参数，并返回 `True` 或 `False` 来指示是否满足条件。
    *   **推荐阅读**：[Simulation Managers](https://docs.angr.io/en/latest/core-concepts/pathgroups.html#simple-exploration) (特别是关于 `explore()` 方法中 `find` 和 `avoid` 参数接受函数的部分)

2.  **标准输出的符号化与检查**
    *   **学习目标**：理解 angr 如何在符号执行过程中捕获程序的标准输出（stdout）。学习如何使用 `state.posix.dumps(sys.stdout.fileno())` 来获取当前状态下程序已经打印到标准输出的内容，并据此进行条件判断。
    *   **推荐阅读**：[`dumps` API](https://docs.angr.io/en/latest/api.html#angr.state_plugins.SimSystemPosix.dumps)

## 技术要点详解

*   **`is_successful(state)` 函数**：
    *   这个函数将作为 `explore()` 方法的 `find` 参数，接收一个 SimState 对象作为参数，并返回 True 或 False 来指示是否满足条件。
    *   它需要检查 `state.posix.dumps(sys.stdout.fileno())` 返回的字符串是否包含 "Good Job."。
    *   示例：`return b"Good Job." in stdout_output`
*   **`should_abort(state)` 函数**：
    *   这个函数将作为 `explore()` 方法的 `avoid` 参数。和 `is_successful` 类似，它也是接收一个 SimState 对象作为参数，并返回 True 或 False 来指示是否满足条件。
    *   它需要检查 `state.posix.dumps(sys.stdout.fileno())` 返回的字符串是否包含 "Try again."。
    *   示例：`return b"Try again." in stdout_output`
*   **`state.posix.dumps(sys.stdout.fileno())`**：
    *   这个方法用于从当前 `SimState` 中提取程序到目前为止的所有标准输出内容。返回的是字节串（`bytes`），因此在比较时需要注意编码。
*   **`simulation.explore(find=is_successful, avoid=should_abort)`**：
    *   这一行代码是 `scaffold02.py` 的核心。它告诉 `angr` 开始探索，直到 `is_successful` 函数返回 `True`，或者在 `should_abort` 函数返回 `True` 时放弃某条路径。
*   **`simulation.found`**：
    *   当 `explore()` 找到一个或多个满足 `find` 条件的状态时，它会将这些状态存储在 `simulation.found` 列表中。您可以通过 `simulation.found[0]` 来访问第一个找到的成功状态。
*   **`angr.options`**：
    *   在 `scaffold02.py` 中，我们使用了 `angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY` 和 `angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS`。这些选项告诉 `angr`，当遇到未初始化的内存或寄存器时，用符号值填充它们，而不是具体的默认值。这对于探索所有可能的路径至关重要。

## 实践步骤

1.  **阅读 C 代码分析**：
    *   在开始编写 Python 代码之前，请确保您已理解 C 代码的逻辑（本系列 CTF 使用 `*.c.jinja` 作为模版，用 `generate.py` 生成真正的 C 代码）。
2.  **生成 `02_angr_find_condition` 可执行文件**：
    *   `python generate.py 1234 02_angr_find_condition`
3.  **修改 `scaffold02.py`**：
    *   将 `path_to_binary` 设置为正确的二进制文件路径（例如 `'02_angr_find_condition/02_angr_find_condition'`）。
    *   实现 `is_successful(state)` 函数，使其在 `stdout_output` 包含 `b"Good Job."` 时返回 `True`。
    *   实现 `should_abort(state)` 函数，使其在 `stdout_output` 包含 `b"Try again."` 时返回 `True`。
4.  **运行解决方案**：
    *   执行您的 Python 脚本：`python scaffold02.py`
    *   脚本将输出找到的密码。

## 扩展学习

*   **angr 官方文档**：[angr Documentation](https://docs.angr.io/en/latest.md) - 完整的 angr 文档，包含所有模块和 API 细节。
*   **angr CTF 仓库**：[angr_ctf](https://github.com/jakespringer/angr_ctf) - 更多 angr CTF 挑战，可以帮助您进一步提升技能。
*   **angr Cheatsheet**：[Angr Cheatsheet](https://docs.angr.io/en/latest/appendix/cheatsheet.html) - 快速参考 angr 的常用功能和代码片段。

## 常见问题

*   **`stdout_output` 为空**：确保程序确实有输出，并且 `angr` 能够捕获到。有时，输出可能在程序执行的后期才出现。
*   **条件判断不准确**：仔细检查 `is_successful` 和 `should_abort` 函数中的字符串比较，确保大小写和完整性匹配。
*   **找不到解决方案**：
    *   检查 `path_to_binary` 是否正确。
    *   确保您的 `is_successful` 和 `should_abort` 逻辑正确无误。
    *   对于更复杂的挑战，可能需要更深入地分析程序逻辑。

祝您学习愉快，并在 angr 的世界中取得成功！
