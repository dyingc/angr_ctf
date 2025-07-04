# 02_angr_find_condition CTF 挑战：自定义探索条件

## 挑战概述

`02_angr_find_condition` 是 angr CTF 系列的第三个挑战，它将 `simgr.explore()` 方法的灵活性提升到了新的水平。与前两个挑战不同，您不再需要精确地知道成功或失败的地址。相反，您将学习如何通过**自定义 Python 函数**来定义探索的成功和规避条件。

这个挑战将帮助您掌握如何编写谓词（predicate）函数，这些函数能够检查 `SimState` 的当前状态（特别是程序的标准输出），并据此指导 angr 的符号执行引擎。

## 学习前置知识

在解决此挑战之前，请确保您已理解并掌握 `00_angr_find` 和 `01_angr_avoid` 挑战中的所有概念和技术。特别是：

*   angr 项目的创建和加载。
*   `SimState` 的基本操作。
*   `SimulationManager` 的基本使用和 `explore()` 方法的 `find` 和 `avoid` 参数。
*   如何使用反汇编工具查找目标地址。

## 核心学习重点

为了成功解决 `02_angr_find_condition` 挑战并深入理解 angr，请重点学习以下概念和 angr 文档章节：

1.  **自定义探索条件**
    *   **学习目标**：理解 `angr.SimulationManager` 的 `explore()` 方法不仅可以接受地址作为 `find` 和 `avoid` 参数，还可以接受**自定义的 Python 函数**。这些函数接收一个 `SimState` 对象作为参数，并返回 `True` 或 `False` 来指示是否满足条件。
    *   **推荐阅读**：[Simulation Managers](https://docs.angr.io/en/latest/core-concepts/pathgroups.html) (特别是关于 `explore()` 方法中 `find` 和 `avoid` 参数接受函数的部分)

2.  **标准输出的符号化与检查**
    *   **学习目标**：理解 angr 如何在符号执行过程中捕获程序的标准输出（stdout）。学习如何使用 `state.posix.dumps(sys.stdout.fileno())` 来获取当前状态下程序已经打印到标准输出的内容，并据此进行条件判断。
    *   **推荐阅读**：[Machine State in angr](https://docs.angr.io/en/latest/core-concepts/states.html) (特别是关于 `state.posix.dumps` 的部分)

## 技术要点详解

*   **`is_successful(state)` 函数**：
    *   这个函数将作为 `explore()` 方法的 `find` 参数。
    *   它需要检查 `state.posix.dumps(sys.stdout.fileno())` 返回的字符串是否包含 "Good Job."。
    *   示例：`return b"Good Job." in stdout_output`
*   **`should_abort(state)` 函数**：
    *   这个函数将作为 `explore()` 方法的 `avoid` 参数。
    *   它需要检查 `state.posix.dumps(sys.stdout.fileno())` 返回的字符串是否包含 "Try again."。
    *   示例：`return b"Try again." in stdout_output`
*   **`state.posix.dumps(sys.stdout.fileno())`**：
    *   这个方法用于从当前 `SimState` 中提取程序到目前为止的所有标准输出内容。返回的是字节串（`bytes`），因此在比较时需要注意编码。

## 实践步骤

1.  **分析二进制文件**：
    *   虽然不再需要精确的地址，但理解程序的输入输出逻辑仍然重要。
    *   了解程序何时打印 "Good Job." 和 "Try again."。
2.  **修改 `scaffold02.py`**：
    *   将 `path_to_binary` 设置为正确的二进制文件路径（例如 `'./02_angr_find_condition'`）。
    *   实现 `is_successful(state)` 函数，使其在 `stdout_output` 包含 "Good Job." 时返回 `True`。
    *   实现 `should_abort(state)` 函数，使其在 `stdout_output` 包含 "Try again." 时返回 `True`。
3.  **运行解决方案**：
    *   执行您的 Python 脚本：`python scaffold02.py`
    *   脚本将输出找到的密码。

## 扩展学习

*   **angr 官方文档**：[angr Documentation](https://docs.angr.io/en/latest.md) - 完整的 angr 文档，包含所有模块和 API 细节。
*   **angr CTF 仓库**：[angr_ctf](https://github.com/jakespringer/angr_ctf) - 更多 angr CTF 挑战，可以帮助您进一步提升技能。
*   **angr Cheatsheet**：[Angr Cheatsheet](https://docs.angr.io/en/latest/appendix/cheatsheet.html) - 快速参考 angr 的常用功能和代码片段。

## 常见问题

*   **`stdout_output` 为空**：确保程序确实有输出，并且 angr 能够捕获到。有时，输出可能在程序执行的后期才出现。
*   **条件判断不准确**：仔细检查 `is_successful` 和 `should_abort` 函数中的字符串比较，确保大小写和完整性匹配。
*   **找不到解决方案**：
    *   检查 `path_to_binary` 是否正确。
    *   确保您的 `is_successful` 和 `should_abort` 逻辑正确无误。
    *   对于更复杂的挑战，可能需要更深入地分析程序逻辑。
*   **`angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY` 和 `SYMBOL_FILL_UNCONSTRAINED_REGISTERS`**：这些选项对于确保符号执行能够探索所有可能的路径至关重要。

祝您学习愉快，并在 angr 的世界中取得成功！
