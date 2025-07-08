# 04_angr_symbolic_stack CTF 挑战：符号化栈变量

## 挑战概述

`04_angr_symbolic_stack` 是 angr CTF 系列中一个重要的进阶挑战。在之前的挑战中，我们学会了如何符号化标准输入（stdin）和 CPU 寄存器。现在，我们将学习一项更底层、更强大的技术：**直接对栈上的局部变量进行符号化**。

在这个挑战中，程序会从用户处读取两个整数，并将它们存储在 `handle_user` 函数的**栈帧**中。我们的任务是绕过 `scanf`，直接在内存中创建符号变量，并将它们放置在栈上的正确位置，以模拟 `scanf` 的执行结果。

这个挑战将教会您如何：

*   **理解函数栈帧**：了解在函数调用期间，局部变量是如何在栈上分配和访问的。
*   **手动控制栈指针**：学习如何操纵 `ebp` (基址指针) 和 `esp` (栈指针) 来模拟函数序言（prologue）的行为。
*   **在任意内存地址写入符号值**：使用 `state.memory.store()` 这一核心功能，将符号变量精确地注入到栈上的特定位置。
*   **处理无栈保护的程序**：理解 `-fno-stack-protector` 编译选项的含义，以及它为什么是进行此类栈操作的前提。

掌握这些技能对于分析更复杂的二进制文件至关重要，特别是那些涉及复杂数据结构、自定义数据传递方式或存在栈溢出漏洞的程序。

## 背景知识回顾：函数栈帧 (Function Stack Frame)

要理解为什么这个挑战的解法是有效的，我们必须先回顾一下函数在底层是如何工作的。这其中最核心的概念就是**函数栈帧**。

### 什么是栈帧？

可以把栈帧想象成一个函数专属的、临时的“工作区”。当一个函数被调用时，它会在一个叫做“栈”的内存区域顶部为自己划分出一块空间。这个空间就是该函数的栈帧，它用来存储：

*   **局部变量**：在函数内部声明的变量。
*   **函数参数**：传递给该函数的参数（在32位程序中很常见）。
*   **返回地址**：函数执行完毕后应该返回到哪里。
*   **保存的寄存器**：尤其是调用者的 `ebp`（基址指针寄存器，标记调用者栈帧的起始位置），用于在函数返回时正确恢复调用者的栈帧，从而保持调用链的完整性，确保程序能够继续正常执行。

### 关键寄存器与函数序言

栈帧的管理依赖于两个关键的 CPU 寄存器：

### 关键寄存器与函数序言

栈帧的管理依赖于两个关键的CPU寄存器：

*   **`esp` (Stack Pointer)**：栈顶指针。在 x86 架构中，栈向低地址生长：`push` 时 `esp` 减小，`pop` 时 `esp` 增大。
*   **`ebp` (Base Pointer)**：基址指针。与 `esp` 不同，`ebp` 在函数执行期间通常保持不变，像一个“锚点”，为访问栈帧内的局部变量和参数提供稳定的参考。

为了建立这个“锚点”，几乎每个函数在执行之初都会运行一段被称为 **函数序言 (Function Prologue)** 的固定代码：

1.  `push ebp`：将调用者函数的 `ebp` 值压入栈中进行保存。
2.  `mov ebp, esp`：将当前的 `esp` 值赋给 `ebp`，确立当前函数新的栈帧基址。此时，`ebp` 指向保存调用者原始 `ebp`（**caller ebp**）的位置，为后续恢复调用者栈帧提供依据。
3.  `sub esp, N`：将 `esp` 向下移动 `N` 个字节，为所有局部变量“预留”出空间。

当函数结束时，会执行相应的 **函数结语 (Function Epilogue)**，通常包含以下固定步骤：

1.  `mov esp, ebp`：将当前栈帧基址 `ebp` 赋值给 `esp`，释放当前函数的栈帧空间。
2.  `pop ebp`：从栈中弹出调用者保存的 `ebp`，恢复调用者的栈帧。
3.  `ret`：根据栈中保存的返回地址跳转回调用点，继续执行调用者的代码。

### 与本挑战的联系

**这套机制正是本挑战的核心所在。** 我们的angr脚本选择从`handle_user`函数的**中间**开始执行，完全跳过了函数序言。因此，为了让后续的程序逻辑能正确执行，我们必须手动创建一个“以假乱真”的最小化栈环境。

以下是我们具体模拟了什么，又刻意忽略了什么：

*   **我们模拟了什么？**
    *   **`mov ebp, esp`**: 这是最关键的一步。我们通过 `initial_state.regs.ebp = initial_state.regs.esp` 完美地模拟了它，从而在模拟环境中建立了一个稳定的栈帧“锚点” (`ebp`)，后续所有基于 `ebp` 的内存访问才能成功。
    *   **变量的最终位置**: 我们通过 `state.memory.store(ebp - 0xc, ...)` 直接将符号值放置在它最终应该在的内存地址上。这一步直接模拟了`scanf`函数将用户输入写入局部变量地址的**最终结果**，从而巧妙地绕过了`sub esp, N`这一空间分配过程。

*   **我们忽略了什么，以及为什么？**
    *   **`push ebp`**: 我们不需要模拟它。这个操作的唯一目的是保存**调用者**（`main`函数）的`ebp`，以便函数能正确返回。但我们的目标是在当前函数内找到解，一旦找到成功路径，模拟就会终止，我们根本不关心程序能否正确返回。
    *   **函数结语 (`leave`, `ret`)**: 同理，我们也不需要关心函数结语。因为我们的模拟永远不会执行到函数末尾的返回部分，它在找到解时就提前结束了。

通过这种“精确打击”式的模拟，我们只构建了让目标代码段运行所必需的最小环境，极大地简化了分析过程。

## C 代码分析

为了高效地使用 angr，我们首先需要理解目标程序的行为。以下是 `04_angr_symbolic_stack` 的 C 代码核心逻辑分析：

1.  **输入**：程序在 `handle_user` 函数中通过 `scanf("%u %u", &user_int0, &user_int1);` 从用户处获取两个以空格分隔的无符号整数。这两个变量 `user_int0` 和 `user_int1` 是 `handle_user` 的**局部变量**，存储在函数栈帧上。

2.  **复杂转换**：
    *   输入的两个整数分别被传递给两个独立的、由 `generate.py` 随机生成的复杂函数：`complex_function0` 和 `complex_function1`。
    *   在 `04_angr_symbolic_stack.c.jinja` 中，这些函数被定义为对输入值执行 32 次随机的 `^=` (异或) 操作。
        ```c
        uint32_t complex_function0(uint32_t value) {
          // value ^= 0xABCDEF01;
          // value ^= 0x12345678;
          // ... (32 times)
          {{ complex_function0 }}
          return value;
        }
        ```
    *   **手动逆向的不可行性**：与之前的挑战类似，要手动逆向这两条包含 32 个随机异或操作的链条来找出正确的输入是极其困难的。每个函数的输出与输入之间都存在复杂的非线性关系。

3.  **成功条件**：
    *   程序将两个复杂函数转换后的结果，与另外两个在编译时随机生成的32位整数 `USERDEF0` 和 `USERDEF1` 进行比较。
    *   只有当 `complex_function0` 的返回值等于 `USERDEF0` **并且** `complex_function1` 的返回值等于 `USERDEF1` 时，程序才会打印 "Good Job."。
    ```c
    // The condition (a ^ b --> a XOR b) is equivalent to (a != b) for integers.
    if ((user_int0 ^ USERDEF0) || (user_int1 ^ USERDEF1)) {
      printf("Try again.\n");
    } else {
      printf("Good Job.\n");
    }
    ```

4.  **编译选项**：`generate.py` 使用 `gcc -fno-stack-protector` 进行编译。这个选项会禁用“栈金丝雀”（stack canaries）机制。栈金丝雀是一种在函数栈帧中插入随机值的安全技术，程序在函数返回前会检查该值是否被篡改，以检测并阻止栈缓冲区溢出攻击。禁用金丝雀后，栈上不会再有随机且不可预测的检查值，使得栈布局变得稳定可预测，因此我们能够准确定位和覆盖返回地址，这是本挑战能够进行的关键。

**这对我们意味着什么？**
这意味着我们不能再依赖 angr 对 `scanf` 的默认处理方式。其根本原因在于 **angr 内置的 `scanf` 模拟程序（SimProcedure）的一个已知局限性**：

*   对于 `scanf("%s", buffer)` 这样只读取**单个**值的简单格式，angr 通常能很好地处理。
*   但对于 `scanf("%u %u", &var1, &var2)` 这样需要从输入流中解析**多个**独立值的复杂格式，angr 的默认模拟程序就无能为力了。它不知道如何构造一个符号化的输入，来同时满足格式要求（如包含空格）并让解析出的两个部分成为独立的符号变量。

因此，我们必须另辟蹊径。我们需要完全接管程序的初始状态，跳过 `scanf` 调用，并手动在栈内存中创建两个符号变量，精确地放置在 `user_int0` 和 `user_int1` 应该在的位置。

值得注意的是，解决这个问题的另一种更高级的方法是为 `scanf` 编写一个自定义的 `SimProcedure`（一种用Python模拟函数行为的技术，将在后续挑战，CTF 10 SimProcedures，中学习）。然而，本挑战的核心教学目标，是掌握手动控制程序状态（尤其是栈）这一基本功。这是一种在很多复杂场景下都非常有用的底层分析技术，也是学习更高级技术的基础。

## 核心学习重点

为了成功解决 `04_angr_symbolic_stack` 挑战，请重点学习以下概念和 angr 官方文档：

1.  **创建空白状态 (`project.factory.blank_state`)**
    *   **学习目标**：理解 `blank_state` 的用途。与从程序入口点开始的 `entry_state` 不同，`blank_state` 允许我们创建一个“空白”的、可完全自定义的初始状态。我们可以指定执行的起始地址 (`addr`)，并配置寄存器和内存的初始值。这对于跳入函数中间执行至关重要。
    *   **推荐阅读**：[States](https://docs.angr.io/en/latest/core-concepts/states.html) - 了解不同类型的 `SimState` 以及如何创建它们。

2.  **手动管理栈指针 (`state.regs.ebp`, `state.regs.esp`)**
    *   **学习目标**：学习如何读取和写入栈指针寄存器。由于我们跳过了 `handle_user` 函数的序言（prologue），栈帧没有被建立。我们需要通过分析汇编代码，手动模拟栈帧的创建过程，通常包括将 `esp` 的值赋给 `ebp`，并为局部变量预留空间。
    *   **推荐阅读**：[Review: Reading and writing memory and registers](https://docs.angr.io/en/latest/core-concepts/states.html#review-reading-and-writing-memory-and-registers)

3.  **在内存中读写 (`state.memory.store`, `state.memory.load`)**
    *   **学习目标**：这是本挑战最核心的技能。学习如何使用 `state.memory.store(address, value, endness='Iend_LE')` 将一个符号变量（或具体值）写入到模拟内存的任意地址。同时，了解如何使用 `state.memory.load` 来读取值。
    *   **关键参数 `endness`**: 理解字节序（Endianness）的重要性。在 x86 架构中，数据以小端序（Little-Endian）存储，因此在写入多字节数据（如一个32位整数）时，必须指定 `endness='Iend_LE'` 以确保 angr 按正确的字节顺序存储它。
    *   **推荐阅读**：[Memory and Registers](https://docs.angr.io/en/latest/core-concepts/memory.html) - 这篇文档详细介绍了如何与 angr 的模拟内存进行交互。

4.  **通过标准输出检查状态 (`state.posix.dumps`)**
    *   **学习目标**：学习一种更灵活的、不依赖于特定代码地址的成功/失败判断方法。通过 `state.posix.dumps(sys.stdout.fileno())` 可以获取到该状态下模拟的标准输出内容。我们可以检查这个输出中是否包含 "Good Job." 或 "Try again." 字符串来引导符号执行的 `explore`。
    *   **推荐阅读**：[Interacting with the Environment](https://docs.angr.io/en/latest/core-concepts/environment.html)

## 技术要点详解

*   **选择正确的起始地址 (`start_address`)**:
    *   **目标**：我们的目标是跳过对 `scanf` 的调用。
    *   **汇编分析**:
        ```assembly
        ; Address of scanf call might vary
        0x0804921f      call    sym.imp.__isoc99_scanf
        0x08049224      add     esp, 0x10
        0x08049227      mov     eax, dword [ebp-0xc]  ; <-- OUR STARTING POINT
        ```
    *   `call` 指令会将返回地址压入栈中。`add esp, 0x10` 这条指令的作用是清理栈，它将栈指针 `esp` 增加 `0x10` (16) 字节，以移除之前为 `scanf` 压入的三个参数（格式字符串指针、`&user_int1`、`&user_int0`，在32位模式下总共12字节，对齐后为16字节）。
    *   由于我们不实际执行 `scanf`，我们也不需要执行这条清理指令。因此，最佳的起始地址是 `add esp, 0x10` **之后** 的那条指令。

*   **手动构建栈帧**:
    *   **分析 `handle_user` 的函数序言**:
        ```assembly
        ; handle_user function prologue
        0x080491f8      push    ebp
        0x080491f9      mov     ebp, esp
        0x080491fb      sub     esp, 0x18  ; Allocate 24 bytes for local variables
        ```
    *   **在 angr 中模拟**:
        1.  **设置 `ebp`**: 在我们的 `initial_state` 中，我们需要模拟 `mov ebp, esp`。一个简单的方法是让 `ebp` 和 `esp` 指向同一个高地址，因为栈向下增长。`initial_state.regs.ebp = initial_state.regs.esp`。
        2.  **分配空间**: 我们需要知道局部变量相对于 `ebp` 的位置。

*   **定位栈变量**:
    *   **分析 `scanf` 的参数压栈过程**:
        ```assembly
        ; Before calling scanf
        0x08049214      lea     eax, [ebp-0x10]  ; Load address of the second variable
        0x08049217      push    eax
        0x08049218      lea     eax, [ebp-0xc]   ; Load address of the first variable
        0x0804921b      push    eax
        0x0804921c      push    str.u_u          ; Push format string "%u %u"
        0x08049221      call    sym.imp.__isoc99_scanf
        ```
    *   从汇编代码中我们可以清晰地看到：
        *   第一个输入 (`user_int0`) 存储在 `[ebp-0xc]`。
        *   第二个输入 (`user_int1`) 存储在 `[ebp-0x10]`。

*   **将符号变量写入栈**:
    *   **创建符号变量**:
        ```python
        password0 = claripy.BVS('password0', 32)
        password1 = claripy.BVS('password1', 32)
        ```
    *   **计算地址并写入**:
        ```python
        # In the initial_state, ebp is set.
        addr_password0 = initial_state.regs.ebp - 0xc
        addr_password1 = initial_state.regs.ebp - 0x10

        # Store the symbolic variables into the stack memory
        initial_state.memory.store(addr_password0, password0, endness='Iend_LE')
        initial_state.memory.store(addr_password1, password1, endness='Iend_LE')
        ```
    *   通过这几步，我们成功地在不执行 `scanf` 的情况下，将两个符号变量注入到了程序期望它们出现的位置。

## 实践步骤

1.  **生成 `04_angr_symbolic_stack` 可执行文件**：
    *   `python generate.py 5678 04_angr_symbolic_stack` (您可以使用任何种子)。
2.  **获取起始地址**:
    *   使用 `r2 -q -c 'aaa; pdf @ sym.handle_user'` 或其他反汇编工具分析 `handle_user` 函数。
    *   找到 `call <...scanf...>` 指令。
    *   记录 `call` 指令之后、用于清理栈的 `add esp, ...` 指令**之后**的那条指令的地址。这将是您的 `start_address`。
3.  **修改 `scaffold04.py`**：
    *   将 `path_to_binary` 设置为正确的二进制文件路径。
    *   设置正确的 `start_address`。
    *   在创建 `blank_state` 后，通过 `initial_state.regs.ebp = initial_state.regs.esp` 初始化栈帧基址。
    *   创建两个 32 位的 `claripy.BVS` 符号变量 `password0` 和 `password1`。
    *   计算出两个密码在栈上的地址（`ebp - 0xc` 和 `ebp - 0x10`）。
    *   使用 `initial_state.memory.store()` 将这两个符号变量写入计算出的地址，确保使用 `endness='Iend_LE'`。
    *   实现 `is_successful` 和 `should_abort` 函数，让它们检查 `state.posix.dumps(sys.stdout.fileno())` 的输出中是否分别包含 "Good Job." 和 "Try again."。
    *   在找到 `solution_state` 后，使用 `solver.eval()` 分别解析出两个符号变量的具体值。
    *   将两个整数解格式化为由空格分隔的字符串。
4.  **运行解决方案**：
    *   执行您的 Python 脚本：`python scaffold04.py`
    *   脚本将输出需要输入到程序的两个无符号整数密码。

祝您在探索栈操作的旅程中取得成功！
