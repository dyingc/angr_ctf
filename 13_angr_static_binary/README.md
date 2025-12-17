# 13_angr_static_binary：静态二进制下的符号执行，需手动 hook 库函数

本关的核心目标：理解静态链接二进制文件与 angr 的交互。当二进制静态编译时，angr 的自动库函数替换失效，需要手动识别并 hook 标准库函数。程序逻辑与第 00 关相同：循环比较输入字符与变换结果，全部匹配则输出 "Good Job."。

静态二进制（static binary）将所有依赖库直接编译进可执行文件，不依赖外部共享库。这导致 angr 无法自动识别和替换标准库函数（如 printf、scanf），需手动处理。


## TL;DR

- 静态二进制：所有库函数静态链接，无外部依赖；angr 无法自动 hook 标准库。
- 关键步骤：从 main 函数开始执行（而非 entry_state）；手动筛选并 hook 所需标准库函数（如 strcmp、printf、scanf）。
- Hook 方法：用 `project.hook(addr, SIM_PROCEDURES['libc']['func']())` 替换指定地址的函数。
- 可选：替换 `__libc_start_main` 跳过初始化开销。
- 实测效果：与动态版本类似，但需更多手动配置。


## 1. 程序结构与关键点（从 Pcode 分析）

- 伪代码（简化）：
  ```c
  char local_40[20];  // 目标字符串缓冲区
  char local_2c[20];  // 输入缓冲区

  builtin_strncpy(local_40, "KLXLFFSS", 8);  // 设置目标
  scanf("%20s", local_2c);  // 读取输入

  for (int i=0; i<8; i++) {
    local_2c[i] = complex_function(local_2c[i], i);  // 变换输入
  }

  if (strcmp(local_2c, local_40) == 0) puts("Good Job.");
  else puts("Try again.");
  ```
- `complex_function`：对输入字符应用公式 `(ch - 'A' + i * 0x25) % 26 + 'A'`（类似凯撒密码）。
- 目标：输入 8 字符，经过变换后等于 "KLXLFFSS"。

关键差异：静态编译，无外部库依赖；需手动处理所有库函数。


## 2. 静态二进制与 angr 的挑战

### 为什么静态二进制特殊？
- 动态链接：二进制调用外部库函数（.so/.dll）；angr 可自动识别并替换为高效 SimProcedure。
- 静态链接：库函数代码直接编译进二进制；angr 看到的是原始汇编，无法自动识别为“printf”或“scanf”。
- 结果：angr 会执行原始函数实现（慢、复杂），或因缺少模拟而失败。

### 解决方案
- **手动 hook**：识别库函数地址，用 angr 的 SimProcedure 替换。
- **起始点调整**：用 `project.factory.blank_state(addr=main_addr)` 从 main 开始，跳过初始化。
- **可选优化**：hook `__libc_start_main` 跳过 glibc 初始化（可节省时间）。

### 与第 00 关对比
- 第 00 关（动态）：用 `entry_state()` 从程序入口开始，angr 自动处理库函数。
- 第 13 关（静态）：用 `blank_state(addr=main_addr)` 从 main 开始，手动 hook 所有库函数。
- 逻辑相同，但静态版本需更多配置。


## 3. 解法实现（基于 scaffold13.py）

### 核心步骤

1. **筛选符号**（symbol_filter 函数）：
   - 从 `project.loader.symbols` 获取所有符号。
   - 过滤感兴趣的函数名（如 strcmp、printf、scanf）。
   - 返回地址→符号映射。

2. **匹配 SimProcedure**（get_simprocedure_by_name 函数）：
   - 从 `SIM_PROCEDURES['libc']` 获取对应实现。
   - 处理命名差异（如 `__isoc99_scanf` → `scanf`）。
   - 无法匹配时打印警告。

3. **Hook 替换**（hook_simprocedures 函数）：
   - 对每个地址调用 `project.hook(addr, simproc())`。
   - 示例：`project.hook(scanf_addr, SIM_PROCEDURES['libc']['scanf']())`。

4. **创建状态**：
   - `state = project.factory.blank_state(addr=main_addr)`：从 main 开始（推荐，更精确）。
   - 注：`entry_state()` 也可工作（也需要从 main 开始），且性能差异可忽略；若 entry_state 有效，可简化代码。
   - 添加选项：`ZERO_FILL_UNCONSTRAINED_MEMORY`、`ZERO_FILL_UNCONSTRAINED_REGISTERS`。

5. **探索**：
   - `simgr.explore(find=..., avoid=...)`：基于 stdout 匹配。

### 示例代码片段

```python
# 筛选并 hook
interested_symbols = symbol_filter(project)
syms = get_simprocedure_by_name(interested_symbols)
hook_simprocedures(project, syms)

# 从 main 开始
main_addr = project.loader.find_symbol('main').rebased_addr
state = project.factory.blank_state(
    addr=main_addr,
    add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                 angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS}
)

# 探索
simgr.explore(find=lambda s: b"Good Job." in s.posix.dumps(1),
              avoid=lambda s: b"Try again." in s.posix.dumps(1))
```

### 可选：Hook __libc_start_main
- 在静态二进制中，程序入口调用 `__libc_start_main` 初始化环境。
- Hook：`project.hook(libc_start_main_addr, SIM_PROCEDURES['glibc']['__libc_start_main']())`。
- 效果：跳过初始化，直接进入 main，节省执行时间。


## 4. 符号识别与匹配要点

- **感兴趣函数**：scaffold 指定 `['strcmp', 'printf', 'exit', '__isoc99_scanf', 'puts']`（从 Pcode 分析得来）。
- **地址获取**：`sym.rebased_addr` 获得重定位后地址。
- **命名调整**：`__isoc99_scanf` → `scanf`（移除前缀匹配）。
- **未匹配处理**：如 `builtin_strncpy` 无对应 SimProcedure，忽略（本关不影响解题）。
- **验证**：用 r2/Ghidra 检查符号表，确保地址正确。


## 5. 与动态版本对比

- **性能**：静态需手动 hook，初始配置多；执行时因库函数模拟更快。
- **可靠性**：动态依赖 angr 自动识别；静态需手动维护符号列表。
- **适用场景**：静态二进制常见于嵌入式/CTF；动态更易用但依赖外部库。

### 何时选静态处理？
- 二进制静态编译、angr 报“外部函数未模拟”错误时。
- 需要精细控制库函数行为时。
- CTF 中二进制为静态时。


## 6. 常见坑位

- **符号未找到**：检查二进制符号表（`r2 -c 'is'` 或 Ghidra）；确保 `auto_load_libs=False`。
- **Hook 失败**：确认地址为函数入口；SimProcedure 实例化时加 `()`。
- **起始地址错**：用 `find_symbol('main').rebased_addr`，非 `entry_state`。
- **命名不匹配**：处理 `__isoc99_` 前缀；检查 SIM_PROCEDURES 字典。
- **未 hook 必要函数**：若 scanf 未 hook，angr 可能执行原实现导致慢或失败。
- **__libc_start_main**：可选 hook，但确保 main_addr 正确。

### 调试建议
- 运行前用 `r2` 确认符号：`r2 -c 'afl; afl~main; afl~strcmp'`。
- 若解不出，检查是否所有输入/输出函数已 hook。
- 打印 `len(project.hooked_by_addr)` 确认 hook 数量。


## 7. 参考链接

- SimProcedures 列表：https://docs.angr.io/en/latest/extending-angr/simprocedures.html
- 符号加载：https://docs.angr.io/en/latest/advanced-topics/loader.html
- 静态 vs 动态链接：GCC `-static` 选项文档。

——

本关 takeaway：静态二进制挑战 angr 的自动化能力，需手动 hook 保持高效。理解符号识别与状态创建是关键，为处理复杂二进制打基础。
