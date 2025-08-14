# `rz_utils` 库文档（中文版）

本文档介绍了 `rz_utils.py` 提供的各项函数。该库基于 `Rizin`（通过 `rzpipe`）封装了一组 Python 接口，用于二进制程序分析。

---

### 1. `get_call_graph`

**功能说明：**
为二进制文件生成调用图（Call Graph）。既可以为整个二进制生成全局调用图，也可以以某个函数为起点、并限定深度，生成局部调用图。

**参数：**
- `binary_path` (str)：二进制文件的绝对路径。
- `function_name` (Optional[str])：调用图的起始函数名。若为 `None`，则生成全局调用图。

**返回值：**
- `Dict[str, Any]`：包含以下两个键的字典
  - `"nodes"`：节点列表，每个节点是一个字典，包含 `"name"` 与 `"addr"`。
  - `"edges"`：边列表，每条边是一个元组 `(from_address, to_address)`，表示有向边。

**示例：**
```python
from ai_agent import rz_utils

# 获取全局调用图
global_graph = rz_utils.get_call_graph("/path/to/your/binary")
print(global_graph["nodes"])

# 以函数 main 为起点，生成调用图
main_graph = rz_utils.get_call_graph("/path/to/your/binary", function_name="main")
print(main_graph["edges"])
```

---

### 2. `get_cfg_basic_blocks`

**功能说明：**
获取某函数控制流图（CFG）的基本块信息，包括块边界及后继块。

**参数：**
- `binary_path` (str)：二进制文件的绝对路径。
- `function_name` (str)：要分析的函数名。

**返回值：**
- `List[Dict[str, Any]]`：基本块字典列表。每个字典的键是基本块的地址，值是包含以下信息的字典：
  - `"addr"` (int)：基本块起始地址。
  - `"size"` (int)：块大小（字节数）。
  - `"num_of_input_blocks"` (int)：输入块数量。
  - `"num_of_output_blocks"` (int)：输出块数量。
  - `"num_of_instructions"` (int)：指令数量。
  - `"jump_to_addr"` (Optional[int])：跳转目标地址（如果有）。
  - `"jump_to_func_with_offset"` (Optional[str])：跳转目标函数名及偏移（如果有）。
  - `"fall_through_addr"` (Optional[int])：自然下落目标地址（如果有）。
  - `"fall_through_func_with_offset"` (Optional[str])：自然下落目标函数名及偏移（如果有）。

**示例：**
```python
from ai_agent import rz_utils

blocks = rz_utils.get_cfg_basic_blocks("/path/to/your/binary", function_name="main")
for block in blocks:
    print(f"Block at {hex(block['offset'])} has successors: {[hex(s) for s in block['succ']]}")
```

---

### 3. `get_strings`

**功能说明：**
从二进制中提取所有可打印字符串，要求长度不小于给定阈值。

**参数：**
- `binary_path` (str)：二进制文件的绝对路径。
- `min_length` (int)：最小字符串长度。默认 `4`。

**返回值：**
- `List[Dict[str, Any]]`：字符串信息字典列表，每项包含
  - `"vaddr"`：虚拟地址
  - `"paddr"`：物理地址
  - `"string"`：字符串内容
  - `"section"`：所在段
  - `"length"`：字符串长度

**示例：**
```python
from ai_agent import rz_utils

strings = rz_utils.get_strings("/path/to/your/binary", min_length=8)
for s in strings:
    print(f"Found string: '{s['string']}' at address {hex(s['vaddr'])}")
```

---

### 4. `search_string_refs`

**功能说明：**
查找代码中对满足指定查询（子串或正则）的字符串的引用位置。

**参数：**
- `binary_path` (str)：二进制文件的绝对路径。
- `query` (str)：要搜索的子串或正则表达式。
- `ignore_case` (bool)：大小写不敏感开关。默认 `True`。
- `max_refs` (int)：对于每个匹配字符串，最多返回多少条引用。默认 `50`。

**返回值：**
- `List[Dict[str, Any]]`：匹配结果列表。每个元素为一条字符串匹配，包含
  - `"string"` (str)：匹配到的字符串
  - `"str_addr"` (int)：字符串地址。
  - `"refs"` (List[Dict])：引用信息列表，每条引用包含：
    - `"caller"` (str)：调用函数名。
    - `"calling_addr"` (int)：调用指令地址。
    - `"disasm"` (str)：调用指令的反汇编。
    - `"opcode"` (str)：调用指令的操作码。

**示例：**
```python
from ai_agent import rz_utils

# 查找包含 "password" 的字符串引用
refs = rz_utils.search_string_refs("/path/to/your/binary", query="password")
for ref_info in refs:
    print(f"String '{ref_info['string']}' is referenced at:")
    for r in ref_info['refs']:
        print(f"  - {r['fcn']} + {hex(r['offset'])}")
```

---

### 5. `emulate_function`

**功能说明：**
使用 Rizin 的 RzIL（Rizin Intermediate Language）对指定函数进行逐指令模拟执行（Emulation），并在每步记录寄存器状态。模拟运行在独立线程中，可设置超时时间。支持对栈和数据段进行自定义内存映射，并能模拟外部函数调用。

**参数：**
- `binary_path` (str)：二进制文件的绝对路径。
- `function_name` (str)：需要模拟的函数名。
- `max_steps` (int)：最多模拟多少条指令。默认 `100`。
- `timeout` (int)：模拟的最长允许时间（秒）。默认 `60`。
- `stack_bytes` (int)：每次执行步骤时读取的栈快照字节数。默认 `32`。
- `stack_size` (int)：为模拟分配的栈内存大小（字节）。默认 `0x10000` (64KB)。
- `stack_base` (int)：栈内存的基地址。默认 `0x70000000`。
- `data_size` (int)：为模拟分配的额外数据内存大小（字节）。默认 `0x1000` (4KB)。
- `data_base` (int)：数据内存的基地址。默认 `0x60000000`。

**返回值：**
- `Dict[str, Any]`：模拟结果字典，包含：
  - `"success"` (bool)：模拟是否成功。
  - `"final_registers"` (Dict)：最终寄存器状态。
  - `"execution_trace"` (List[Dict])：执行轨迹列表，每步包含 `"step"`、`"pc"`、`"instruction"`（反汇编）、`"opcode"`、`"type"`、`"registers"` 和 `"timestamp"`。
  - `"vm_state_changes"` (List[Dict])：VM 状态变化列表，包含寄存器、内存和栈的变化。
  - `"execution_summary"` (Dict)：执行摘要，包含 `"steps_executed"`、`"execution_time"`、`"memory_setup_success"` 和 `"architecture"`。
  - `"emulation_type"` (str)：模拟类型，固定为 "RzIL_v2"。
  - `"setup_log"` (List[str])：详细的设置日志。
  - 如果失败或超时，可能包含 `"error"` (str) 和 `"partial_trace"` (List[Dict])。

**示例：**
```python
from ai_agent import rz_utils

result = rz_utils.emulate_function(
    binary_path="/path/to/your/binary",
    function_name="calculate_key",
    max_steps=50,
    timeout=60,
    stack_bytes=64,           # 读取64字节的栈快照
    stack_size=0x20000,       # 128KB栈大小
    stack_base=0x70000000,    # 栈基地址
    data_size=0x2000,         # 8KB数据区域
    data_base=0x60000000      # 数据区域基地址
)
if "error" in result:
    print(f"Emulation failed: {result['error']}")
    # 打印设置日志以帮助调试
    if "setup_log" in result:
        print("Setup Log:")
        for log_entry in result["setup_log"]:
            print(f"  • {log_entry}")
else:
    print("Emulation completed successfully!")
    print(f"Steps executed: {result['execution_summary']['steps_executed']}")
    print(f"Architecture: {result['execution_summary']['architecture']}")
    print("\nFinal Registers:")
    print(result['final_registers'])
```

---

### 从 Radare2 迁移至 Rizin

该库已由使用 `r2pipe`（Radare2）迁移至 `rzpipe`（Rizin）。Rizin 是 Radare2 的社区分支，目标是提供更好的可用性与稳定性。

**主要差异与迁移注意事项：**

* **项目关系**：Rizin 源自 Radare2，大多数核心命令与功能保持向后兼容。
* **Python 绑定**：Radare2 使用 `r2pipe`，而 Rizin 使用 `rzpipe`。两者 API 基本一致，迁移较为直接。
* **命令行接口（CLI）**：绝大部分 `radare2` 命令（如 `aaa`, `afl`, `pdf`, `agj`, `aei`, `aer`）在 Rizin 中可直接使用。一些新增命令可能带有 `rz-` 前缀（如 `rz-asm`），但通过 `rzpipe` 调用的内部命令基本相同。
* **Ghidra 反编译**：伪 C 反编译命令 `pdg` / `pdgj` 在两者之间保持一致。
* **交叉引用（`axtj`）**：在旧版 Radare2 中，`axtj` 输出中可能直接包含调用函数名 `fcn_name`；而在 Rizin 中，`axtj` 主要给出 `from` 与 `to` 地址。若需获取调用方函数名，需要额外执行 `afij @ <address>`。本库中的 `search_string_refs` 函数已据此调整实现，能够正确解析 `axtj` 结果并获取调用方函数名及指令信息。
* **依赖**：请确保已安装 `rzpipe`，并且系统 PATH 中可以找到 `rizin`。不再需要 `r2pipe`。

通过本次迁移，库能够利用 Rizin 的持续开发与社区支持，同时保持与既有分析流程的兼容性。
