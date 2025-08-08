Excellent question! Here are the tools I'd recommend for angr-based analysis (Radare2 优先，含详细可实现建议和首次需求场景优先级)：

---

## 1. **get_binary_info**
```python
def get_binary_info(binary_path: str) -> dict:
    """
    提取二进制基础信息，供 angr/脚本初始化分析，包括架构/端序/入口/基址/PIE/strip/节区表/PLT/GOT 表。

    Args:
        binary_path: ELF、PE或Mach-O文件路径

    Returns:
        dict: {
            'arch': 'x86_64',
            'bits': 64,
            'endian': 'little',
            'entry_point': 0x400000,
            'base_addr': 0x400000,
            'is_pie': False,
            'is_stripped': False,
            'binary_type': 'ELF',
            'sections': [{'name': '.text', 'addr': 0x400000, 'size': 0x1000}],
            'plt_entries': {'printf': 0x400100},
            'got_entries': {'printf': 0x601000}
        }
    实现建议:
      - 优先用 `r2 -q -c 'ij'` 获取架构、PIE、section等；补全缺失字段可用 python-pefile/pyelftools。
      - 对 ELF 可并用 `readelf -l -S ...` 校准 load segment/base_addr。
      - 返回所有涉及内存映射与符号执行相关的元数据。
    Priority: 00_angr_find
    """
```
**Why**: angr needs architecture info and memory layout for proper initialization
**Implementation**: Use `angr.Project(binary_path).loader` and `pefile`/`pyelftools`

---

## 2. **find_symbolic_constraints**
```python
def find_symbolic_constraints(binary_path: str, function_name: str) -> dict:
    """
    自动分析指定函数的数据符号化入口、显式约束和关键比较点。用于辅助 angr 自动选符号变量、自动插入路径约束。

    Args:
        binary_path: 可执行文件路径
        function_name: 目标函数名

    Returns:
        dict: {
            'input_sources': ['scanf', 'gets', 'fgets', 'read'],
            'comparison_points': [
                {'addr': 0x400500, 'type': 'strcmp', 'operands': ['input_buffer', 'constant_string']},
                {'addr': 0x400520, 'type': 'cmp', 'operands': ['eax', '0x42']}
            ],
            'buffer_sizes': {'input_buffer': 32},
            'loop_bounds': [{'addr': 0x400530, 'iterations': 8}]
        }
    实现建议:
      - 用 r2 `afcf`, `agjf`, `pdf` 结合自定义脚本批量提取所有输入API、dst缓冲区、所有 cmp/strcmp 等汇编比较点；
      - 数据流可用 r2 的 aeaf/aae/axf 定位符号变量流向，统计影响。
      - 可再综合 pyelftools/dwarf info 完善参数类型。
    Priority: 02_angr_find_condition
    """
```
**Why**: Helps LLM identify where to place symbolic variables and constraints
**Implementation**: Use Radare2 graph + dataflow (afcf/agjf/pdf/aeaf/axf), cross-check with DWARF (pyelftools)

---

## 3. **get_function_signature**
```python
def get_function_signature(binary_path: str, function_name: str) -> dict:
    """
    提取指定函数签名、调用约定、参数与局部变量、返回类型、栈帧布局。支持解析无符号时的静态推断。

    Args:
        binary_path: 文件路径
        function_name: 函数名

    Returns:
        dict: {
            'addr': 0x400000,
            'calling_convention': 'x64_sysv',
            'parameters': [
                {'type': 'int', 'register': 'rdi', 'name': 'argc'},
                {'type': 'char**', 'register': 'rsi', 'name': 'argv'}
            ],
            'return_type': 'int',
            'stack_frame_size': 0x30,
            'local_vars': [{'offset': -0x10, 'size': 8, 'type': 'buffer'}]
        }
    实现建议:
      - 首选 `r2 -qq -c "afij;afvj"` 拉取参数+局部变量分布。
      - DWARF/pyelftools补全类型信息。
      - 没有符号/调试时可静态分析 prologue/epilogue+惯例。
    Priority: 03_angr_symbolic_registers
    """
```

---

## 4. **trace_data_flow**
```python
def trace_data_flow(binary_path: str, source_addr: int, sink_addr: int) -> dict:
    """
    跟踪 source 到 sink 的数据流，收集所有变换操作与污染状态，辅助破解复杂 trans/encoding 路径。

    Args:
        binary_path: 文件路径
        source_addr: 源头（如 scanf/输入）
        sink_addr: 汇点（如 strcmp/比较）

    Returns:
        dict: {
            'path_exists': True,
            'transformations': [
                {'addr': 0x400100, 'operation': 'xor', 'operand': 0x42},
                {'addr': 0x400120, 'operation': 'add', 'operand': 3}
            ],
            'intermediate_functions': ['complex函数1'],
            'tainted_registers': ['rax', 'rbx'],
            'tainted_memory': [0x601000]
        }
    实现建议:
      - 用 `r2 -qqc 'aat; agfd...'` 获取简CFG，配合 axt 数据流分解。
      - 可调用 YARA/angr 数据流/污点分析辅助。
    Priority: 02_angr_find_condition
    """
```

---

## 5. **get_reachable_addresses**
```python
def get_reachable_addresses(binary_path: str, start_addr: int) -> dict:
    """
    基于 CFG，自动分析所有可达的成功/失败/出口块、不可达路径和循环结构（for angr find/avoid 提供依据）。

    Args:
        binary_path: 执行文件路径
        start_addr: 起始地址

    Returns:
        dict: {
            'success_addresses': [0x400200],  # 打印GoodJob
            'failure_addresses': [0x400300],  # 打印TryAgain
            'exit_points': [0x400400],
            'unreachable_from_start': [0x400500],
            'loops': [{'head': 0x400600, 'back_edge': 0x400650}]
        }
    实现建议:
      - r2 `agfj`/`agC` 拓扑遍历，自动归类 return/exit/分支情况。
      - 可选用 angr.CFGFast 验证节点覆盖精度。
    Priority: 00_angr_find
    """
```

---

## 6. **extract_static_memory**
```python
def extract_static_memory(binary_path: str, addr: int, size: int) -> dict:
    """
    读取给定虚拟地址静态内容&所属节区/权限（flag/秘钥硬编码场景），自动补救非ASCII自动编码推断。

    Args:
        binary_path
        addr
        size

    Returns:
        dict: {
            'content': b'HXUITWOA',
            'content_hex': '4858554954574f41',
            'content_string': 'HXUITWOA',
            'section': '.rodata',
            'permissions': 'r--'
        }
    实现建议:
      - r2 `px` + `iSj` 定位节区；auto-detect utf8/16/32 打印转换。
      - 指定 size>真实内容，需截断 trailing 空字节。
    Priority: 00_angr_find
    """
```

---

## 7. **search_string_refs**
```python
def search_string_refs(binary_path: str, query: str, ignore_case: bool = True, max_refs: int = 20) -> dict:
    """
    使用 `r2 iz` 查找所有字符串地址，并用 `axt` 查询引用指令，输出每个字符串的所有引用详情。

    Args:
        binary_path
        query
        ignore_case
        max_refs

    Returns:
        dict: {
            'results': [
                {'string': 'Good Job.', 'str_addr': 0x400800,
                 'refs': [{'fcn': 'main', 'addr': 0x400900, 'disasm': 'push ...'}]}
            ]
        }
    实现建议:
      - r2 `izj`, `axtj` 批量处理所有节区字符串及xref, 自动聚类排序。
    Priority: 00_angr_find
    """
```

---

## 8. **identify_angr_hooks**
```python
def identify_angr_hooks(binary_path: str) -> dict:
    """
    检测适合 angry hook/simproc 的外部/复杂函数，推荐 skip/summary/自定义实现方法和原因。

    Args:
        binary_path

    Returns:
        dict: {
            'recommended_hooks': [
                {'name': 'printf', 'addr': 0x400100, 'reason': 'output function'},
                {'name': 'sleep', 'addr': 0x400200, 'reason': 'time delay'},
                {'name': 'rand', 'addr': 0x400300, 'reason': 'non-deterministic'}
            ],
            'complex_functions': [
                {'name': 'crypto_func', 'addr': 0x400400, 'complexity': 1000}
            ]
        }
    实现建议:
      - r2 `aa; afl~sym.imp` 发现所有外部依赖；自行定义 cyclomatic complexity 分析排序。
      - 可联动 patch/导入自定义 SimProcedure。
    Priority: 09_angr_hooks
    """
```

---

## 9. **generate_angr_template**
```python
def generate_angr_template(path_to_binary: str, analysis_goal: str = 'find_path') -> dict:
    """
    给定基本参数，自动生成包含 angr.Project/State/Simgr/Explore 核心流程的 python 框架，部分步骤以 TODO 标注补充点，便于新分析任务快速“开箱即用”。

    Args:
        path_to_binary
        analysis_goal

    Returns:
        dict: {
            'template_code': '...完整py代码字符串...'
        }
    实现建议:
      - 结构参照 scaffoldXX.py/solutions/下范例，模板化主流程，所有与具体二进制相关的细节用占位（如 find_addr/avoid_addr/constraint等）留由人/LLM后续补全。
    Priority: 00_angr_find
    """
```

---

## 10. **function_fingerprint**
```python
def function_fingerprint(binary_path: str, function_name: str) -> dict:
    """
    统计函数的 cyclomatic_complexity, 调用深度, dominator 结构, 导入调用，为复杂度排序与分析分层提供依据。

    Args:
        binary_path
        function_name

    Returns:
        dict: {
            'cyclomatic_complexity': 5,
            'call_depth': 2,
            'dominators': [0x401000, ...],
            'import_calls': ['puts', 'memcmp']
        }
    实现建议:
      - r2 agj/aggj/afcf 输出所有路径复杂度信息；对于无 symbol 场景可静态CFG暴力统计。
    Priority: 03_angr_symbolic_registers
    """
```

---

## 11. **analyze_loop_bounds**
```python
def analyze_loop_bounds(binary_path: str, function_name: str) -> dict:
    """
    自动评估函数内部所有 loop 的最大/最小迭代次数/类型。用于 angr/Veritesting 优化，避免状态爆炸。

    Args:
        binary_path
        function_name

    Returns:
        dict: {
            'loops': [
                {'head': 0x400600, 'max_iter': 16, 'min_iter': 4, 'type': 'for'},
                ...
            ]
        }
    实现建议:
      - r2 agfj/agGj 分析所有循环块，静态估计块间关系。可以联合 angr loopseeker 二次验证。
    Priority: 04_angr_symbolic_stack
    """
```

---

## 12. **solve_constraints_sample**
```python
def solve_constraints_sample(constraints: list) -> dict:
    """
    给定 claripy AST 约束，调用内置或外部 z3，返回可行模型或 sat/unsat。适合自动验证 arbitrary AST。

    Args:
        constraints

    Returns:
        dict: {
            'sat': True/False,
            'model': {
                'var1': 0x41,
                ...
            }
        }
    实现建议:
      - 通过 python-z3 解析 claripy.ast 并 model()；异常情况及时 unsafe fail。
    Priority: 08_angr_constraints
    """
```

---

## 13. **collect_coverage_trace**
```python
def collect_coverage_trace(binary_path: str, input_args: str = "") -> dict:
    """
    动态运行并收集所有被执行的 basic block 和分支(trace)，适配 QEMU/Frida。辅助静态CFG对比和死块分析。

    Args:
        binary_path
        input_args

    Returns:
        dict: {
            'block_hits': [0x400800, ...],
            'branch_hits': [(0x400123, 0x400456), ...]
        }
    实现建议:
      - 核心调用 QEMU `-d exec`, frida 挂钩 BB，trace 按块聚合/归档。
    Priority: 12_angr_veritesting
    """
```

---

## 14. **auto_patch_constant**
```python
def auto_patch_constant(binary_path: str, addr: int, new_bytes: bytes) -> dict:
    """
    静态修改给定地址字节并产出新二进制；产物可用于后续自动化验证或 patch-challenge。

    Args:
        binary_path
        addr
        new_bytes

    Returns:
        dict: {
            'patched_binary_path': '/tmp/patched_xxx',
            'patch_summary': '0x401234: 41->99',
            'success': True/False
        }
    实现建议:
      - python 直接 mmap 写 patch，确保权限与格式校验。
    Priority: 13_angr_static_binary
    """
```

---
