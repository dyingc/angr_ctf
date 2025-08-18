"""
MCP Server for exposing reverse engineering tools.

This server uses the mcp-sdk with a stdio transport, allowing a Gemini client
to interact with the reverse engineering functions defined in the project.
"""
import sys
import os
import yaml

# Add the project root to the Python path to resolve module imports
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

import asyncio
from fastmcp import FastMCP
from typing import List, Optional, Any, Dict, Literal

# Import the functions and their input models from the existing modules
from ai_agent.reverse_engineering import (
    get_function_list as get_function_list_impl,
    get_disassembly as get_disassembly_impl,
    get_pseudo_code as get_pseudo_code_impl,
    execute_python_code as execute_python_code_impl,
    execute_os_command as execute_os_command_impl,
    do_internal_inference as do_internal_inference_impl,
    InternalInferenceToolInput
)
from ai_agent.core import call_graph, cfg, strings, emulation
from ai_agent.samples.esil_sample.emulation import (
    emulate_region as emulate_region_impl,
    StopConditionType,
)
from ai_agent.libs.r2_utils import (
    get_binary_info as get_binary_info_impl,
    get_reachable_addresses as get_reachable_addresses_impl,
    extract_static_memory as extract_static_memory_impl,
    generate_angr_template as generate_angr_template_impl
)

# Initialize the FastMCP server
mcp = FastMCP(
    "reverse_engineering_tools",
    "A collection of tools for binary reverse engineering using Rizin and other utilities."
)

@mcp.tool()
async def get_function_list(binary_path: str, exclude_builtins: bool = True) -> List[Dict[str, Any]]:
    """
    Get the list of functions in a binary using the configured backend.

    Args:
        binary_path: The absolute path to the binary file.
        exclude_builtins: If True, excludes built-in functions (e.g., 'sym.printf').

    Returns:
        A dictionary containing the list of functions and other metadata.

    Example:
    >>> get_function_list("/path/to/binary")
    {
        "result": [
            {
            "offset": 4294968752,
            "name": "main",
            "size": 212,
            "file": "tmpw097u8dj.c",
            "signature": "int main (int argc, char **argv, int64_t envp);",
            "called_by": []
            },
            {
            "offset": 4294968620,
            "name": "sym._complex_function",
            "size": 132,
            "file": "tmpw097u8dj.c",
            "signature": "sym._complex_function (int64_t arg1, int64_t arg2, int64_t arg_20h);",
            "called_by": [
                {
                "name": "main",
                "offset": 4294968856,
                "five_instructs_before_calling": [
                    {
                    "addr": 4294968836,
                    "disasm": "ldrsw x9, [var_10h]"
                    },
                    ... ...
                ]
                }
            ]
            },
            ... ...
        ]
    }
    """
    return get_function_list_impl(binary_path, exclude_builtins)

@mcp.tool()
async def get_disassembly(binary_path: str, function_name: str) -> Dict[str, Any]:
    """
    Get disassembly of a specific function from a binary using the configured backend.

    Args:
        binary_path: The absolute path to the binary file.
        function_name: The name of the function to disassemble.

    Returns:
        A dictionary containing the disassembly text and other metadata.
    """
    return get_disassembly_impl(binary_path, function_name)

@mcp.tool()
async def get_pseudo_code(binary_path: str, function_name: str) -> Dict[str, Any]:
    """
    Get pseudo C code of a function using the configured backend's decompiler.

    Args:
        binary_path: The absolute path to the binary file.
        function_name: The name of the function to decompile.

    Returns:
        A dictionary containing the pseudo code and other metadata.
    """
    return get_pseudo_code_impl(binary_path, function_name)

@mcp.tool()
async def get_call_graph(binary_path: str, function_name: str = "") -> Dict[str, Any]:
    """
    Generates a call graph for a binary. Global or for a specific function.

    Args:
        binary_path: The absolute path to the binary file.
        function_name: The function to start the graph from. If empty, generates a global graph.

    Returns:
        A dictionary containing the nodes and edges of the call graph.

    Example:
    >>> get_call_graph("/path/to/binary", "main")
    {
        "result": {
            "result": {
            "nodes": [
                {
                "id": 0,
                "name": "dbg.main",
                "addr": "0x1000005b0"
                },
                {
                "id": 1,
                "name": "sym.imp.printf",
                "addr": "0x100000684"
                },
                ... ...
            ],
            "edges": [
                {
                "from": 0,
                "to": 1
                },
                ... ...
            ]
            },
            "need_refine": false,
            "prompts": []
        }
    }
    """
    return call_graph.get_call_graph(binary_path, function_name)

@mcp.tool()
async def get_cfg_basic_blocks(binary_path: str, function_name: str) -> Dict[str, Any]:
    """
    Retrieves the basic blocks of a function's Control Flow Graph (CFG).

    Args:
        binary_path: The absolute path to the binary file.
        function_name: The name of the function to analyze.

    Returns:
        A list of dictionaries, each representing a basic block, with
        {addr: {"addr": addr, "size": size, 'num_of_input_blocks': num_of_input_blocks, 'num_of_output_blocks': num_of_output_blocks, 'num_of_instructions': num_of_instructions, 'jump_to_addr': jump_to_addr, 'jump_to_func_with_offset': jump_to_func_with_offset}} format.

    Example:
    >>> get_cfg_basic_blocks("/path/to/binary", "main")
    {
    "result": [
        {
        "0x1000005b0": {
            "addr": "0x1000005b0",
            "size": 68,
            "num_of_input_blocks": 0,
            "num_of_output_blocks": 1,
            "num_of_instructions": 17,
            "jump_to_addr": "0x1000005f4",
            "jump_to_func_with_offset": "dbg.main + 68"
        }
        },
        {
        "0x1000005f4": {
            "addr": "0x1000005f4",
            "size": 12,
            "num_of_input_blocks": 2,
            "num_of_output_blocks": 2,
            "num_of_instructions": 3,
            "jump_to_addr": "0x10000063c",
            "jump_to_func_with_offset": "dbg.main + 140",
            "fall_through_addr": "0x100000600",
            "fall_through_func_with_offset": "dbg.main + 80"
        }
        },
        ... ...
    ],
    "need_refine": false,
    "prompts": []
    }
    """
    return cfg.get_cfg_basic_blocks(binary_path, function_name)

@mcp.tool()
async def get_strings(binary_path: str, min_length: int = 4) -> Dict[str, Any]:
    """
    Extracts all printable strings from a binary file.

    Args:
        binary_path: The absolute path to the binary file.
        min_length: The minimum character length of the strings to extract.

    Returns:
        A list of dictionaries, each representing a found string.
    Example:
    >>> get_strings("/path/to/binary", 4)
    {
        "result": {
            "result": [
            {
                "vaddr": 4294969015,
                "paddr": 1719,
                "ordinal": 0,
                "size": 12,
                "length": 11,
                "section": "2.__TEXT.__cstring",
                "type": "ascii",
                "string": "Try again.\\n"
            },
            ... ...
            ],
            "need_refine": false,
            "prompts": []
        }
    }
    """
    return strings.get_strings(binary_path, min_length)

@mcp.tool()
async def search_string_refs(binary_path: str, query: str, ignore_case: bool = True, max_refs: int = 50) -> Dict[str, Any]:
    """
    Finds all references in the code to strings matching a given query.

    Args:
        binary_path: The absolute path to the binary file.
        query: The substring or regular expression to search for.
        ignore_case: If True, the search is case-insensitive.
        max_refs: The maximum number of references to return for each matched string.

    Returns:
        A list of dictionaries for each matched string and its references.
    Example:
    >>> search_string_refs("/path/to/binary", "try", True, 10)
    {
        "result": [
            {
            "string": "Try again.\\n",
            "str_addr": "0x1000006b7",
            "refs": [
                {
                "fcn": "sym._complex_function",
                "offset": 4294968680,
                "disasm": "add x0, x0, str.Try_again._n"
                },
                {
                "fcn": "main",
                "offset": 4294968920,
                "disasm": "add x0, x0, str.Try_again._n"
                }
            ]
            }
        ],
        "need_refine": false,
        "prompts": []
    }
    """
    return strings.search_string_refs(binary_path, query, ignore_case, max_refs)

@mcp.tool()
async def emulate_region(
    binary_path: str,
    start_addr: str,
    end_addr: str,
    register_inputs: dict,
    stack_inputs: dict,
    memory_inputs: dict,
    skip_external: bool = True,
    stop_type: StopConditionType = StopConditionType.FUNCTION_END,
    max_steps: int = 10000,
    robust_function_exit: bool = False,
    robust_bb_exit: bool = False,
) -> dict:
    """
    对二进制文件中的指定代码区域执行 ESIL 优化模拟，返回仅包含实际变化的寄存器和内存、精简执行快照等结构化结果。
    推荐用于自动化二进制理解、辅助漏洞分析链条的 agent，支持复杂参数配置和跨架构自动判别。

    Args:
        binary_path (str): 必填。待分析 ELF/Mach-O/PE 文件的路径。
        start_addr (str | int): 必填。模拟起始位置，可为符号名（如 'main'）、偏移表达式（如 'func+0x10'）或地址（十六进制/十进制）。
        end_addr (str | int | None, 可选): 显式的模拟终止地址（同上类型）。若未给定，按照 stop_type 推断函数或基本块终点。
        register_inputs (dict[str, int | bytes] | None, 可选): 初始寄存器状态，通常用于模拟参数寄存/上下文恢复。bytes 类型建议以十六进制字符串（如 '41414141'）传递。示例：{'rdi': b"AAAA", 'rcx': 0x1234}
        stack_inputs (dict[int, int | bytes] | None, 可选): 以**当前栈顶为基准**写入数据，常用于模拟被调函数参数、手动构造栈帧或还原特定调用场景。键为偏移量（负数向高地址），值支持 int/bytes（建议十六进制字符串传输）。
            示例：{-0x10: b"AAAA", -0x14: 0xdeadbeef}
        memory_inputs (dict[int, int | bytes] | None, 可选): 指定绝对地址写入内存，用于输入外部缓冲区/全局变量等。格式同上。
            示例：{0x602000: b"secret", 0x10050: 0x41414141}
        skip_external (bool, 可选): 是否跳过外部函数（如 printf 等 LIBC/PLT 接口），跳过时会自动填充返回值。建议为 True（默认），以提高自动化和离线复现能力。
        stop_type (StopConditionType, 可选): 停止条件类型，支持 FUNCTION_END（默认）、BASIC_BLOCK_END、ADDRESS、MANUAL 及其它枚举选项，详细说明见 StopConditionType 注释。
        max_steps (int, 可选): 最大模拟步数，防止死循环。默认 10000。
        robust_function_exit (bool, 可选): 是否收集全部外跳出口提升函数终止容错性。建议复杂/混淆二进制设为 True。
        robust_bb_exit (bool, 可选): 是否收集全部基本块外跳出口。

    Returns:
        dict: 结构化 JSON 结果，核心字段如下（所有均可直接序列化）：
            - final_state:     {'register_changes': ..., 'memory_changes': ..., 'total_registers': int, 'total_memory_locations': int}
            - execution_trace: [{} ...]，每步只保留真正有变化的寄存器/内存，含 pc/disasm/step_number/register_changes/memory_changes 等
            - execution_stats: {'steps_executed': int, 'trace_entries': int, 'compression_ratio': str, 'total_register_changes': int, ...}
            - stop_reason:     终止原因字符串
            - stop_condition:  实际生效的 (StopConditionType, value) 元组
        典型输出片段示例：
            {
                "final_state": {"register_changes": {"rax": {"prev": 0, "curr": 1}}, ...},
                "execution_trace": [
                    {"pc": 4196096, "instruction": "mov eax, 1", "step_number": 3, ...},
                    ...
                ],
                "stop_reason": "reached_function_end"
            }

    用例示范:
        调用格式（函数调用/JSON Function-Calling等场景）：
        {
            "tool_name": "emulate_region",
            "arguments": {
                "binary_path": "./bin/crackme",
                "start_addr": "sym.check_pass",
                "register_inputs": {"rdi": "41414141"},
                "stack_inputs": {"-0x10": "deadbeef"}
            }
        }
    行为要点:
        - 推荐所有 bytes 用十六进制或 base64 编码传输，由 LLM 服务端还原为 bytes。
        - stack_inputs 支持高度自定义的栈布局，还可联合 register_inputs 实现完整手工场景还原（如 fuzzing、漏洞利用链前置）。
        - 参数均自动转发到底层实现，与 ai_agent.esil_sample.emulation.emulate_region 保持一致。

    """
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None,
        emulate_region_impl,
        binary_path,
        start_addr,
        end_addr,
        register_inputs,
        stack_inputs,
        memory_inputs,
        skip_external,
        stop_type,
        max_steps,
        robust_function_exit,
        robust_bb_exit,
    )

@mcp.tool()
async def emulate_function(binary_path: str, function_name: str, max_steps: int = 6, timeout: int = 5, stack_bytes: int = 32, stack_size: int = 0x10000, stack_base: int = 0x70000000, data_size: int = 0x1000, data_base: int = 0x60000000) -> Dict[str, Any]:
    """
    Performs a step-by-step emulation of a function using the configured backend.

    Args:
        binary_path: The absolute path to the binary file.
        function_name: The name of the function to emulate.
        max_steps: The maximum number of instructions to emulate.
        timeout: The maximum time in seconds to allow for the emulation.
        stack_bytes: The number of bytes to read from the stack for snapshotting.
        stack_size: The size of the stack memory region.
        stack_base: The base address of the stack memory region.
        data_size: The size of the additional data memory region.
        data_base: The base address of the additional data memory region.

    Returns:
        A dictionary containing the emulation trace and final register states, or an error.
    """
    return emulation.emulate_function(binary_path, function_name, max_steps, timeout, stack_bytes=stack_bytes, stack_size=stack_size, stack_base=stack_base, data_size=data_size, data_base=data_base)

@mcp.tool()
async def execute_python_code(code: str, timeout: int = 60) -> Dict[str, Any]:
    """
    Execute Python code passed as a string and return the output.

    Args:
        code: A string containing Python code to execute.
        timeout: Maximum execution time in seconds before timing out. Note, due to the nature of `symbolic execution`, you should set a much longer timeout if you're using `angr` and expect complex code paths to be explored.

    Returns:
        The output of the executed code as a string.
    """
    # This function is synchronous in the original implementation.
    # We run it in a separate thread to avoid blocking the asyncio event loop.
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, execute_python_code_impl, code, timeout)

@mcp.tool()
async def execute_os_command(command: str, timeout: int = 60) -> Dict[str, Any]:
    """
    Execute an OS command and return the output.

    Args:
        command: The OS command to execute.
        timeout: Maximum execution time in seconds before timeout.

    Returns:
        A dictionary containing the command output, error, and status.
    """
    return execute_os_command_impl(command, timeout)

@mcp.tool()
async def do_internal_inference(
    known_facts: List[str],
    reasoning_method: str,
    arguments: List[str],
    inferred_insights: List[str],
    validation_check: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Perform internal reasoning and inference based on existing known facts.

    Args:
        known_facts: List of known facts or information.
        reasoning_method: Type of reasoning applied (e.g., deduction).
        arguments: The lines of reasoning constructed from the facts.
        inferred_insights: The final insights or results derived.
        validation_check: Internal validation or consistency check explanation.

    Returns:
        A dictionary representing the structured inference.
    """
    # This function is synchronous, so we can call it directly.
    result_model = do_internal_inference_impl(
        known_facts=known_facts,
        reasoning_method=reasoning_method,
        arguments=arguments,
        inferred_insights=inferred_insights,
        validation_check=validation_check
    )
    return result_model.model_dump()

@mcp.tool()
async def get_binary_info(binary_path: str) -> Dict[str, Any]:
    """
    提取二进制基础信息，供 angr/脚本初始化分析，包括架构/端序/入口/基址/PIE/strip/节区表/PLT/GOT 表。
    Args:
        binary_path: ELF或Mach-O文件路径
    Returns:
    >>> get_binary_info("/path/to/binary")
    {
        "arch": "arm",
        "bits": 64,
        "endian": "little",
        "entry_point": 4294968752,
        "base_addr": 4294967296,
        "is_pie": true,
        "is_stripped": false,
        "binary_type": "mach0",
        "sections": [
            {
            "name": "0.__TEXT.__text",
            "addr": 4294968568,
            "size": 396,
            "perm": "-r-x"
            },
            ... ...
        ],
        "plt_entries": {
            "exit": 4294968976,
            ... ...
        },
        "got_entries": {}
    }
    """
    return get_binary_info_impl(binary_path)

@mcp.tool()
async def get_reachable_addresses(binary_path: str, start_addr: str, entry_mode: str = "function",) -> Dict[str, Any]:
    """
    从给定地址开始分析其所在函数的控制流图（CFG），返回一份**高信息密度且跨架构通用**的摘要，
    便于自动化逆向工程与基于 LLM 的推理/规划。

    设计目标
    --------
    - 以“包含 start_addr 的**整个函数**”为分析范围（不随 entry_mode 改变），
    统一抽取路径可达性、出口点、调用点、间接跳转、switch 与字符串引用等关键信息。
    - 出口点（exit_points）的定义是从“**当前函数视角**”出发：当块的所有后继都离开本函数，
    或该块为显式终止（ret/trap/invalid/swi），则视为函数内的**终点**（覆盖尾跳/PLT stub 等）。
    - 结果尽量简洁，但足以支撑常见的 find/avoid、路径裁剪、模糊测试与交互式溯源等任务。

    入口模式
    --------
    - ``function``：起点为函数入口基本块（分析范围仍是该函数的全部基本块）。
    - ``block``：起点为“包含 start_addr 的基本块”（分析范围同上，只改变遍历起点）。

    Parameters
    ----------
    binary_path : str
        二进制文件路径。
    start_addr : str | int
        起始地址（可为整数地址或 r2 可解析的表达式，如符号名/偏移等）。内部会解析并归一化到所属函数/块。
    entry_mode : Literal["function", "block"]，默认为 "function"
        遍历起点模式；默认为 "function"。仅影响 DFS 的起点，不改变分析范围。

    Returns
    -------
    dict
        返回一个包含以下键的字典（所有地址为整型虚拟地址）：

        - ``entry_block`` (int | None)
            实际使用的遍历起点基本块地址。
        - ``exit_points`` (List[Dict[str, Any]])
            函数内“必然终止”块集合。每项形如
            ``{"addr": <block_addr>, "reason": "<ret|trap|invalid|swi|no_successor|external_jump>"} ``。
            - ``external_jump``：该块所有后继均不在本函数内（典型尾跳/跳至导入桩等）。
            - 该定义与架构无关（x86 的 jmp、AArch64 的 b/br 等均适用）。
        - ``partial_exits`` (List[Dict[str, Any]])
            既有指向函数内的后继、又有指向函数外的后继的块，用于标注“可能逃逸”分支。
            形如 ``{"addr": <block_addr>, "out_of_func_targets": [<addr> ...]}``。
        - ``unreachable_from_start`` (List[int])
            在本函数中、但从所选起点**不可达**的基本块地址列表。
        - ``loops`` (List[Dict[str, int]])
            检测到的循环回边，形如 ``{"head": <loop_header_addr>, "back_edge": <source_addr>}``。
        - ``callsites`` (List[Dict[str, Any]])
            调用点摘要。每项形如
            ``{"addr": <insn_addr>, "callee": <str|None>, "target": <int|None>, "indirect": <bool>, "import": <bool>}``。
            - ``indirect``：是否为间接调用或未解析到静态目标。
            - ``import``：callee 名称是否看起来是导入符号（如 ``sym.imp.*`` / ``imp.*``）。
        - ``indirect_jumps`` (List[Dict[str, Any]])
            间接跳转摘要。每项至少包含 ``{"addr": <insn_addr>}``，若能静态取到潜在目标，
            会补充 ``targets_in_func`` 与 ``targets_out_func``（均为地址列表）。
        - ``switches`` (List[Dict[str, Any]])
            switch 信息，形如 ``{"addr": <block_addr>, "cases": [<addr> ...], "default": <addr|None>}``。
        - ``string_refs_in_func`` (List[Dict[str, Any]])
            命中在本函数内的字符串引用点，形如 ``{"ref_addr": <insn_addr>, "ref_function": <str>, "ref_instruction": <str>, "string_value": <str>}``。
            （内部对字符串数量与每个字符串的引用数做了轻量限速，以避免性能问题。）
        - ``summary`` (Dict[str, int])
            汇总计数：``{"reachable_count": N, "unreachable_count": M, "exit_count": K, "loop_count": L}``。

    Example
    -------
    >>> get_reachable_addresses("/path/to/binary", 0x400100, entry_mode="function")
    {
        "entry_block": 4198400,
        "exit_points": [
            {"addr": 4198464, "reason": "ret"},
            {"addr": 4198496, "reason": "external_jump"}
        ],
        "partial_exits": [
            {"addr": 4198452, "out_of_func_targets": [4199000]}
        ],
        "unreachable_from_start": [4198528],
        "loops": [
            {"head": 4198400, "back_edge": 4198448}
        ],
        "callsites": [
            {"addr": 4198440, "callee": "sym.imp.printf", "target": 4199936, "indirect": false, "import": true}
        ],
        "indirect_jumps": [
            {"addr": 4198456, "targets_in_func": [], "targets_out_func": []}
        ],
        "switches": [
            {"addr": 4198460, "cases": [4198472, 4198480], "default": 4198488}
        ],
        "string_refs_in_func": [
            {"ref_addr": 4198468, "ref_function": "main", "ref_instruction": "add x1, x1, str.Good_Job._n", "string_value": "Good Job"},
            {"ref_addr": 4198476, "ref_function": "main", "ref_instruction": "add x1, x1, str.Try_again._n", "string_value": "Try again"}
        ],
        "summary": {
            "reachable_count": 12,
            "unreachable_count": 1,
            "exit_count": 2,
            "loop_count": 1
        }
    }

    Notes
    -----
    - 需先在 radare2 中完成 ``aaa`` 自动分析；内部主要依赖 ``agfj/afbj/pdj/izj/axtj`` 等输出。
    - “出口点”采用**函数内视角**定义：当块不再返回到本函数（如 ret、trap 或全部后继离开本函数）即视为出口。
    - 为兼顾性能，字符串枚举与引用关系提取做了简单限速（如最多 2000 条字符串、每串至多 50 个引用点）。
    - 本函数为**最小噪音**摘要，不提供完整 CFG 或前驱/后继映射；若需全量结构，请使用更详细的图导出流程。
    """
    return get_reachable_addresses_impl(binary_path, start_addr, entry_mode)

@mcp.tool()
async def extract_static_memory(binary_path: str, addr_expr: str, size: int) -> Dict[str, Any]:
    """
    读取给定虚拟地址静态内容&所属节区/权限（flag/秘钥硬编码场景），自动补救非ASCII自动编码推断。
    Args:
        binary_path
        addr_expr - str | int：虚拟地址或地址表达式，如：0x1000，"0x1000"，"main + 0x10"
        size
    Returns:
    >>> extract_static_memory("/path/to/binary", 0x1000, 64)
    {
        'content_bytes' = ['0x54', '0x72', '0x79', '0x20', '0x61', '0x67', '0x61', '0x69', '0x6e', '0x2e', '0xa', '0x0', '0x45', '0x6e', '0x74', '0x65']
        'content' = b'Try again.\n'
        'content_hex' = '54727920616761696e2e0a'
        'content_string' = 'Try again.\n'
        'section' = '2.__TEXT.__cstring'
        'permissions' = '-r-x'
    }
    """
    import json
    mem = extract_static_memory_impl(binary_path, addr_expr, size)
    def safe_value(v):
        if isinstance(v, (bytes, bytearray)):
            return repr(v)
        elif isinstance(v, (int, float, str, bool)) or v is None:
            return v
        else:
            return json.dumps(v)  # preserve structure for lists/dicts
    return {k: safe_value(v) for k, v in mem.items()}

@mcp.tool()
async def generate_angr_template(path_to_binary: str, analysis_goal: str) -> Dict[str, Any]:
    """
    根据分析目标获取 angr 代码模板。

    重要说明：
    - 返回的代码是一个模板（TEMPLATE），并非可直接运行的脚本。请勿直接复制粘贴运行。
    - 应结合逆向工程（RE）结果（CFG/字符串/符号/调用约定/I-O 模型）来编写最终的 angr 脚本。
    至少需要自定义：目标/避开地址或成功条件、输入大小/约束、hooks、以及任何与架构相关的寄存器或函数原型。

    Args:
        - path_to_binary (str, required): 二进制文件路径。此路径会被插入到模板代码中。
        - analysis_goal (str, required): YAML 文件中 `angr_templates` 下的精确键值（参见支持的取值）。

    支持的 `analysis_goal`：
        • path_search — 到达目标（地址或条件），可选地避开特定地址。
        • state_debug — 在断点处检查/操作 stashes 并打印最近的约束。
        • exploration_perf — 添加 DFS/BFS 策略、LoopSeer/Veritesting/Unicorn，并限制状态数量。
        • memory_init — 默认内存填零、映射临时页、按字节约束机密数据、轻量级架构初始化。
        • input_modeling — 在一个地方建模 stdin/argv/env/file 以及针对性寄存器/内存。
        • function_call — 以具体/符号参数调用函数；收集返回值/输出（感知架构差异）。
        • concolic_seed — 使用种子预约束 stdin；可选地后续移除预约束。
        • api_hooks — Hook libc（strcmp/strlen/printf/malloc/free）并根据需要添加自定义 SimProcedures。
        • vuln_detection — 使用启发式方法标记在大规模 stdin 下的符号化 RET 或栈 canary 篡改。
        • taint_tracking — 跟踪污点 stdin 到敏感函数（system/execve/strcpy），支持架构特定 arg0。
        • rop_chain — 通过 angrop 寻找 gadget 并构造 system/execve 链；payload 与当前架构匹配。
        • deobfuscation — 跳过常见 NOP（x86/x64 0x90，ARM64 0xD503201F）并搜索 “flag”。
        • protocol_reverse — 查找 recv/read 处理函数，跨架构设置 (buf, size)，推断字段，进行模糊翻转。
        • general_analysis — 参数化的测试框架（超时、技术），返回结构化结果字典。
        • other — 提供最基本的 angr 项目初始化模板，适合根据具体需求完全自定义分析逻辑。

    架构支持：
        ARM64（AArch64）、x64（AMD64）和 x86（32 位）在调用约定、返回寄存器、
        NOP/栈约定相关的地方均有支持。模板包含安全默认值，当某特性不适用时会优雅降级。

    Returns:
        dict: {"template_code": "<已注入 binary_path 的字符串>"}
    """
    return generate_angr_template_impl(path_to_binary, analysis_goal)

# async def test():
#     result = await extract_static_memory("/Users/yingdong/VSCode/angr/angr_ctf/00_angr_find/00_angr_find_arm", 0x1000006b7, 0x10)
#     print(result)

# asyncio.run(test())

if __name__ == "__main__":
    # Load configuration from YAML file
    config_path = os.path.join(project_root, "ai_agent", "config.yaml")
    with open(config_path) as f:
        config = yaml.safe_load(f)
    # Run the server using stdio transport
    mcp.run(transport='stdio')
