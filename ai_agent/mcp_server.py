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
from mcp.server.fastmcp import FastMCP
from typing import List, Optional, Any, Dict

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
from ai_agent.esil_sample.emulation import (
    emulate_region as emulate_region_impl,
    StopConditionType,
)

# Initialize the FastMCP server
mcp = FastMCP(
    "reverse_engineering_tools",
    "A collection of tools for binary reverse engineering using Rizin and other utilities."
)

@mcp.tool()
async def get_function_list(binary_path: str, exclude_builtins: bool = True) -> Dict[str, Any]:
    """
    Get the list of functions in a binary using the configured backend.

    Args:
        binary_path: The absolute path to the binary file.
        exclude_builtins: If True, excludes built-in functions (e.g., 'sym.printf').

    Returns:
        A dictionary containing the list of functions and other metadata.
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
async def get_call_graph(binary_path: str, function_name: Optional[str] = None) -> Dict[str, Any]:
    """
    Generates a call graph for a binary. Global or for a specific function.

    Args:
        binary_path: The absolute path to the binary file.
        function_name: Optional. The function to start the graph from. If None, generates a global graph.

    Returns:
        A dictionary containing the nodes and edges of the call graph.
    """
    return call_graph.get_call_graph(binary_path, function_name)

@mcp.tool()
async def get_cfg_basic_blocks(binary_path: str, function_name: str) -> List[Dict[int, Any]]:
    """
    Retrieves the basic blocks of a function's Control Flow Graph (CFG).

    Args:
        binary_path: The absolute path to the binary file.
        function_name: The name of the function to analyze.

    Returns:
        A list of dictionaries, each representing a basic block, with
        {addr: {"addr": addr, "size": size, 'num_of_input_blocks': num_of_input_blocks, 'num_of_output_blocks': num_of_output_blocks, 'num_of_instructions': num_of_instructions, 'jump_to_addr': jump_to_addr, 'jump_to_func_with_offset': jump_to_func_with_offset}} format.
    """
    return cfg.get_cfg_basic_blocks(binary_path, function_name)

@mcp.tool()
async def get_strings(binary_path: str, min_length: int = 4) -> List[Dict[str, Any]]:
    """
    Extracts all printable strings from a binary file.

    Args:
        binary_path: The absolute path to the binary file.
        min_length: The minimum character length of the strings to extract.

    Returns:
        A list of dictionaries, each representing a found string.
    """
    return strings.get_strings(binary_path, min_length)

@mcp.tool()
async def search_string_refs(binary_path: str, query: str, ignore_case: bool = True, max_refs: int = 50) -> List[Dict[str, Any]]:
    """
    Finds all references in the code to strings matching a given query.

    Args:
        binary_path: The absolute path to the binary file.
        query: The substring or regular expression to search for.
        ignore_case: If True, the search is case-insensitive.
        max_refs: The maximum number of references to return for each matched string.

    Returns:
        A list of dictionaries for each matched string and its references.
    """
    return strings.search_string_refs(binary_path, query, ignore_case, max_refs)

@mcp.tool()
async def emulate_region(
    binary_path: str,
    start_addr: str | int,
    end_addr: str | int | None = None,
    register_inputs: dict | None = None,
    stack_inputs: dict | None = None,
    memory_inputs: dict | None = None,
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
        timeout: Maximum execution time in seconds before timing out.

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


if __name__ == "__main__":
    # Load configuration from YAML file
    config_path = os.path.join(project_root, "ai_agent", "config.yaml")
    with open(config_path) as f:
        config = yaml.safe_load(f)
    # Run the server using stdio transport
    mcp.run(transport='stdio')
