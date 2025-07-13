
"""
MCP Server for exposing reverse engineering tools.

This server uses the mcp-sdk with a stdio transport, allowing a Gemini client
to interact with the reverse engineering functions defined in the project.
"""
import sys
import os

# Add the project root to the Python path to resolve module imports
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

import asyncio
from mcp.server.fastmcp import FastMCP
from typing import List, Optional, Any, Dict

# Import the functions and their input models from the existing modules
from ai_agent import r2_utils
from ai_agent.reverse_engineering import (
    get_function_list as get_function_list_impl,
    get_disassembly as get_disassembly_impl,
    get_pseudo_code as get_pseudo_code_impl,
    execute_python_code as execute_python_code_impl,
    execute_os_command as execute_os_command_impl,
    do_internal_inference as do_internal_inference_impl,
    InternalInferenceToolInput
)

# Initialize the FastMCP server
mcp = FastMCP(
    "reverse_engineering_tools",
    "A collection of tools for binary reverse engineering using radare2 and other utilities."
)

@mcp.tool()
async def get_function_list(binary_path: str, exclude_builtins: bool = True) -> Dict[str, Any]:
    """
    Get the list of functions in a binary using radare2.

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
    Get disassembly of a specific function from a binary using radare2.

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
    Get pseudo C code of a function using radare2's Ghidra decompiler plugin.

    Args:
        binary_path: The absolute path to the binary file.
        function_name: The name of the function to decompile.

    Returns:
        A dictionary containing the pseudo code and other metadata.
    """
    return get_pseudo_code_impl(binary_path, function_name)

@mcp.tool()
async def get_call_graph(binary_path: str, function_name: Optional[str] = None, depth: int = 3) -> Dict[str, Any]:
    """
    Generates a call graph for a binary. Global or for a specific function.

    Args:
        binary_path: The absolute path to the binary file.
        function_name: Optional. The function to start the graph from. If None, generates a global graph.
        depth: The depth of the call graph when a function_name is specified.

    Returns:
        A dictionary containing the nodes and edges of the call graph.
    """
    return r2_utils.get_call_graph(binary_path, function_name, depth)

@mcp.tool()
async def get_cfg_basic_blocks(binary_path: str, function_name: str) -> List[Dict[str, Any]]:
    """
    Retrieves the basic blocks of a function's Control Flow Graph (CFG).

    Args:
        binary_path: The absolute path to the binary file.
        function_name: The name of the function to analyze.

    Returns:
        A list of dictionaries, each representing a basic block.
    """
    return r2_utils.get_cfg_basic_blocks(binary_path, function_name)

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
    return r2_utils.get_strings(binary_path, min_length)

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
    return r2_utils.search_string_refs(binary_path, query, ignore_case, max_refs)

@mcp.tool()
async def emulate_function(binary_path: str, function_name: str, max_steps: int = 100, timeout: int = 60) -> Dict[str, Any]:
    """
    Performs a step-by-step emulation of a function using radare2's ESIL.

    Args:
        binary_path: The absolute path to the binary file.
        function_name: The name of the function to emulate.
        max_steps: The maximum number of instructions to emulate.
        timeout: The maximum time in seconds to allow for the emulation.

    Returns:
        A dictionary containing the emulation trace and final register states, or an error.
    """
    return r2_utils.emulate_function(binary_path, function_name, max_steps, timeout)

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
    # Run the server using stdio transport
    mcp.run(transport='stdio')
