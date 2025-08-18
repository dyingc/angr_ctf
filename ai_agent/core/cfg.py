"""
Control-flow graph (CFG) utilities.

Provides functions to retrieve basic blocks and CFG information for functions.
"""

from typing import Dict, Any, List


def get_cfg_basic_blocks(binary_path: str, function_name: str) -> Dict[str, Any]:
    """
    Retrieves the basic blocks of a function's Control Flow Graph (CFG).

    Args:
        binary_path: The path to the binary file.
        function_name: The name of the function to analyze.

    Returns:
        A list of dictionaries, each representing a basic block.
    """
    from ai_agent.backends.dispatcher import call as _call_backend
    result = _call_backend("get_cfg_basic_blocks", binary_path, function_name)
    return {"result": result, "need_refine": False, "prompts": []}
