"""
Call graph generation utilities.

Provides functions to generate call graphs for binaries using Rizin.
"""

from typing import Dict, Any, List, Optional

def get_call_graph(binary_path: str, function_name: Optional[str] = None, depth:int = 3) -> Dict[str, Any]:
    """
    Generates a call graph for a binary.

    Args:
        binary_path: The path to the binary file.
        function_name: Optional. The name of the function to generate the call graph for.
        depth: Optional. The depth of the call graph to generate. Default is 3.

    Returns:
        A dictionary containing the call graph nodes and edges.
    """
    from ai_agent.backends.dispatcher import call as _call_backend
    result = _call_backend("get_call_graph", binary_path, function_name)
    return {"result": result, "need_refine": False, "prompts": []}
