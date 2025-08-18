"""
String extraction and reference utilities.

Provides functions to extract strings from binaries and find references to them.
"""

from typing import Dict, Any, List
import re


def get_strings(binary_path: str, min_length: int = 4) -> Dict[str, Any]:
    """
    Extracts printable strings from a binary file.

    Args:
        binary_path: The path to the binary file.
        min_length: The minimum length of strings to extract.

    Returns:
        A dictionary containing the list of found strings.
    """
    from ai_agent.backends.dispatcher import call as _call_backend
    result = _call_backend("get_strings", binary_path, min_length)
    return {"result": result, "need_refine": False, "prompts": []}


def search_string_refs(
    binary_path: str,
    query: str,
    ignore_case: bool = True,
    max_refs: int = 50
) -> Dict[str, Any]:
    """
    Finds all references in the code to strings matching a given query.

    Args:
        binary_path: The path to the binary file.
        query: The substring or regular expression to search for.
        ignore_case: If True, the search is case-insensitive.
        max_refs: The maximum number of references to return per string.

    Returns:
        A dictionary containing the list of matched strings and their references.
    """
    from ai_agent.backends.dispatcher import call as _call_backend
    result = _call_backend("search_string_refs", binary_path, query, ignore_case, max_refs)
    return {"result": result, "need_refine": False, "prompts": []}
