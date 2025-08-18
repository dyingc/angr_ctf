"""
Core reverse-engineering utilities.

This package provides a clean, backend-agnostic interface for common
binary-analysis tasks.  All functions delegate to the appropriate backend
via ai_agent.backends.dispatcher.
"""

__all__ = [
    "call_graph",
    "cfg",
    "strings",
    "emulation",
]
