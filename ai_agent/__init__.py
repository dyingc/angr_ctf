import warnings
from .core import call_graph, cfg, strings, emulation

# Deprecated imports from rz_utils
def get_call_graph(*args, **kwargs):
    warnings.warn("ai_agent.get_call_graph is deprecated. Use ai_agent.core.call_graph.get_call_graph instead.", DeprecationWarning, stacklevel=2)
    return call_graph.get_call_graph(*args, **kwargs)

def get_cfg_basic_blocks(*args, **kwargs):
    warnings.warn("ai_agent.get_cfg_basic_blocks is deprecated. Use ai_agent.core.cfg.get_cfg_basic_blocks instead.", DeprecationWarning, stacklevel=2)
    return cfg.get_cfg_basic_blocks(*args, **kwargs)

def get_strings(*args, **kwargs):
    warnings.warn("ai_agent.get_strings is deprecated. Use ai_agent.core.strings.get_strings instead.", DeprecationWarning, stacklevel=2)
    return strings.get_strings(*args, **kwargs)

def search_string_refs(*args, **kwargs):
    warnings.warn("ai_agent.search_string_refs is deprecated. Use ai_agent.core.strings.search_string_refs instead.", DeprecationWarning, stacklevel=2)
    return strings.search_string_refs(*args, **kwargs)

# Deprecated import from rz_emulator
def emulate_function(*args, **kwargs):
    warnings.warn("ai_agent.emulate_function is deprecated. Use ai_agent.core.emulation.emulate_function instead.", DeprecationWarning, stacklevel=2)
    return emulation.emulate_function(*args, **kwargs)

__all__ = [
    "get_call_graph",
    "get_cfg_basic_blocks",
    "get_strings",
    "search_string_refs",
    "emulate_function",
    "call_graph",
    "cfg",
    "strings",
    "emulation",
]
