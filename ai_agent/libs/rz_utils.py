import warnings
from ai_agent.core import call_graph, cfg, strings, emulation

# Deprecated imports from rz_utils
def get_call_graph(*args, **kwargs):
    warnings.warn("ai_agent.libs.rz_utils.get_call_graph is deprecated. Use ai_agent.core.call_graph.get_call_graph instead.", DeprecationWarning, stacklevel=2)
    return call_graph.get_call_graph(*args, **kwargs)

def get_cfg_basic_blocks(*args, **kwargs):
    warnings.warn("ai_agent.libs.rz_utils.get_cfg_basic_blocks is deprecated. Use ai_agent.core.cfg.get_cfg_basic_blocks instead.", DeprecationWarning, stacklevel=2)
    return cfg.get_cfg_basic_blocks(*args, **kwargs)

def get_strings(*args, **kwargs):
    warnings.warn("ai_agent.libs.rz_utils.get_strings is deprecated. Use ai_agent.core.strings.get_strings instead.", DeprecationWarning, stacklevel=2)
    return strings.get_strings(*args, **kwargs)

def search_string_refs(*args, **kwargs):
    warnings.warn("ai_agent.libs.rz_utils.search_string_refs is deprecated. Use ai_agent.core.strings.search_string_refs instead.", DeprecationWarning, stacklevel=2)
    return strings.search_string_refs(*args, **kwargs)

# Deprecated import from rz_emulator (if it was here)
# def emulate_function(*args, **kwargs):
#     warnings.warn("ai_agent.libs.rz_utils.emulate_function is deprecated. Use ai_agent.core.emulation.emulate_function instead.", DeprecationWarning, stacklevel=2)
#     return emulation.emulate_function(*args, **kwargs)

# Remove the __main__ block as this file is now a library
if __name__ == "__main__":
    print("This module is now a library and should not be run directly.")
    print("Please use the functions from ai_agent.core or ai_agent.reverse_engineering.")
