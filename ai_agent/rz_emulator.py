import warnings
from ai_agent.core import emulation

# Deprecated import from rz_emulator
def emulate_function_async(*args, **kwargs):
    warnings.warn("ai_agent.rz_emulator.emulate_function_async is deprecated. Use ai_agent.core.emulation.emulate_function instead.", DeprecationWarning, stacklevel=2)
    return emulation.emulate_function(*args, **kwargs)

if __name__ == "__main__":
    print("This module is now a library and should not be run directly.")
    print("Please use the functions from ai_agent.core.emulation or ai_agent.reverse_engineering.")
