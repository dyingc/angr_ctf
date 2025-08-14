import sys
import os

# Add the project root to the Python path to resolve module imports
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from ai_agent.reverse_engineering import get_function_list, get_disassembly, get_pseudo_code

BINARY_PATH = "./crackme100" # Assuming crackme100 is in the current directory

def test_function_list():
    print("--- Testing get_function_list ---")
    try:
        result = get_function_list(BINARY_PATH)
        if result and result.get("result"):
            print(f"Successfully retrieved {len(result['result'])} functions.")
            for func in result['result'][:5]: # Print first 5 functions
                print(f"  - {func['name']} at {hex(func['offset'])}")
        else:
            print("get_function_list returned no functions or an empty result.")
    except Exception as e:
        print(f"Error testing get_function_list: {e}")

def test_disassembly():
    print("\n--- Testing get_disassembly ---")
    # Assuming 'main' function exists in crackme100
    function_name = "main"
    try:
        result = get_disassembly(BINARY_PATH, function_name)
        if result and result.get("result"):
            print(f"Successfully retrieved disassembly for '{function_name}'.")
            print(result['result'][:500]) # Print first 500 chars
        else:
            print(f"get_disassembly returned no disassembly for '{function_name}'.")
    except Exception as e:
        print(f"Error testing get_disassembly for '{function_name}': {e}")

def test_pseudo_code():
    print("\n--- Testing get_pseudo_code ---")
    # Assuming 'main' function exists in crackme100
    function_name = "main"
    try:
        result = get_pseudo_code(BINARY_PATH, function_name)
        if result and result.get("result"):
            print(f"Successfully retrieved pseudo code for '{function_name}'.")
            print(result['result'][:500]) # Print first 500 chars
        else:
            print(f"get_pseudo_code returned no pseudo code for '{function_name}'.")
    except Exception as e:
        print(f"Error testing get_pseudo_code for '{function_name}': {e}")

if __name__ == "__main__":
    if not os.path.exists(BINARY_PATH):
        print(f"Error: Binary '{BINARY_PATH}' not found. Please ensure it's in the current directory.")
        sys.exit(1)

    test_function_list()
    test_disassembly()
    test_pseudo_code()
