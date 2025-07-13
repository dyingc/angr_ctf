# `r2_utils` Library Documentation

This document describes the functions available in the `r2_utils.py` library, which provides Python wrappers around `radare2` for binary analysis.

---

### 1. `get_call_graph`

**Purpose:**
Generates a call graph for a binary. It can create a global graph for the entire binary or a localized graph starting from a specific function up to a certain depth.

**Parameters:**
- `binary_path` (str): The absolute path to the binary file.
- `function_name` (Optional[str]): The name of the function to generate the call graph for. If `None`, a global call graph is generated. Defaults to `None`.
- `depth` (int): The depth of the call graph to generate when `function_name` is specified. Defaults to `3`.

**Returns:**
- `Dict[str, Any]`: A dictionary with two keys:
    - `"nodes"`: A list of dictionaries, where each node has a `"name"` and `"addr"`.
    - `"edges"`: A list of tuples, where each tuple represents a directed edge `(from_address, to_address)`.

**Example Usage:**
```python
from ai_agent import r2_utils

# Get global call graph
global_graph = r2_utils.get_call_graph("/path/to/your/binary")
print(global_graph["nodes"])

# Get call graph for the 'main' function with a depth of 5
main_graph = r2_utils.get_call_graph("/path/to/your/binary", function_name="main", depth=5)
print(main_graph["edges"])
```

---

### 2. `get_cfg_basic_blocks`

**Purpose:**
Retrieves the basic blocks of a function's Control Flow Graph (CFG), including their boundaries and successor information.

**Parameters:**
- `binary_path` (str): The absolute path to the binary file.
- `function_name` (str): The name of the function to analyze.

**Returns:**
- `List[Dict[str, Any]]`: A list of dictionaries, where each dictionary represents a basic block and contains:
    - `"offset"` (int): The starting address of the block.
    - `"size"` (int): The size of the block in bytes.
    - `"type"` (str): The type of the block (e.g., "entry", "cond", "uncond").
    - `"succ"` (List[int]): A list of addresses of the successor blocks.

**Example Usage:**
```python
from ai_agent import r2_utils

blocks = r2_utils.get_cfg_basic_blocks("/path/to/your/binary", function_name="main")
for block in blocks:
    print(f"Block at {hex(block['offset'])} has successors: {[hex(s) for s in block['succ']]}")
```

---

### 3. `get_strings`

**Purpose:**
Extracts all printable strings from a binary file that meet a minimum length requirement.

**Parameters:**
- `binary_path` (str): The absolute path to the binary file.
- `min_length` (int): The minimum character length of the strings to extract. Defaults to `4`.

**Returns:**
- `List[Dict[str, Any]]`: A list of dictionaries, where each dictionary represents a string and contains its `"vaddr"`, `"paddr"`, `"string"`, `"section"`, and `"length"`.

**Example Usage:**
```python
from ai_agent import r2_utils

strings = r2_utils.get_strings("/path/to/your/binary", min_length=8)
for s in strings:
    print(f"Found string: '{s['string']}' at address {hex(s['vaddr'])}")
```

---

### 4. `search_string_refs`

**Purpose:**
Finds all references in the code to strings that match a given query (substring or regex).

**Parameters:**
- `binary_path` (str): The absolute path to the binary file.
- `query` (str): The substring or regular expression to search for.
- `ignore_case` (bool): If `True`, the search is case-insensitive. Defaults to `True`.
- `max_refs` (int): The maximum number of references to return for each matched string. Defaults to `50`.

**Returns:**
- `List[Dict[str, Any]]`: A list of dictionaries for each matched string, containing:
    - `"string"` (str): The matched string.
    - `"str_addr"` (str): The hexadecimal address of the string.
    - `"refs"` (List[Dict]): A list of references, where each reference includes the function name (`"fcn"`), the reference address (`"offset"`), and the disassembly (`"disasm"`).

**Example Usage:**
```python
from ai_agent import r2_utils

# Find references to any string containing "password"
refs = r2_utils.search_string_refs("/path/to/your/binary", query="password")
for ref_info in refs:
    print(f"String '{ref_info['string']}' is referenced at:")
    for r in ref_info['refs']:
        print(f"  - {r['fcn']} + {hex(r['offset'])}")
```

---

### 5. `emulate_function`

**Purpose:**
Performs a step-by-step emulation of a function using radare2's ESIL (Evaluable String Intermediate Language) and captures the state at each step. The emulation runs in a separate thread to enforce a timeout.

**Parameters:**
- `binary_path` (str): The absolute path to the binary file.
- `function_name` (str): The name of the function to emulate.
- `max_steps` (int): The maximum number of instructions to emulate. Defaults to `100`.
- `timeout` (int): The maximum time in seconds to allow for the emulation. Defaults to `60`.

**Returns:**
- `Dict[str, Any]`: A dictionary containing either the emulation results or an error:
    - On success: `{"final_regs": {...}, "trace": [...]}`
    - On failure/timeout: `{"error": "..."}`
    The `"trace"` is a list of dictionaries, each capturing the `"pc"`, `"op"` (disassembly), and `"regs"` for one step.

**Example Usage:**
```python
from ai_agent import r2_utils

result = r2_utils.emulate_function("/path/to/your/binary", function_name="calculate_key", max_steps=50)
if "error" in result:
    print(f"Emulation failed: {result['error']}")
else:
    print("Emulation trace:")
    for step in result['trace']:
        print(f"PC: {step['pc']}, OP: {step['op']}")
    print("\nFinal Registers:")
    print(result['final_regs'])
```
