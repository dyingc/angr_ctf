from langchain_core.tools import StructuredTool
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
import json
import sys, os
import subprocess
import yaml
import traceback
from io import StringIO
import contextlib
import concurrent.futures
from ai_agent.backends.dispatcher import call_backend
from ai_agent.libs import rz_utils as rzu
import rzpipe  # Add missing import

# Lazy load configuration
_config = None

def get_config():
    """Lazily load and return the configuration."""
    global _config
    if _config is None:
        config_path = os.path.join(os.path.dirname(__file__), "config.yaml")
        with open(config_path) as f:
            _config = yaml.safe_load(f)
    return _config

# Get the list of functions in a binary, using Rizin
# Excluding those built-in functions

class FunctionListToolInput(BaseModel):
    binary_path: str = Field(..., description="The path to the binary file.")
    exclude_builtins: bool = Field(True, description="Whether to exclude the system or C-library built-in functions, usually starts with \"sym.\".")

def get_function_list(binary_path:str, exclude_builtins:bool=True)->Dict[str, Any]:
    # Open the binary in Rizin
    rz = rzpipe.open(binary_path)

    # Perform analysis (equivalent to "aaa" command)
    rz.cmd("aaa")

    # Get function list (equivalent to "afl" command)
    functions = rz.cmd("aflj")  # JSON output

    # Parse JSON output
    if not functions or not isinstance(functions, str):
        return {"result": [],
                "need_refine": False,
                "prompts": []}

    func_list = json.loads(functions)
    # Filter out built-in functions if needed
    if exclude_builtins:
        func_list = [f for f in func_list if not f["name"].startswith("sym.imp.") and not f["name"].startswith("func.")]

    shortented_func_list = []
    for func in func_list:
        shortented_func = {
            "offset": func["offset"],
            "name": func["name"],
            "size": func.get("realsz", 0),
            "file": func.get("file", ""),
            "signature": func.get("signature", "")
        }
        # Use the helper function from rz_utils to get detailed function info including callers
        detailed_func = rzu._get_function_via_addr(rz, func["offset"])
        if detailed_func:
            shortented_func["called_by"] = detailed_func.get("called_by", [])
        else:
            shortented_func["called_by"] = []
        shortented_func_list.append(shortented_func)

    # Close the rzpipe session
    rz.quit()
    result = {"result": shortented_func_list,
              "need_refine": False,
              "prompts": []}
    return result

# Create the function_list_tool tool
function_list_tool = StructuredTool.from_function(
    get_function_list,
    name="get_function_list",
    description="Get the list of functions in a binary, using Rizin. Exclude built-in functions by default. Dependencies: Rizin installed and available in PATH.",
    args_schema=FunctionListToolInput,
)

# get_function_list(binary_path=file_name, exclude_builtins=True)

# Get disassembly of a specific function from a binary, using Rizin

class DisassemblyToolInput(BaseModel):
    binary_path: str = Field(..., description="The path to the binary file.")
    function_name: str = Field(..., description="The name of the function to disassemble.")

def get_disassembly(binary_path:str, function_name:str)->Dict[str, Any]:
    # Open the binary in Rizin
    rz = rzpipe.open(binary_path)

    # Perform analysis (equivalent to "aaa" command)
    rz.cmd("e scr.color=0; aaa")

    # Get disassembly of the function (equivalent to "pdf @ function_name" command)
    disassembly = rz.cmd(f"pdfj @ {function_name}")
    if not disassembly or not isinstance(disassembly, str):
        return {"result": "", "need_refine": False, "prompts": []}
    disassembly = json.loads(disassembly)

    # Close the rzpipe session
    rz.quit()

    ops = disassembly.get('ops', [])
    disa_str = '\n'.join([f"{d['offset']}\t{d['disasm']}" for d in ops])

    # Use corrected key name: get_assembly_messages
    config = get_config()
    return {"result": disa_str,
            "need_refine": False,
            "prompts": [
                    config["tool_messages"]["get_assembly_messages"]["system"],
                    config["tool_messages"]["get_assembly_messages"]["task"].format(original_assembly_code=disa_str)
                ]
        }

# Create the disassembly_tool tool
disassembly_tool = StructuredTool.from_function(
    get_disassembly,
    name="get_disassembly",
    description="Get disassembly of a specific function from a binary, using Rizin. Dependencies: Rizin installed and available in PATH.",
    args_schema=DisassemblyToolInput,
)

# get_disassembly(file_name, "dbg.main")


# Get the pseudo code of a specific function from a binary, using Rizin's Ghidra plugin
class PseudoCodeToolInput(BaseModel):
    binary_path: str = Field(..., description="The path to the binary file.")
    function_name: str = Field(..., description="The name of the function to get pseudo C code.")

def get_pseudo_code(binary_path:str, function_name:str)-> Dict[str, Any]: # Changed return type to Dict[str, Any]
    # Open the binary in Rizin
    rz = rzpipe.open(binary_path)

    # Perform analysis (equivalent to "aaa" command)
    rz.cmd("e scr.color=0; aaa")

    # Get pseudo code of the function (equivalent to "pdg @ function_name" command)
    pseudo_code = rz.cmd(f"pdgj @ {function_name}")
    if not pseudo_code or not isinstance(pseudo_code, str):
        return {
            "result": "",
            "need_refine": True,
            "prompts": [
                config["tool_messages"]["get_pseudo_code_messages"]["system"],
                config["tool_messages"]["get_pseudo_code_messages"]["task"].format(original_pseudo_code="")
            ]
        }
    pseudo_code = json.loads(pseudo_code)

    # Close the rzpipe session
    rz.quit()

    pcode_str = pseudo_code.get('code', '')

    config = get_config()
    return {
        "result": pcode_str,
        "need_refine": True,
        "prompts": [
            config["tool_messages"]["get_pseudo_code_messages"]["system"],
            config["tool_messages"]["get_pseudo_code_messages"]["task"].format(original_pseudo_code=pcode_str)
        ]}

# Create the pseudo_code_tool tool
pseudo_code_tool = StructuredTool.from_function(
    get_pseudo_code,
    name="get_pseudo_code",
    description="Get pseudo C code of a specific function from a binary, \nusing Rizin's Ghidra plugin. Dependencies: Rizin with Ghidra plugin installed.",
    args_schema=PseudoCodeToolInput,
)

# get_pseudo_code(file_name, "dbg.main")
class PythonInterpreterToolInput(BaseModel):
    code: str = Field(..., description="The Python code to execute.")
    timeout: int = Field(10, description="Maximum execution time in seconds before timeout.")

@contextlib.contextmanager
def capture_stdout():
    """Capture stdout and return it as a string."""
    stdout = StringIO()
    old_stdout = sys.stdout
    sys.stdout = stdout
    try:
        yield stdout
    finally:
        sys.stdout = old_stdout

def execute_code_with_timeout(code, local_vars, timeout):
    """Execute code with timeout using ThreadPoolExecutor."""
    def exec_target():
        exec(code, local_vars, local_vars)  # Use shared environment for both globals and locals

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(exec_target)
        try:
            future.result(timeout=timeout)
        except concurrent.futures.TimeoutError:
            raise TimeoutError(f"Execution timed out after {timeout} seconds")

def execute_python_code(code: str, timeout: int = 7_200) -> Dict[str, Any]:
    """
    Execute Python code passed as a string and return the output.

    Args:
        code: A string containing Python code to execute
        timeout: Maximum execution time in seconds before timing out

    Returns:
        The output of the executed code as a string
    """
    result_content = "" # Initialize result_content
    try:
        # Create a dictionary for local variables
        local_vars = {}
        hit_error = False

        # Capture stdout during execution
        with capture_stdout() as output:
            # Execute the code with timeout
            try:
                # Check for syntax errors before execution
                compile(code, '<string>', 'exec')

                # Execute with timeout using ThreadPoolExecutor
                execute_code_with_timeout(code, local_vars, timeout)

            except TimeoutError as e:
                hit_error = True
                result_content = f"{str(e)}\nThe given code is running too slowly. Please check the code and try again."
            except SyntaxError as e:
                hit_error = True
                # For syntax errors, we can get line and position information directly
                offset_str = str(e.offset) if e.offset is not None else "N/A"
                result_content =  f"SyntaxError while calling the given code: {str(e.msg)} (line {e.lineno}, position {offset_str})\n" + \
                       f"```\n{e.text}\n{' ' * (e.offset-1) if e.offset is not None else ''}^\n```\nPlease check the code and try again."
            except Exception as e:
                # Get the full traceback
                full_tb = traceback.format_exc()

                # Extract just the relevant parts (error type, message, and code context)
                tb_lines = full_tb.split('\n')
                cleaned_tb = []

                # Find where the "<string>" part starts (the executed code)
                for i, line in enumerate(tb_lines):
                    if '<string>' in line:
                        # Add this line and all subsequent lines
                        cleaned_tb = tb_lines[i:]
                        break

                # If we couldn't find the specific part, use the last few lines which typically
                # contain the exception type and message
                if not cleaned_tb and len(tb_lines) >= 3:
                    cleaned_tb = tb_lines[-3:]

                hit_error = True
                result_content = f"Error during execution:\n" + '\n'.join(cleaned_tb) + "\nPlease check the code and try again."

        if not hit_error:
            # Get captured output
            result = output.getvalue()

            # If there's no stdout but there are return values in local variables,
            # add them to the result
            if not result.strip() and local_vars:
                # Find potential result variables
                potential_results = [var for var in local_vars if not var.startswith('_')]
                if potential_results:
                    result += "\nLocal variables after execution:\n"
                    for var in potential_results:
                        result += f"{var}: {repr(local_vars[var])}\n"

            result_content = result.strip() if result.strip() else "Code executed successfully with no output."

    except Exception as e:
        result_content = f"Error setting up execution environment: {str(e)}"

    final_result = {
        "result": result_content,
        "need_refine": False,
        "prompts": []
    }
    return final_result


# Create the python_interpreter_tool
python_interpreter_tool = StructuredTool.from_function(
    execute_python_code,
    name="execute_python_code",
    description="Execute Python code passed as a string and return the output.",
    args_schema=PythonInterpreterToolInput,
)

# --- New Tools based on r2_utils ---

# get_call_graph
class CallGraphToolInput(BaseModel):
    binary_path: str = Field(..., description="The path to the binary file.")
    function_name: Optional[str] = Field(None, description="The name of the function to generate the call graph for. If None, a global call graph is generated.")

def _get_call_graph_tool_impl(tool_input: CallGraphToolInput) -> Dict[str, Any]:
    result = call_backend('get_call_graph', tool_input.binary_path, tool_input.function_name)
    return {"result": result, "need_refine": False, "prompts": []}

call_graph_tool = StructuredTool.from_function(
    _get_call_graph_tool_impl,
    name="get_call_graph",
    description="Generates a call graph for a binary using Rizin. Can be global or for a specific function with depth.",
    args_schema=CallGraphToolInput,
)

# get_cfg_basic_blocks
class CFGBasicBlocksToolInput(BaseModel):
    binary_path: str = Field(..., description="The path to the binary file.")
    function_name: str = Field(..., description="The name of the function to get basic blocks for.")

def _get_cfg_basic_blocks_tool_impl(tool_input: CFGBasicBlocksToolInput) -> Dict[str, Any]:
    result = call_backend('get_cfg_basic_blocks', tool_input.binary_path, tool_input.function_name)
    return {"result": result, "need_refine": False, "prompts": []}

cfg_basic_blocks_tool = StructuredTool.from_function(
    _get_cfg_basic_blocks_tool_impl,
    name="get_cfg_basic_blocks",
    description="Retrieves basic blocks information for a given function, including boundaries and control flow information.",
    args_schema=CFGBasicBlocksToolInput,
)

# get_strings
class GetStringsToolInput(BaseModel):
    binary_path: str = Field(..., description="The path to the binary file.")
    min_length: int = Field(4, description="Minimum length of strings to extract.")

def _get_strings_tool_impl(tool_input: GetStringsToolInput) -> Dict[str, Any]:
    result = call_backend('get_strings', tool_input.binary_path, tool_input.min_length)
    return {"result": result, "need_refine": False, "prompts": []}

get_strings_tool = StructuredTool.from_function(
    _get_strings_tool_impl,
    name="get_strings",
    description="Extracts printable strings from a binary using Rizin.",
    args_schema=GetStringsToolInput,
)

# search_string_refs
class SearchStringRefsToolInput(BaseModel):
    binary_path: str = Field(..., description="The path to the binary file.")
    query: str = Field(..., description="The substring or regex to search for.")
    ignore_case: bool = Field(True, description="Whether to ignore case during search.")
    max_refs: int = Field(50, description="Maximum number of references to return per string.")

def _search_string_refs_tool_impl(tool_input: SearchStringRefsToolInput) -> Dict[str, Any]:
    result = call_backend('search_string_refs', tool_input.binary_path, tool_input.query, tool_input.ignore_case, tool_input.max_refs)
    return {"result": result, "need_refine": False, "prompts": []}

search_string_refs_tool = StructuredTool.from_function(
    _search_string_refs_tool_impl,
    name="search_string_refs",
    description="Searches for string references in a binary based on a query (substring or regex) using Rizin.",
    args_schema=SearchStringRefsToolInput,
)

# emulate_function
class EmulateFunctionToolInput(BaseModel):
    binary_path: str = Field(..., description="The path to the binary file.")
    function_name: str = Field(..., description="The name of the function to emulate.")
    max_steps: int = Field(100, description="Maximum number of emulation steps.")
    timeout: int = Field(60, description="Maximum execution time in seconds before timeout.")

def _emulate_function_tool_impl(tool_input: EmulateFunctionToolInput) -> Dict[str, Any]:
    result = call_backend('emulate_function', tool_input.binary_path, tool_input.function_name, max_steps=tool_input.max_steps, timeout=tool_input.timeout)
    return {"result": result, "need_refine": False, "prompts": []}

emulate_function_tool = StructuredTool.from_function(
    _emulate_function_tool_impl,
    name="emulate_function",
    description="Emulates a function for a specified number of steps and returns register states and trace using Rizin's ESIL.",
    args_schema=EmulateFunctionToolInput,
)

# Define the input schema for the execute_os_command tool
class ExecuteOSCommandToolInput(BaseModel):
    command: str = Field(..., description="The OS command to execute. For example \"ls -l /tmp\".")
    timeout: int = Field(60, description="Maximum execution time in seconds before timeout.")

def execute_os_command(command: str, timeout: int = 60) -> Dict[str, Any]:
    """
    Execute an OS command and return the output.

    Args:
        command: The OS command to execute.
        timeout: Maximum execution time in seconds before timeout.

    Returns:
        A dictionary containing the command output, error (if any), and execution status.
    """
    try:
        # Execute the command with a timeout
        result = subprocess.run(
            command,
            shell=True,
            timeout=timeout,
            capture_output=True,
            text=True
        )

        # Prepare the result dictionary
        output = {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
            "success": result.returncode == 0
        }

        return {
            "result": output,
            "need_refine": False,
            "prompts": []
        }

    except subprocess.TimeoutExpired:
        return {
            "result": {
                "stdout": "",
                "stderr": "Command timed out",
                "returncode": -1,
                "success": False
            },
            "need_refine": False,
            "prompts": []
        }
    except Exception as e:
        return {
            "result": {
                "stdout": "",
                "stderr": str(e),
                "returncode": -1,
                "success": False
            },
            "need_refine": False,
            "prompts": []
        }

# Create the execute_os_command_tool tool
execute_os_command_tool = StructuredTool.from_function(
    execute_os_command,
    name="execute_os_command",
    description="Execute an OS command and return the output. This can be used for anything from preparing the environment, installing missing dependencies, verifying file existence, to running scripts or binaries, etc.",
    args_schema=ExecuteOSCommandToolInput,
)

class InternalInferenceToolInput(BaseModel):
    known_facts: List[str] = Field(..., description="List of known facts or information already available.")
    reasoning_method: str = Field(..., description="Type of reasoning applied, e.g., deduction, induction, etc.")
    arguments: List[str] = Field(..., description="The lines of reasoning or arguments constructed from the known facts.")
    inferred_insights: List[str] = Field(..., description="The final insights, answer, or results derived.")
    validation_check: Optional[str] = Field(None, description="Internal validation or consistency check explanation.")

    def get_inference_repr(self) -> str:
        text = f"Known Facts:\n"
        for fact in self.known_facts:
            text += f"- {fact}\n"
        text += f"Reasoning Method: {self.reasoning_method}\n"
        text += f"Arguments:\n"
        for arg in self.arguments:
            text += f"- {arg}\n"
        text += f"Conclusion:\n"
        for insight in self.inferred_insights:
            text += f"- {insight}\n"
        if self.validation_check:
            text += f"Validation Check: {self.validation_check}\n"
        return text

def do_internal_inference(
    known_facts: List[str],
    reasoning_method: str,
    arguments: List[str],
    inferred_insights: Optional[List[str]] = None,
    validation_check: Optional[str] = None,
) -> InternalInferenceToolInput:
    return InternalInferenceToolInput(
        known_facts=known_facts,
        reasoning_method=reasoning_method,
        arguments=arguments,
        inferred_insights=inferred_insights or [],
        validation_check=validation_check,
    )

internal_inference_tool = StructuredTool.from_function(
    func=do_internal_inference,
    name="do_internal_inference",
    description="Use this tool to perform internal reasoning and inference based only on existing known facts and logical methods.",
    args_schema=InternalInferenceToolInput,
)
