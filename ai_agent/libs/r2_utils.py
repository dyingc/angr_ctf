"""
This module provides a set of utility functions for binary analysis using the radare2
framework via the r2pipe library.

It includes functionalities for generating call graphs, retrieving CFG basic blocks,
extracting strings and their references, and emulating functions using ESIL.
All operations are designed to be thread-safe.
"""
import r2pipe
import json
from typing import Dict, Any, List, Optional
import re
import concurrent.futures
import threading
import queue

# Global lock for r2pipe operations to prevent race conditions
r2_lock = threading.Lock()

def _open_r2pipe(binary_path: str) -> r2pipe.open:
    """
    Opens an r2pipe instance for a given binary and performs initial analysis.

    Args:
        binary_path: The path to the binary file.

    Returns:
        An initialized r2pipe instance after running 'aaa' analysis and disabling color.
    """
    r2 = r2pipe.open(binary_path)
    r2.cmd("e scr.color=0; aaa")  # Disable color, perform auto-analysis
    return r2

def get_call_graph(binary_path: str, function_name: Optional[str] = None) -> Dict[str, Any]:
    """
    Generates a call graph for a binary.

    If a function_name is provided, it generates a localized call graph
    for that function. Otherwise, it generates a global call graph
    for the entire binary.

    Args:
        binary_path: The path to the binary file.
        function_name: Optional. The name of the function to start the graph from.

    Returns:
        A dictionary containing 'nodes' and 'edges' of the call graph.
        Nodes are dicts with 'name' and 'addr'. Edges are tuples of (from_addr, to_addr).
    """
    with r2_lock:
        r2 = _open_r2pipe(binary_path)
        try:
            if function_name:
                # Get call graph for a specific function, JSON output
                graph_json = r2.cmdj(f"agcj @ {function_name}")
            else:
                # Get global call graph, JSON output
                graph_json = r2.cmdj("agCj")

            if not graph_json:
                return {"nodes": [], "edges": []}

            graph_data = json.loads(graph_json)
            nodes = []
            edges = []

            # For agfj, it's a list of nodes with 'name', 'addr', 'imports', 'exports'
            # For agCdj, it's a single object with 'nodes' and 'edges'
            if function_name:
                if graph_data and isinstance(graph_data, dict):
                    nodes = [{"name": n["name"], "addr": n["addr"]} for n in graph_data.get("nodes", [])]
                    edges = [(e["from"], e["to"]) for e in graph_data.get("edges", [])]
            else:
                # Process global call graph (agfj)
                for node in graph_data:
                    nodes.append({"name": node["name"], "addr": node["addr"]})
                    # agfj doesn't directly give edges in a simple list, need to infer from imports/exports
                    # This part might need refinement based on exact agfj output structure for edges
                    # For simplicity, we'll just list nodes for now, or use a different r2 command if needed for edges
                    # A more robust approach for global graph might involve parsing 'agf' and then 'axf' for calls

            return {"nodes": nodes, "edges": edges}
        finally:
            r2.quit()

def _determine_block_type(block: Dict[str, Any]) -> str:
    """
    Determines the type of a basic block based on its jump/fail fields.

    Args:
        block: Basic block data from afbj command

    Returns:
        String representing block type: "entry", "cond", "uncond", "ret", "call"
    """
    inputs = block.get("inputs", 0)
    has_jump = "jump" in block and block["jump"]
    has_fail = "fail" in block and block["fail"]

    # Entry block: no inputs
    if inputs == 0:
        return "entry"

    # Conditional jump: has both jump and fail targets
    if has_jump and has_fail:
        return "cond"

    # Unconditional jump: has only jump target
    if has_jump and not has_fail:
        return "uncond"

    # Return block: no jump or fail targets
    if not has_jump and not has_fail:
        return "ret"

    # Call block: typically has fail target (fall-through)
    if has_fail and not has_jump:
        return "call"

    return "unknown"


def get_cfg_basic_blocks(binary_path: str, function_name: str) -> List[Dict[str, Any]]:
    """
    Retrieves Control Flow Graph (CFG) basic blocks for a given function.

    Args:
        binary_path: The path to the binary file.
        function_name: The name of the function to analyze.

    Returns:
        A list of dictionaries, where each dictionary represents a basic block
        and contains its 'offset', 'size', 'type', and a list of successor
        offsets in 'succ'.
    """
    with r2_lock:
        r2 = _open_r2pipe(binary_path)
        try:
            # Verify function exists
            functions = r2.cmdj("aflj")
            if not functions or not any(f.get("name") == function_name for f in functions):
                raise ValueError(f"Function '{function_name}' not found in binary")

            # Get basic block information
            blocks_json = r2.cmd(f"afbj @ {function_name}")
            if not blocks_json or blocks_json.strip() == "[]":
                return []
            blocks_data = json.loads(blocks_json)

            edges_data = r2.cmdj(f"agj @ {function_name}")

            # Map block addresses to their data for easier lookup
            block_map = {b["addr"]: b for b in blocks_data}

            for block in blocks_data:
                # Determine block type based on jump/fail fields
                block_type = _determine_block_type(block)

                # Extract successors from jump/fail fields
                successors = []
                if "jump" in block and block["jump"]:
                    successors.append(block["jump"])
                if "fail" in block and block["fail"]:
                    successors.append(block["fail"])

                formatted_block = {
                    "offset": block["addr"],
                    "size": block["size"],
                    "type": block_type,
                    "succ": successors,
                    "inputs": block.get("inputs", 0),
                    "outputs": block.get("outputs", 0),
                    "ninstr": block.get("ninstr", 0)
                }
                formatted_blocks.append(formatted_block)

            return formatted_blocks

        except Exception as e:
            raise RuntimeError(f"Error analyzing function '{function_name}': {e}")
        finally:
            r2.quit()


def analyze_function_cfg(binary_path: str, function_name: str) -> Dict[str, Any]:
    """
    Comprehensive CFG analysis for a function.

    Args:
        binary_path: Path to binary file
        function_name: Function name to analyze

    Returns:
        Dictionary containing CFG analysis results
    """
    blocks = get_cfg_basic_blocks(binary_path, function_name)

    if not blocks:
        return {"blocks": [], "stats": {}}

    # Calculate CFG statistics
    total_blocks = len(blocks)
    total_instructions = sum(b["ninstr"] for b in blocks)
    total_size = sum(b["size"] for b in blocks)

    # Find entry and exit blocks
    entry_blocks = [b for b in blocks if b["type"] == "entry"]
    exit_blocks = [b for b in blocks if b["type"] == "ret"]

    # Calculate complexity metrics
    edges = sum(len(b["succ"]) for b in blocks)
    cyclomatic_complexity = edges - total_blocks + 2

    stats = {
        "total_blocks": total_blocks,
        "total_instructions": total_instructions,
        "total_size": total_size,
        "entry_blocks": len(entry_blocks),
        "exit_blocks": len(exit_blocks),
        "edges": edges,
        "cyclomatic_complexity": cyclomatic_complexity,
        "avg_block_size": total_size / total_blocks if total_blocks > 0 else 0
    }

    return {
        "blocks": blocks,
        "stats": stats,
        "entry_points": [b["offset"] for b in entry_blocks],
        "exit_points": [b["offset"] for b in exit_blocks]
    }

def get_strings(binary_path: str, min_length: int = 4) -> List[Dict[str, Any]]:
    """
    Extracts printable strings from a binary.

    Args:
        binary_path: The path to the binary file.
        min_length: The minimum length of strings to be extracted.

    Returns:
        A list of dictionaries, each representing a string and containing its
        'vaddr', 'paddr', 'string', 'section', and 'length'.
    """
    with r2_lock:
        r2 = _open_r2pipe(binary_path)
        try:
            # izj: info strings, JSON output
            strings_json = r2.cmd("izj")
            if not strings_json:
                return []
            strings_data = json.loads(strings_json)

            return [
                s for s in strings_data if s.get("length", 0) >= min_length
            ]
        finally:
            r2.quit()

def search_string_refs(binary_path: str, query: str, ignore_case: bool = True, max_refs: int = 50) -> List[Dict[str, Any]]:
    """
    Searches for references to strings that match a given query.

    Args:
        binary_path: The path to the binary file.
        query: The substring or regex pattern to search for within the strings.
        ignore_case: If True, performs a case-insensitive search.
        max_refs: The maximum number of references to return per matched string.

    Returns:
        A list of dictionaries, where each dictionary contains the matched 'string',
        its 'str_addr', and a list of 'refs' pointing to it. Each reference
        includes the function name ('fcn'), 'offset', and 'disasm' of the instruction.
    """
    all_strings = get_strings(binary_path)

    regex_flags = re.IGNORECASE if ignore_case else 0
    matched_strings = [
        s for s in all_strings if re.search(query, s.get("string", ""), regex_flags)
    ]

    results = []
    with r2_lock:
        r2 = _open_r2pipe(binary_path)
        try:
            for s in matched_strings:
                str_addr = s.get("vaddr")
                if str_addr is None:
                    continue

                # axtj: xrefs to address, JSON output
                refs_json = r2.cmd(f"axtj @ {str_addr}")
                refs_data = json.loads(refs_json) if refs_json else []

                formatted_refs = [
                    {
                        "fcn": ref.get("fcn_name"),
                        "offset": ref.get("from"),
                        "disasm": ref.get("opcode") # This might be the instruction that references it
                    } for ref in refs_data[:max_refs]
                ]

                results.append({
                    "string": s.get("string"),
                    "str_addr": hex(str_addr),
                    "refs": formatted_refs
                })
            return results
        finally:
            r2.quit()

def _emulate_function_target(r2_instance, function_name, max_steps, result_queue):
    """
    Target function for threaded ESIL emulation to allow for timeouts.

    This function is intended to be run in a separate thread. It initializes
    ESIL, steps through the function's instructions, and records the trace.
    It reports the status of the emulation: 'completed', 'max_steps_reached', or 'error'.

    Args:
        r2_instance: An active r2pipe instance.
        function_name: The name of the function to emulate.
        max_steps: The maximum number of instructions to emulate.
        result_queue: A queue to store the final result or error.
    """
    try:
        r2_instance.cmd(f"aeim @ {function_name}") # Initialize ESIL emulation at function entry
        trace = []
        emulation_status = "max_steps_reached"  # Default status if loop finishes naturally

        for step in range(max_steps):
            # Get current register state (aerj: ESIL registers, JSON output)
            regs_json = r2_instance.cmd("aerj")
            current_regs = json.loads(regs_json) if regs_json else {}

            # Get current instruction (pdj 1 @ PC)
            # The program counter register name is architecture-dependent.
            # We check in order of specificity: rip (x64), eip (x86), then pc (generic).
            current_pc = current_regs.get("rip") or current_regs.get("eip") or current_regs.get("pc")
            if current_pc is None:
                # If no program counter is found, emulation cannot continue. This is a critical error.
                result_queue.put({"error": "Emulation failed: Program Counter (PC) could not be determined."})
                return

            disasm_json = r2_instance.cmd(f"pdj 1 @ {current_pc}")
            current_op = json.loads(disasm_json)[0] if disasm_json and disasm_json.strip().startswith('[') else {}

            trace.append({
                "step": step,
                "pc": hex(current_pc),
                "op": current_op.get("disasm"),
                "regs": current_regs
            })

            # Execute one ESIL instruction (aei: ESIL step)
            r2_instance.cmd("aei")

            # Check if emulation finished (e.g., hit ret or invalid instruction)
            # This is a heuristic, a more robust check might involve analyzing ESIL flags or state
            if r2_instance.cmd("aerj").strip() == "{}": # If registers are empty, emulation might have stopped
                emulation_status = "completed"
                break

        final_regs_json = r2_instance.cmd("aerj")
        final_regs = json.loads(final_regs_json) if final_regs_json else {}
        result_queue.put({
            "status": emulation_status,
            "final_regs": final_regs,
            "trace": trace
        })
    except Exception as e:
        result_queue.put({"error": str(e)})

def emulate_function(binary_path: str, function_name: str, max_steps: int = 100, timeout: int = 60) -> Dict[str, Any]:
    """
    Emulates a function using ESIL for a number of steps and returns the trace.

    This function uses a separate thread to run the emulation, allowing for a
    timeout to prevent hangs on complex or infinite loops.

    Args:
        binary_path: The path to the binary file.
        function_name: The name of the function to emulate.
        max_steps: The maximum number of instructions to emulate.
        timeout: The maximum time in seconds to wait for the emulation to complete.

    Returns:
        A dictionary containing the 'status', 'final_regs', and instruction 'trace',
        or an 'error' message if the emulation failed or timed out.
    """
    with r2_lock: # Acquire lock before opening r2pipe
        r2 = _open_r2pipe(binary_path)
        result_queue = queue.Queue()
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        future = executor.submit(_emulate_function_target, r2, function_name, max_steps, result_queue)

        try:
<<<<<<< HEAD:ai_agent/r2_utils.py
            # Block until the result is available or timeout occurs.
            return result_queue.get(timeout=timeout)
        except queue.Empty:
            # This is the primary expected exception: the emulation took too long.
            return {"error": f"Emulation timed out after {timeout} seconds."}
=======
            result = result_queue.get(timeout=timeout)
            if "error" in result:
                return {"success": False, "error": result["error"]}
            return result
        except queue.Empty:
            return {"success": False, "error": f"Emulation timed out after {timeout} seconds."}
        except Exception as e:
            return {"success": False, "error": f"An unexpected error occurred: {str(e)}"}
>>>>>>> 34e06c358b4c0752dcc59c44a86c6f018d550603:ai_agent/libs/r2_utils.py
        finally:
            # Ensure the thread and r2pipe are cleaned up regardless of outcome.
            future.cancel()
            executor.shutdown(wait=False)
            r2.quit()
