"""
This module provides a set of utility functions for binary analysis using the Rizin
framework via the rzpipe library.

It includes functionalities for generating call graphs, retrieving CFG basic blocks,
extracting strings and their references, and emulating functions using ESIL.
All operations are designed to be thread-safe.
"""
import rzpipe
import json
from typing import Dict, Any, List, Optional
import re
import concurrent.futures
import threading
import queue

# Global lock for rzpipe operations to prevent race conditions
rz_lock = threading.Lock()

def _open_rzpipe(binary_path: str) -> rzpipe.open:
    """
    Opens an rzpipe instance for a given binary and performs initial analysis.

    Args:
        binary_path: The path to the binary file.

    Returns:
        An initialized rzpipe instance after running 'aaa' analysis and disabling color.
    """
    rz = rzpipe.open(binary_path)
    rz.cmd("e scr.color=0; aaa")  # Disable color, perform auto-analysis
    return rz

def _get_function_via_addr(rz: rzpipe.open, addr: int) -> Dict[str, Any]:
    """
    Retrieves function information for a given address.

    Args:
        rz: An active rzpipe instance.
        addr: The address of the function.

    Returns:
        A dictionary containing function information, or an empty dict if not found.
    """
    func = json.loads(rz.cmd(f"afij @ {addr}"))
    func = func[0] if isinstance(func, list) and len(func) > 0 else {}
    if not func:
        return {}
    shortented_func = {
        "offset": func.get("offset"),
        "name": func.get("name"),
        "size": func.get("realsz"),
        "file": func.get("file", ""),
        "signature": func.get("signature")
    }
    # Get the list of functions that call this function
    xrefs = rz.cmdj(f"axtj @ {addr}")
    shortented_func["called_by"] = []
    for x in xrefs or []:
        from_addr = x.get("from")
        if from_addr is None:
            continue
        # Get the function info for the caller
        finfo = rz.cmdj(f"afij @ {from_addr}")
        if not finfo or not isinstance(finfo, list) or len(finfo) == 0:
            continue
        fname = finfo[0].get("name", "unknown")
        shortented_func["called_by"].append({'name': fname, 'offset': from_addr})

    return shortented_func

def get_call_graph(binary_path: str, function_name: Optional[str] = None, depth: int = 3) -> Dict[str, Any]:
    """
    Generates a call graph for a binary.

    If a function_name is provided, it generates a localized call graph for that
    function up to a specified depth. Otherwise, it generates a global call graph
    for the entire binary.

    Args:
        binary_path: The path to the binary file.
        function_name: Optional. The name of the function to start the graph from.
        depth: The maximum depth of the call graph when a function_name is given.

    Returns:
        A dictionary containing 'nodes' and 'edges' of the call graph.
        Nodes are dicts with 'name' and 'addr'. Edges are tuples of (from_addr, to_addr).
    """
    with rz_lock:
        rz = _open_rzpipe(binary_path)
        try:
            if function_name:
                # Get call graph for a specific function with depth
                # agCdj: call graph with depth, JSON output
                graph_json = rz.cmd(f"agCdj {depth} @ {function_name}")
            else:
                # Get global call graph
                # agfj: function call graph, JSON output
                graph_json = rz.cmd("agfj")

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
                    # For simplicity, we'll just list nodes for now, or use a different rz command if needed for edges
                    # A more robust approach for global graph might involve parsing 'agf' and then 'axf' for calls

            return {"nodes": nodes, "edges": edges}
        finally:
            rz.quit()

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
    with rz_lock:
        rz = _open_rzpipe(binary_path)
        try:
            # Get basic block information (afbj: function basic blocks, JSON output)
            blocks_json = rz.cmd(f"afbj @ {function_name}")
            if not blocks_json:
                return []
            blocks_data = json.loads(blocks_json)

            # Get control flow graph edges (agj: graph, JSON output)
            edges_json = rz.cmd(f"agj @ {function_name}")
            edges_data = json.loads(edges_json) if edges_json else []

            # Map block addresses to their data for easier lookup
            block_map = {b["offset"]: b for b in blocks_data}

            # Add successors to each block
            for edge in edges_data:
                src_addr = edge["from"]
                dst_addr = edge["to"]
                if src_addr in block_map:
                    if "succ" not in block_map[src_addr]:
                        block_map[src_addr]["succ"] = []
                    block_map[src_addr]["succ"].append(dst_addr)

            # Format output
            formatted_blocks = [
                {
                    "offset": block["offset"],
                    "size": block["size"],
                    "type": block.get("type", "unknown"), # e.g., "entry", "cond", "uncond"
                    "succ": block.get("succ", [])
                } for block in blocks_data
            ]
            return formatted_blocks
        finally:
            rz.quit()

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
    with rz_lock:
        rz = _open_rzpipe(binary_path)
        try:
            # izj: info strings, JSON output
            strings_json = rz.cmd("izj")
            if not strings_json:
                return []
            strings_data = json.loads(strings_json)

            return [
                s for s in strings_data if s.get("length", 0) >= min_length
            ]
        finally:
            rz.quit()

def search_string_refs(binary_path: str, query: str, ignore_case: bool = True, max_refs: int = 50) -> List[Dict[str, Any]]:
    """
    Searches for references to strings that match a given query.

    Args:
        binary_path: The substring or regex pattern to search for within the strings.
        query: The substring or regex to search for.
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
    with rz_lock:
        rz = _open_rzpipe(binary_path)
        try:
            for s in matched_strings:
                str_addr = s.get("vaddr")
                if str_addr is None:
                    continue

                # axtj: xrefs to address, JSON output
                refs_json = rz.cmd(f"axtj @ {str_addr}")
                refs_data = json.loads(refs_json) if refs_json else []
                refs = []
                for ref in refs_data:
                    if not ref:
                        continue
                    f = _get_function_via_addr(rz, ref.get("from"))
                    code = ref.get("from")
                    code = json.loads(rz.cmd(f"pdj 1 @ {code}"))  # Get disassembly for the target address
                    if not code:
                        continue
                    disasm = code[0].get("disasm", "")
                    opcode = code[0].get("opcode", "")
                    refs.append({
                        "caller": f.get("name") if f else "unknown",
                        "calling_addr": hex(ref.get("from")) if ref.get("from") else "unknown",
                        "disasm": disasm or "unknown",
                        "opcode": opcode or "unknown",\
                    })

                results.append({
                    "string": s.get("string"),
                    "str_addr": hex(str_addr),
                    "refs": refs[:max_refs]  # Limit to max_refs
                })
            return results
        finally:
            rz.quit()

def _emulate_function_target(rz_instance, function_name, max_steps, result_queue):
    """
    Target function for threaded ESIL emulation to allow for timeouts.

    This function is intended to be run in a separate thread. It initializes
    ESIL, steps through the function's instructions, and records the trace.

    Args:
        rz_instance: An active rzpipe instance.
        function_name: The name of the function to emulate.
        max_steps: The maximum number of instructions to emulate.
        result_queue: A queue to store the final result or error.
    """
    try:
        rz_instance.cmd(f"aeim @ {function_name}") # Initialize ESIL emulation at function entry
        trace = []
        for step in range(max_steps):
            # Get current register state (aerj: ESIL registers, JSON output)
            regs_json = rz_instance.cmd("aerj")
            current_regs = json.loads(regs_json) if regs_json else {}

            # Get current instruction (pdj 1 @ PC)
            current_pc = current_regs.get("pc")
            if current_pc is None:
                break # PC not found, something went wrong

            disasm_json = rz_instance.cmd(f"pdj 1 @ {current_pc}")
            current_op = json.loads(disasm_json)[0] if disasm_json else {}

            trace.append({
                "step": step,
                "pc": hex(current_pc),
                "op": current_op.get("disasm"),
                "regs": current_regs
            })

            # Execute one ESIL instruction (aei: ESIL step)
            rz_instance.cmd("aei")

            # Check if emulation finished (e.g., hit ret or invalid instruction)
            # This is a heuristic, a more robust check might involve analyzing ESIL flags or state
            if rz_instance.cmd("aerj").strip() == "{}": # If registers are empty, emulation might have stopped
                break

        final_regs_json = rz_instance.cmd("aerj")
        final_regs = json.loads(final_regs_json) if final_regs_json else {}
        result_queue.put({"final_regs": final_regs, "trace": trace})
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
        A dictionary containing the 'final_regs' and instruction 'trace',
        or an 'error' message if the emulation failed or timed out.
    """
    with rz_lock: # Acquire lock before opening rzpipe
        rz = _open_rzpipe(binary_path)
        result_queue = queue.Queue()
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        future = executor.submit(_emulate_function_target, rz, function_name, max_steps, result_queue)

        try:
            return result_queue.get(timeout=timeout)
        except queue.Empty:
            return {"error": f"Emulation timed out after {timeout} seconds."}
        except Exception as e:
            return {"error": f"An unexpected error occurred: {str(e)}"}
        finally:
            future.cancel()
            executor.shutdown(wait=False)
            rz.quit()


if __name__ == "__main__":
    binary_path = "./crackme100"  # Example binary path
    function_name = "main"  # Example function name

    # Test search_string_refs
    query = "Enter the secret password:"
    results = search_string_refs(binary_path, query)
    print(f"Search results for '{query}':")

    for res in results:
        print(f"  String: {res['string']}, Address: {res['str_addr']}")
        for ref in res['refs']:
            print(f"    Ref: {ref['fcn']} at {hex(ref['offset'])} - {ref['disasm']}")

    # Emulate the function and print the result
    result = emulate_function(binary_path, function_name)
    print(json.dumps(result, indent=2))