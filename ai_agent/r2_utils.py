import r2pipe
import json
from typing import Dict, Any, List, Optional
import re
import concurrent.futures
import threading
import queue # Import queue module

# Global lock for r2pipe operations to prevent race conditions
r2_lock = threading.Lock()

def _open_r2pipe(binary_path: str):
    """Helper to open r2pipe with common analysis commands."""
    r2 = r2pipe.open(binary_path)
    r2.cmd("e scr.color=0; aaa") # Disable color, perform auto-analysis
    return r2

def get_call_graph(binary_path: str, function_name: Optional[str] = None, depth: int = 3) -> Dict[str, Any]:
    """
    Generates a call graph for a binary.
    If function_name is provided, generates a call graph for that function up to a specified depth.
    Otherwise, generates a global call graph.
    """
    with r2_lock:
        r2 = _open_r2pipe(binary_path)
        try:
            if function_name:
                # Get call graph for a specific function with depth
                # agCdj: call graph with depth, JSON output
                graph_json = r2.cmd(f"agCdj {depth} @ {function_name}")
            else:
                # Get global call graph
                # agfj: function call graph, JSON output
                graph_json = r2.cmd("agfj")

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
                    pass # Edges from agfj are complex to parse directly into (src, dst) tuples without more info

            return {"nodes": nodes, "edges": edges}
        finally:
            r2.quit()

def get_cfg_basic_blocks(binary_path: str, function_name: str) -> List[Dict[str, Any]]:
    """
    Retrieves basic blocks information for a given function, including boundaries,
    and control flow information.
    """
    with r2_lock:
        r2 = _open_r2pipe(binary_path)
        try:
            # Get basic block information (afbj: function basic blocks, JSON output)
            blocks_json = r2.cmd(f"afbj @ {function_name}")
            if not blocks_json:
                return []

            blocks_data = json.loads(blocks_json)

            # Get control flow graph edges (agj: graph, JSON output)
            edges_json = r2.cmd(f"agj @ {function_name}")
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
            formatted_blocks = []
            for block in blocks_data:
                formatted_blocks.append({
                    "offset": block["offset"],
                    "size": block["size"],
                    "type": block.get("type", "unknown"), # e.g., "entry", "cond", "uncond"
                    "succ": block.get("succ", [])
                })
            return formatted_blocks
        finally:
            r2.quit()

def get_strings(binary_path: str, min_length: int = 4) -> List[Dict[str, Any]]:
    """
    Extracts printable strings from a binary.
    """
    with r2_lock:
        r2 = _open_r2pipe(binary_path)
        try:
            # izj: info strings, JSON output
            strings_json = r2.cmd("izj")
            if not strings_json:
                return []

            strings_data = json.loads(strings_json)

            filtered_strings = []
            for s in strings_data:
                if s.get("length", 0) >= min_length:
                    filtered_strings.append({
                        "vaddr": s.get("vaddr"),
                        "paddr": s.get("paddr"),
                        "string": s.get("string"),
                        "section": s.get("section"),
                        "length": s.get("length")
                    })
            return filtered_strings
        finally:
            r2.quit()

def search_string_refs(binary_path: str, query: str, ignore_case: bool = True, max_refs: int = 50) -> List[Dict[str, Any]]:
    """
    Searches for string references in a binary based on a query (substring or regex).
    """
    all_strings = get_strings(binary_path)

    matched_strings = []
    for s in all_strings:
        s_content = s.get("string", "")
        if ignore_case:
            if re.search(query, s_content, re.IGNORECASE):
                matched_strings.append(s)
        else:
            if re.search(query, s_content):
                matched_strings.append(s)

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

                formatted_refs = []
                for ref in refs_data[:max_refs]: # Limit number of refs
                    formatted_refs.append({
                        "fcn": ref.get("fcn_name"),
                        "offset": ref.get("from"),
                        "disasm": ref.get("opcode") # This might be the instruction that references it
                    })

                results.append({
                    "string": s.get("string"),
                    "str_addr": hex(str_addr),
                    "refs": formatted_refs
                })
            return results
        finally:
            r2.quit()

def _emulate_function_target(r2_instance, function_name, max_steps, result_queue):
    """Target function for emulation to run in a separate thread."""
    try:
        r2_instance.cmd(f"aeim @ {function_name}") # Initialize ESIL emulation at function entry

        trace = []
        for step in range(max_steps):
            # Get current register state (aerj: ESIL registers, JSON output)
            regs_json = r2_instance.cmd("aerj")
            current_regs = json.loads(regs_json) if regs_json else {}

            # Get current instruction (pdj 1 @ PC)
            current_pc = current_regs.get("pc")
            if current_pc is None:
                break # PC not found, something went wrong

            disasm_json = r2_instance.cmd(f"pdj 1 @ {current_pc}")
            current_op = json.loads(disasm_json)[0] if disasm_json else {}

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
                break

        final_regs_json = r2_instance.cmd("aerj")
        final_regs = json.loads(final_regs_json) if final_regs_json else {}

        result_queue.put({"final_regs": final_regs, "trace": trace})
    except Exception as e:
        result_queue.put({"error": str(e)})

def emulate_function(binary_path: str, function_name: str, max_steps: int = 100, timeout: int = 60) -> Dict[str, Any]:
    """
    Emulates a function for a specified number of steps and returns register states and trace.
    """
    with r2_lock: # Acquire lock before opening r2pipe
        r2 = _open_r2pipe(binary_path)

        result_queue = queue.Queue()
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)

        future = executor.submit(_emulate_function_target, r2, function_name, max_steps, result_queue)

        try:
            # Wait for the result with a timeout
            emulation_result = result_queue.get(timeout=timeout)
            return emulation_result
        except concurrent.futures.TimeoutError:
            return {"error": f"Emulation timed out after {timeout} seconds."}
        except Exception as e:
            return {"error": f"An unexpected error occurred during emulation setup: {str(e)}"}
        finally:
            executor.shutdown(wait=False) # Ensure the thread is cleaned up
            r2.quit() # Ensure r2pipe is closed
