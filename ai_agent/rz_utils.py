"""
This module provides a set of utility functions for binary analysis using the Rizin
framework via the rzpipe library.

It includes functionalities for generating call graphs, retrieving CFG basic blocks,
extracting strings and their references, and emulating functions using RzIL.
All operations are designed to be thread-safe.
"""
import rzpipe
import json
from typing import Dict, Any, List, Optional
import re
import threading

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
    rz.cmd("e scr.color=0; aaa 2>/dev/null")  # Disable color, perform auto-analysis
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

def get_call_graph(binary_path: str, function_name: Optional[str] = None) -> Dict[str, Any]:
    """
    Generates a call graph for a binary.

    If a function_name is provided, it generates a localized call graph for that
    function. Otherwise, it generates a global call graph for the entire binary.

    Args:
        binary_path: The path to the binary file.
        function_name: Optional. The name of the function to start the graph from.

    Returns:
        A dictionary containing 'nodes' and 'edges' of the call graph.
        Nodes are dicts with 'name' and 'addr'. Edges are tuples of (from_addr, to_addr).
    """
    with rz_lock:
        rz = _open_rzpipe(binary_path)
        try:
            if function_name:
                # Get call graph for a specific function
                # agCj: call graph, JSON output
                graph_json = rz.cmd(f"agc json @ {function_name}")
            else:
                # Get global call graph
                # agCj: call graph, JSON output
                graph_json = rz.cmd("agC json")

            if not graph_json:
                return {"nodes": [], "edges": []}

            graph_data = json.loads(graph_json)
            nodes = []
            edges = []

            # Map internal graph node-id → offset for easy edge translation
            id2off = {}
            nodes = []
            for n in graph_data.get("nodes", []):
                node_entry = {
                    "id": n.get("id"),
                    "name": n.get("title"),
                    "addr": hex(n.get("offset")) if n.get("offset") else "unknown",
                }
                nodes.append(node_entry)
                id2off[node_entry["id"]] = node_entry["addr"]

            edges = []
            from_node = graph_data.get("nodes", [])[0]
            out_node_ids = from_node.get("out_nodes", [])
            for dst_id in out_node_ids:
                src_id = from_node.get("id")
                if src_id in id2off and dst_id in id2off:
                    edges.append({"from": src_id, "to": dst_id})

            return {"nodes": nodes, "edges": edges}
        except Exception as e:
            print(f"Error generating call graph: {e}")
            return {"nodes": [], "edges": []}
        finally:
            rz.quit()

def get_cfg_basic_blocks(binary_path: str, function_name: str) -> List[Dict[str, Any]]:
    """
    Retrieves Control Flow Graph (CFG) basic blocks for a given function.

    Args:
        binary_path: The path to the binary file.
        function_name: The name of the function to analyze.

    Returns:
        A list of dictionaries, where each dictionary represents a basic block.
        The key of the dictionary is the block's address, and the value is a
        dictionary containing 'addr', 'size', 'num_of_input_blocks',
        'num_of_output_blocks', 'num_of_instructions', 'jump_to_addr',
        'jump_to_func_with_offset', 'fall_through_addr' (if applicable), and
        'fall_through_func_with_offset' (if applicable).
    """
    with rz_lock:
        rz = _open_rzpipe(binary_path)
        try:
            # Get basic block information (afbj: function basic blocks, JSON output)
            blocks_json = rz.cmd(f"afbj @ {function_name}")
            if not blocks_json:
                return []
            blocks_data = json.loads(blocks_json)
            formatted_blocks = []
            for block in blocks_data:
                b = {
                    "addr": hex(block.get("addr")) if block.get("addr") else "unknown",
                    "size": block.get("size"),
                    "num_of_input_blocks": block.get("inputs", 0),
                    "num_of_output_blocks": block.get("outputs", 0),
                    "num_of_instructions": block.get("ninstr", 0),
                    "jump_to_addr": hex(block.get("jump")) if block.get("jump") else "unknown",
                    "jump_to_func_with_offset": rz.cmd(f"afd @ {block.get('jump')}").strip() if block.get("jump") else None
                }
                if "fail" in block:
                    b["fall_through_addr"] = hex(block["fail"]) if block.get("fail") else "unknown"
                    b["fall_through_func_with_offset"] = rz.cmd(f"afd @ {block.get('fail')}").strip() if block.get("fail") else None
                formatted_blocks.append({b['addr']: b})
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
        binary_path: The path to the binary file.
        query: The substring or regex pattern to search for within the strings.
        ignore_case: If True, performs a case-insensitive search.
        max_refs: The maximum number of references to return per matched string.

    Returns:
        A list of dictionaries, where each dictionary contains the matched 'string',
        its 'str_addr', and a list of 'refs' pointing to it. Each reference
        includes the 'caller' function name, 'calling_addr', 'disasm' of the
        instruction, and 'opcode'.
    """
    all_strings = get_strings(binary_path)

    regex_flags = re.IGNORECASE if ignore_case else 0
    matched_strings = [
        s for s in all_strings if re.search(query, s.get("string", ""), regex_flags)
    ]

    results = []
    with rz_lock:
        rz = _open_rzpipe(binary_path)
        # 获取二进制基址
        bin_info = rz.cmdj("ij")
        baddr = bin_info.get("bin", {}).get("baddr", 0)

        try:
            for s in matched_strings:
                str_addr = s.get("paddr") + baddr if s.get("paddr") else None
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
                        "opcode": opcode or "unknown",
                    })

                results.append({
                    "string": s.get("string"),
                    "str_addr": hex(str_addr) if str_addr else "unknown",
                    "refs": refs[:max_refs]  # Limit to max_refs
                })
            return results
        finally:
            rz.quit()

if __name__ == "__main__":
    binary_path = "./00_angr_find/00_angr_find_arm"  # Example binary path
    function_name = "main"  # Example function name

    print("=" * 60)
    print("Rizin Binary Analysis with Improved RzIL Emulation")
    print("=" * 60)

    # Test search_string_refs
    query = "Try again."
    print(f"\n🔍 Searching for string references: '{query}'")
    results = search_string_refs(binary_path, query)
    print(f"Search results for '{query}':")

    for res in results:
        print(f"  String: {res['string']}, Address: {res['str_addr']}")
        for ref in res['refs']:
            print(f"    Ref: {ref['caller']} at {ref['calling_addr']} - {ref['disasm']}")

    # Test get_call_graph
    print(f"\n📊 Generating call graph for function '{function_name}':")
    call_graph = get_call_graph(binary_path, function_name)
    print("Nodes:")
    for node in call_graph['nodes']:
        print(f"  {node}")
    print("Edges:")
    for edge in call_graph['edges']:
        print(f"  {edge}")

    # Test get_cfg_basic_blocks
    print(f"\n🔗 Getting CFG basic blocks for function '{function_name}':")
    cfg_blocks = get_cfg_basic_blocks(binary_path, function_name)
    for block in cfg_blocks:
        for addr, block_info in block.items():
            print(f"  Address: {addr}, Block: {block_info}")

    # Test emulate_function
    print(f"\n🧪 Emulating function '{function_name}':")
    result = emulate_function(binary_path, function_name, max_steps=10, timeout=60,
                              stack_bytes=32, stack_size=0x10000,
                              stack_base=0x70000000, data_size=0x1000,
                              data_base=0x60000000)
    print(f"Emulation result: {result}")
