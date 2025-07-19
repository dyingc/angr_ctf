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

def get_call_graph(binary_path: str, function_name: Optional[str] = None) -> Dict[str, Any]:
    """
    Generates a call graph for a binary.

    If a function_name is provided, it generates a localized call graph for that
    function up to a specified depth. Otherwise, it generates a global call graph
    for the entire binary.

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
                # Get call graph for a specific function with depth
                # agCdj: call graph with depth, JSON output
                graph_json = rz.cmd(f"agc json @ {function_name}")
            else:
                # Get global call graph
                # agfj: function call graph, JSON output
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
                    "addr": n.get("offset"),
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
            formatted_blocks = []
            for block in blocks_data:
                b = {
                    "addr": block.get("addr"),
                    "size": block.get("size"),
                    "num_of_input_blocks": block.get("inputs", 0),
                    "num_of_output_blocks": block.get("outputs", 0),
                    "num_of_instructions": block.get("ninstr", 0),
                    "jump_to_addr": block.get("jump"),
                    "jump_to_func_with_offset": rz.cmd(f"afd @ {block.get('jump')}").strip() if block.get("jump") else None
                }
                if "fail" in block:
                    b["fall_through_addr"] = block["fail"]
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
                        "calling_addr": ref.get("from") if ref.get("from") else "unknown",
                        "disasm": disasm or "unknown",
                        "opcode": opcode or "unknown",
                    })

                results.append({
                    "string": s.get("string"),
                    "str_addr": str_addr,
                    "refs": refs[:max_refs]  # Limit to max_refs
                })
            return results
        finally:
            rz.quit()

import json
import time

def _emulate_function_target_rzil(rz_instance, function_name, max_steps, result_queue, timeout_seconds=30):
    """
    现代化的RzIL模拟函数，充分利用Rizin的新架构

    Args:
        rz_instance: rzpipe实例
        function_name: 要模拟的函数名
        max_steps: 最大执行步数
        result_queue: 结果队列
        timeout_seconds: 超时时间（秒）
    """
    start_time = time.time()

    try:
        # 1. 初始化RzIL VM
        rz_instance.cmd(f"s {function_name}")  # 跳转到函数
        init_result = rz_instance.cmd("aezi")   # 初始化RzIL VM

        if "error" in init_result.lower():
            result_queue.put({
                "error": f"Failed to initialize RzIL VM: {init_result}",
                "success": False
            })
            return

        trace = []
        vm_changes = []  # 记录VM状态变化

        # 2. 开始执行
        for step in range(max_steps):
            # 超时检查
            if time.time() - start_time > timeout_seconds:
                break

            # 3. 获取当前寄存器状态
            regs_json = rz_instance.cmd("arj")
            current_regs = json.loads(regs_json) if regs_json.strip() else {}

            # 4. 获取当前PC
            current_pc = current_regs.get("rip", current_regs.get("pc", current_regs.get("eip")))
            if current_pc is None:
                break

            # 5. 获取当前指令信息
            disasm_json = rz_instance.cmd(f"pdj 1 @ {current_pc}")
            if not disasm_json.strip():
                break

            try:
                current_op = json.loads(disasm_json)[0]
            except (json.JSONDecodeError, IndexError):
                current_op = {}

            # 6. 获取RzIL表示
            rzil_repr = ""
            try:
                rzil_repr = rz_instance.cmd(f"aoip 1 @ {current_pc}")
            except:
                rzil_repr = "N/A"

            # 7. 记录当前状态
            step_info = {
                "step": step,
                "pc": hex(current_pc) if isinstance(current_pc, int) else current_pc,
                "op": current_op.get("disasm", ""),
                "opcode": current_op.get("opcode", ""),
                "type": current_op.get("type", ""),
                "rzil": rzil_repr.strip(),
                "regs": current_regs,
                "timestamp": time.time() - start_time
            }

            trace.append(step_info)

            # 8. 执行一步RzIL并记录状态变化
            step_output = rz_instance.cmd("aezse 1")  # 执行并显示状态变化

            # 解析VM状态变化
            if step_output.strip():
                vm_changes.append({
                    "step": step,
                    "changes": step_output.strip(),
                    "timestamp": time.time() - start_time
                })

            # 9. 检查是否到达函数结尾
            if current_op.get("type") in ["ret", "retn", "retf"]:
                break

            # 10. 检查是否有执行错误
            if any(keyword in step_output.lower() for keyword in ["error", "invalid", "failed"]):
                break

            # 11. 检查PC是否变化（防止无限循环）
            new_regs_json = rz_instance.cmd("arj")
            new_regs = json.loads(new_regs_json) if new_regs_json.strip() else {}
            new_pc = new_regs.get("rip", new_regs.get("pc", new_regs.get("eip")))

            # 如果PC没变化且不是循环指令，可能遇到了问题
            if new_pc == current_pc and current_op.get("type") not in ["nop", "call"]:
                break

        # 12. 获取最终状态
        final_regs_json = rz_instance.cmd("arj")
        final_regs = json.loads(final_regs_json) if final_regs_json.strip() else {}

        result_queue.put({
            "success": True,
            "final_regs": final_regs,
            "trace": trace,
            "vm_changes": vm_changes,
            "steps_executed": len(trace),
            "execution_time": time.time() - start_time,
            "emulation_type": "RzIL"
        })

    except Exception as e:
        result_queue.put({
            "error": str(e),
            "success": False,
            "execution_time": time.time() - start_time,
            "partial_trace": trace if 'trace' in locals() else []
        })
    finally:
        # RzIL资源清理
        try:
            # 重置到原始位置
            rz_instance.cmd("s-")
        except:
            pass


def emulate_function_with_timeout(rz_instance, function_name, max_steps=1000, timeout=30):
    """
    带超时的函数模拟包装器

    Args:
        rz_instance: rzpipe实例
        function_name: 函数名
        max_steps: 最大步数
        timeout: 超时时间（秒）

    Returns:
        dict: 模拟结果
    """
    import queue
    import threading

    result_queue = queue.Queue()

    # 启动模拟线程
    emulation_thread = threading.Thread(
        target=_emulate_function_target_rzil,
        args=(rz_instance, function_name, max_steps, result_queue, timeout)
    )

    emulation_thread.daemon = True
    emulation_thread.start()

    try:
        # 等待结果或超时
        result = result_queue.get(timeout=timeout + 5)  # 给一些缓冲时间
        return result
    except queue.Empty:
        return {
            "error": f"Emulation timed out after {timeout} seconds",
            "success": False
        }
    finally:
        if emulation_thread.is_alive():
            # 线程仍在运行，但我们已经超时了
            pass

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
        future = executor.submit(_emulate_function_target_rzil, rz, function_name, max_steps, result_queue, timeout_seconds=timeout)

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
        print(f"  String: {res['string']}, Address: {hex(res['str_addr'])}")
        for ref in res['refs']:
            print(f"    Ref: {ref['caller']} at {hex(ref['calling_addr'])} - {ref['disasm']}")

    # Test get_call_graph
    call_graph = get_call_graph(binary_path, function_name)
    print(f"\nCall graph for function '{function_name}':")
    print("Nodes:")
    for node in call_graph['nodes']:
        print(f"  {node}")
    print("Edges:")
    for edge in call_graph['edges']:
        print(f"  {edge}")

    # Test get_cfg_basic_blocks
    cfg_blocks = get_cfg_basic_blocks(binary_path, function_name)
    print(f"\nCFG basic blocks for function '{function_name}':")
    for block in cfg_blocks:
        for addr, block in block.items():
            print(f"  Address: {hex(addr)}, Block: {block}")

    # Emulate the function and print the result
    result = emulate_function(binary_path, function_name, max_steps=10, timeout=3600)
    print(json.dumps(result, indent=2))