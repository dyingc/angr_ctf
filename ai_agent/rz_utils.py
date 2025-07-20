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

def _initialize_rzil_vm(rz_instance, result_queue):
    """
    初始化 RzIL VM 并处理初始化失败的情况。
    """
    # 3. 初始化 RzIL VM
    init_result = rz_instance.cmd("aezi")
    if "error" in init_result.lower() or "fail" in init_result.lower():
        result_queue.put({
            "error": f"Failed to initialize RzIL VM: {init_result}",
            "success": False
        })
        return False
    return True

def _get_arch_specific_registers(binary_info):
    """
    根据二进制信息确定架构和位数，返回相应的栈指针、基指针和初始栈地址。
    """
    # 获取架构信息来确定正确的寄存器名称
    arch_info = binary_info.get("bin", {})
    arch = arch_info.get("arch", "x86")
    bits = arch_info.get("bits", 64)

    # 根据架构设置合适的栈指针
    if arch == "x86" and bits == 64:
        # x86_64 架构
        stack_pointer = "rsp"
        base_pointer = "rbp"
        initial_sp = 0x7fffff000000  # 简化的栈地址
    elif arch == "x86" and bits == 32:
        # x86_32 架构
        stack_pointer = "esp"
        base_pointer = "ebp"
        initial_sp = 0xbffff000
    elif arch == "arm" and bits == 64:
        # ARM64 架构
        stack_pointer = "sp"
        base_pointer = "fp"
        initial_sp = 0x7fffff000000
    elif arch == "arm" and bits == 32:
        # ARM32 架构
        stack_pointer = "sp"
        base_pointer = "fp"
        initial_sp = 0xbffff000
    else:
        # 默认值
        stack_pointer = "sp"
        base_pointer = "fp"
        initial_sp = 0x7fffff000000

    # 设置栈指针（确保16字节对齐）
    aligned_sp = initial_sp & ~0xF
    return arch, bits, stack_pointer, base_pointer, aligned_sp

def _set_initial_registers(rz_instance, stack_pointer, base_pointer, aligned_sp):
    """
    设置初始寄存器值。
    """
    rz_instance.cmd(f"aezv {stack_pointer} {hex(aligned_sp)}")
    rz_instance.cmd(f"aezv {base_pointer} {hex(aligned_sp)}")

    # 5. 验证设置
    current_sp = rz_instance.cmd(f"aezv {stack_pointer}")
    print(f"Stack pointer ({stack_pointer}) set to: {current_sp.strip()}")

def _get_current_emulation_state(rz_instance, start_time, step):
    """
    获取当前寄存器状态、PC、指令信息和 RzIL 表示。
    """
    # 7. 获取当前寄存器状态
    current_regs = {}
    try:
        regs_json = rz_instance.cmd("aezvj")  # 使用 JSON 格式获取 VM 寄存器
        if not regs_json.strip():
            # 如果 aezvj 不工作，尝试标准的寄存器命令
            regs_json = rz_instance.cmd("drj")
        current_regs = json.loads(regs_json) if regs_json.strip() else {}
    except json.JSONDecodeError:
        current_regs = {}

    # 8. 获取当前PC
    current_pc = None
    pc_candidates = ["rip", "pc", "eip", "ip", "PC"]
    for pc_reg in pc_candidates:
        if pc_reg in current_regs:
            current_pc = current_regs[pc_reg]
            break

    if current_pc is None:
        print("Cannot determine current PC, stopping execution")
        return None, None, None, None, None

    # 9. 获取当前指令信息
    current_op = {}
    try:
        disasm_json = rz_instance.cmd(f"pdj 1 @ {current_pc}")
        if disasm_json.strip():
            current_op = json.loads(disasm_json)[0]
        else:
            current_op = {}
    except (json.JSONDecodeError, IndexError):
        current_op = {}

    # 10. 获取RzIL表示（如果可用）
    rzil_repr = ""
    try:
        rzil_repr = rz_instance.cmd(f"aoip 1 @ {current_pc}")
    except:
        rzil_repr = "N/A"

    # 11. 记录当前状态
    step_info = {
        "step": step,
        "pc": hex(current_pc) if isinstance(current_pc, int) else str(current_pc),
        "op": current_op.get("disasm", ""),
        "opcode": current_op.get("opcode", ""),
        "type": current_op.get("type", ""),
        "rzil": rzil_repr.strip(),
        "regs": current_regs,
        "timestamp": time.time() - start_time
    }
    return step_info, current_pc, current_op, current_regs, rzil_repr

def _check_emulation_termination(step_info, step_output, timeout_seconds, start_time, trace):
    """
    检查模拟是否应该终止（超时、返回指令、执行错误、无限循环）。
    返回 True 表示应该终止，False 表示继续。
    """
    # 超时检查
    if time.time() - start_time > timeout_seconds:
        print(f"Execution timed out after {timeout_seconds} seconds")
        return True

    # 检查是否到达函数结尾
    op_type = step_info.get("type", "")
    if op_type in ["ret", "retn", "retf", "return"]:
        print(f"Reached return instruction at step {step_info['step']}")
        return True

    # 检查是否有执行错误
    if step_output and any(keyword in str(step_output).lower() for keyword in ["error", "invalid", "failed"]):
        print(f"Execution error at step {step_info['step']}: {step_output}")
        return True

    # 简单的无限循环检测
    if step_info['step'] > 0 and len(trace) >= 2:
        prev_pc = trace[-2]["pc"]
        if prev_pc == step_info["pc"] and op_type not in ["nop", "call"]:
            print(f"Possible infinite loop detected at step {step_info['step']}")
            return True
    return False

def _emulate_function_target_rzil(rz_instance, function_name, max_steps, result_queue, timeout_seconds=30):
    """
    修正后的 RzIL 模拟函数，移除了不存在的命令并优化了内存处理。

    Args:
        rz_instance: 活跃的 rzpipe 实例。
        function_name: 要模拟的函数名称。
        max_steps: 最大执行步数。
        result_queue: 用于放置模拟结果的队列。
        timeout_seconds: 超时时间（秒）。
    """
    start_time = time.time()
    original_offset = None
    trace = []
    vm_changes = []

    try:
        # 1. 保存当前偏移量并跳转到函数
        original_offset = rz_instance.cmd("s").strip()
        rz_instance.cmd(f"s {function_name}")

        # 2. 获取二进制信息
        binary_info = rz_instance.cmdj("ij")
        if not binary_info:
            result_queue.put({
                "error": "Failed to get binary information",
                "success": False
            })
            return

        # 3. 初始化 RzIL VM
        if not _initialize_rzil_vm(rz_instance, result_queue):
            return

        # 4. 设置基本的寄存器初始值
        arch, bits, stack_pointer, base_pointer, aligned_sp = _get_arch_specific_registers(binary_info)
        _set_initial_registers(rz_instance, stack_pointer, base_pointer, aligned_sp)

        # 6. 开始执行循环
        for step in range(max_steps):
            step_info, current_pc, current_op, current_regs, rzil_repr = _get_current_emulation_state(rz_instance, start_time, step)

            if current_pc is None:
                # Cannot determine current PC, stopping execution (handled in _get_current_emulation_state)
                break

            trace.append(step_info)

            # 12. 执行一步并记录状态变化
            try:
                step_output = json.loads(rz_instance.cmd("aezsej 1"))
            except json.JSONDecodeError:
                print(f"执行错误: {e}")
                break

            # 记录VM状态变化
            if step_output:
                vm_changes.append({
                    "step": step,
                    "changes": step_output,
                    "timestamp": time.time() - start_time
                })

            # 检查是否应该终止模拟
            if _check_emulation_termination(step_info, step_output, timeout_seconds, start_time, trace):
                break

        # 16. 获取最终状态
        final_regs = {}
        try:
            final_regs_json = rz_instance.cmd("aezvj")
            if not final_regs_json.strip():
                final_regs_json = rz_instance.cmd("arj")
            final_regs = json.loads(final_regs_json) if final_regs_json.strip() else {}
        except json.JSONDecodeError:
            final_regs = {}

        result_queue.put({
            "success": True,
            "final_regs": final_regs,
            "trace": trace,
            "vm_changes": vm_changes,
            "steps_executed": len(trace),
            "execution_time": time.time() - start_time,
            "emulation_type": "RzIL",
            "memory_setup": {
                "architecture": arch,
                "bits": bits,
                "stack_pointer": stack_pointer,
                "initial_sp": hex(aligned_sp)
            }
        })

    except Exception as e:
        result_queue.put({
            "error": str(e),
            "success": False,
            "execution_time": time.time() - start_time,
            "partial_trace": trace if 'trace' in locals() else []
        })
    finally:
        # 清理：恢复到原始偏移量
        if original_offset:
            try:
                rz_instance.cmd(f"s {original_offset}")
            except:
                pass

        # 注意：RzIL VM 会在 rzpipe 实例关闭时自动清理，
        # 这里不需要手动清理 VM 状态


# 添加一个辅助函数来设置更复杂的内存布局
def setup_realistic_memory_layout(rz_instance):
    """
    设置更真实的内存布局，包括代码段、数据段和栈段
    """
    try:
        # 获取程序入口点和段信息
        segments = rz_instance.cmdj("iSj")  # 获取段信息

        if segments:
            for seg in segments:
                perm = seg.get("perm", "")
                vaddr = seg.get("vaddr", 0)
                size = seg.get("size", 0)

                if size > 0 and vaddr > 0:
                    # 为每个段设置内存映射
                    perm_str = "rwx" if "x" in perm else ("rw" if "w" in perm else "r")
                    map_cmd = f"aezm {hex(vaddr)} {hex(size)} {perm_str}"
                    result = rz_instance.cmd(map_cmd)
                    print(f"Mapped segment: {hex(vaddr)}-{hex(vaddr + size)} ({perm_str})")

        # 设置栈
        stack_base = 0x7fffffff0000
        stack_size = 0x10000
        rz_instance.cmd(f"aezm {hex(stack_base - stack_size)} {hex(stack_size)} rwx")
        rz_instance.cmd(f"aezv rsp {hex(stack_base - 0x100)}")
        rz_instance.cmd(f"aezv rbp {hex(stack_base - 0x100)}")

        print(f"Stack mapped: {hex(stack_base - stack_size)}-{hex(stack_base)}")

    except Exception as e:
        print(f"Warning: Could not set up complete memory layout: {e}")
        # 回退到基本栈设置
        stack_base = 0x7fffffff0000
        stack_size = 0x10000
        rz_instance.cmd(f"aezm {hex(stack_base - stack_size)} {hex(stack_size)} rwx")
        rz_instance.cmd(f"aezv rsp {hex(stack_base - 0x100)}")


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
    Emulates a function using Rizin's RzIL for a number of steps and returns the trace.

    This function uses a separate thread to run the emulation, allowing for a
    timeout to prevent hangs on complex or infinite loops.

    Args:
        binary_path: The path to the binary file.
        function_name: The name of the function to emulate.
        max_steps: The maximum number of instructions to emulate.
        timeout: The maximum time in seconds to wait for the emulation to complete.

    Returns:
        A dictionary containing the emulation result, including 'success' status,
        'final_regs', 'trace' of execution steps, 'vm_changes' (VM state changes),
        'steps_executed', 'execution_time', and 'emulation_type'.
        If an error occurs or timeout is reached, an 'error' message is included.
    """
    with rz_lock: # Acquire lock before opening rzpipe
        rz = _open_rzpipe(binary_path)
        result_queue = queue.Queue()
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        future = executor.submit(_emulate_function_target_rzil, rz, function_name, max_steps, result_queue, timeout_seconds=timeout)

        try:
            return result_queue.get(timeout=timeout)
        except queue.Empty:
            return {"error": f"Emulation timed out after {timeout} seconds.", "success": False}
        except Exception as e:
            return {"error": f"An unexpected error occurred: {str(e)}", "success": False}
        finally:
            future.cancel()
            executor.shutdown(wait=False)
            rz.quit()


if __name__ == "__main__":
    binary_path = "/Users/yingdong/VSCode/angr/angr_ctf/00_angr_find/00_angr_find_arm"  # Example binary path
    function_name = "entry0"  # Example function name

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
    result = emulate_function(binary_path, function_name, max_steps=2, timeout=3600)
    print(json.dumps(result, indent=2))
