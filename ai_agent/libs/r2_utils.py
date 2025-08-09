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
import angr  # 用于补全 ELF base_addr/fallback 方案

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
            # Get basic block information (afbj: function basic blocks, JSON output)
            blocks_json = r2.cmd(f"afbj @ {function_name}")
            if not blocks_json:
                return []
            blocks_data = json.loads(blocks_json)

            # Get control flow graph edges (agj: graph, JSON output)
            edges_data = r2.cmdj(f"agj @ {function_name}")

            # Map block addresses to their data for easier lookup
            block_map = {b["addr"]: b for b in blocks_data}

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
            r2.quit()

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
def get_reachable_addresses(binary_path: str, start_addr: int) -> Dict[str, Any]:
    """
    基于 CFG，自动分析所有可达的成功/失败/出口块、不可达路径和循环结构（for angr find/avoid 提供依据）。
    Args:
        binary_path: 执行文件路径
        start_addr: 起始地址
    Returns:
        dict: {
            'success_addresses': [0x400200],
            'failure_addresses': [0x400300],
            'exit_points': [0x400400],
            'unreachable_from_start': [0x400500],
            'loops': [{'head': 0x400600, 'back_edge': 0x400650}]
        }
    """
    with r2_lock:
        r2 = _open_r2pipe(binary_path)
        try:
            # 获取含所有基本块和连接信息
            blocks = r2.cmdj(f"agfj @{start_addr}")
            if not blocks or not isinstance(blocks, list):
                return {
                    "success_addresses": [],
                    "failure_addresses": [],
                    "exit_points": [],
                    "unreachable_from_start": [],
                    "loops": []
                }
            node_map = {}
            edges = []
            for func in blocks:
                for bb in func.get("blocks", []):
                    addr = bb.get("offset")
                    node_map[addr] = bb
                    # outgoing edges
                    for dst in bb.get("jump", []) if isinstance(bb.get("jump"), list) else [bb.get("jump")]:
                        if dst is not None:
                            edges.append((addr, dst))
                    for dst in bb.get("fail", []) if isinstance(bb.get("fail"), list) else [bb.get("fail")]:
                        if dst is not None:
                            edges.append((addr, dst))

            # DFS 遍历，收集可达块、循环(back-edge)、不可达节点
            visited = set()
            parent = {}
            on_path = set()
            loops = []

            def dfs(addr):
                if addr in visited:
                    return
                visited.add(addr)
                on_path.add(addr)
                # 遍历 edges: jump/fail/branches
                bb = node_map.get(addr)
                for k in ['jump', 'fail', 'switch']:
                    dsts = bb.get(k)
                    if isinstance(dsts, list):
                        tgts = [d for d in dsts if d is not None]
                    else:
                        tgts = [dsts] if dsts is not None else []
                    for tgt in tgts:
                        if tgt not in visited:
                            parent[tgt] = addr
                            dfs(tgt)
                        elif tgt in on_path:
                            # back edge ==> loop
                            loops.append({"head": tgt, "back_edge": addr})
                on_path.remove(addr)

            if start_addr in node_map:
                dfs(start_addr)

            # 可达点/不可达点
            reachable = visited
            unreachable = set(node_map.keys()) - reachable

            # 分类出口
            success_addrs = []
            failure_addrs = []
            exit_points = []
            strings_cache = {}

            def get_cmt_or_str(addr):
                """提取该块是否有 Good/Flag/Fail 等字符串引用（性能优化：缓存本地块字符串）"""
                if addr in strings_cache:
                    return strings_cache[addr]
                bb = node_map.get(addr, {})
                instrs = bb.get("ops", [])
                foundstr = ""
                for op in instrs:
                    if "esil" in op and any(x in op["esil"] for x in ["Good", "GOOD", "FLAG", "SUCCESS", "TRY", "FAIL", "Again", "again"]):
                        foundstr = op["esil"]
                        break
                    if "comment" in op and any(x in op["comment"] for x in ["Good", "good", "FLAG", "Success", "Fail", "Try", "Again"]):
                        foundstr = op["comment"]
                        break
                strings_cache[addr] = foundstr
                return foundstr

            for addr in reachable:
                bb = node_map.get(addr, {})
                ops = bb.get("ops", [])
                if not ops:
                    continue
                last_op = ops[-1]
                # 判断成功/失败（含 "Good"/"Flag"/"Success"）
                cmt = get_cmt_or_str(addr)
                opstr = (last_op.get("opcode") or "") + " " + (last_op.get("disasm") or "")
                if any(x in cmt for x in ["Good", "GOOD", "FLAG", "Success"]):
                    success_addrs.append(addr)
                elif any(x in cmt for x in ["Fail", "fail", "Try", "Again"]):
                    failure_addrs.append(addr)
                elif "ret" in opstr or last_op.get("type") == "ret":
                    # 无法分类的通用出口
                    exit_points.append(addr)
                elif last_op.get("type") in ("trap", "invalid", "swi", "exit"):
                    exit_points.append(addr)

            return {
                "success_addresses": list(set(success_addrs)),
                "failure_addresses": list(set(failure_addrs)),
                "exit_points": list(set(exit_points)),
                "unreachable_from_start": list(unreachable),
                "loops": loops
            }
        finally:
            r2.quit()

def extract_static_memory(binary_path: str, addr: int, size: int) -> Dict[str, Any]:
    """
    读取给定虚拟地址静态内容&所属节区/权限（flag/秘钥硬编码场景），自动补救非ASCII自动编码推断。
    Args:
        binary_path
        addr
        size
    Returns:
        dict: {
            'content': b'HXUITWOA',
            'content_hex': '4858554954574f41',
            'content_string': 'HXUITWOA',
            'section': '.rodata',
            'permissions': 'r--'
        }
    """
    with r2_lock:
        r2 = _open_r2pipe(binary_path)
        try:
            # 读 bytes
            content_bytes = r2.cmdj(f"pxj {size} @ {addr}")
            if not content_bytes or not isinstance(content_bytes, list):
                content_bytes = []
            # auto-truncate trailing 0x00
            cut_bytes = bytes([b for b in content_bytes if isinstance(b, int)])  # 保守转换
            while cut_bytes and cut_bytes[-1] == 0:
                cut_bytes = cut_bytes[:-1]

            # 尝试多种方式解读
            try:
                s = cut_bytes.decode('utf-8')
            except Exception:
                try:
                    s = cut_bytes.decode('utf-16')
                except Exception:
                    try:
                        s = cut_bytes.decode('latin-1')
                    except Exception:
                        s = ""

            content_hex = cut_bytes.hex()

            # 节区 & 权限
            section = ""
            permissions = ""
            sections = r2.cmdj("iSj")
            found = False
            for sec in sections or []:
                vaddr = sec.get("vaddr", 0)
                vsize = sec.get("size", 0)
                if vaddr <= addr < vaddr + vsize:
                    section = sec.get("name", "")
                    permissions = sec.get("perm", "")
                    found = True
                    break

            return {
                "content": cut_bytes,
                "content_hex": content_hex,
                "content_string": s,
                "section": section,
                "permissions": permissions
            }
        finally:
            r2.quit()

def generate_angr_template(path_to_binary: str, analysis_goal: str = "find_path") -> Dict[str, Any]:
    """
    给定基本参数，自动生成包含 angr.Project/State/Simgr/Explore 核心流程的 python 框架，部分步骤以 TODO 标注补充点，便于新分析任务快速“开箱即用”。
    该模板强制仅从 config.yaml.angr_templates 加载，相应字段缺失或解析失败直接抛出异常。
    """
    import os
    import yaml
    config_path = os.path.join(os.path.dirname(__file__), "../config.yaml")
    with open(config_path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)
    angr_templates = config.get("angr_templates", None)
    if not angr_templates:
        raise RuntimeError("No 'angr_templates' section found in config.yaml")
    key = analysis_goal if analysis_goal in angr_templates else "other"
    if key not in angr_templates:
        raise RuntimeError(f"No template found for analysis_goal='{analysis_goal}' in config.yaml[angr_templates]")
    code_template = angr_templates[key]
    if "{binary_path}" not in code_template:
        raise RuntimeError("The template string must contain the '{binary_path}' placeholder")
    code = code_template.replace("{binary_path}", path_to_binary)
    return {"template_code": code}

def get_binary_info(binary_path: str) -> Dict[str, Any]:
    """
    提取二进制基础信息，供 angr/脚本初始化分析，包括架构/端序/入口/基址/PIE/strip/节区表/PLT/GOT 表。
    Args:
        binary_path: ELF、PE或Mach-O文件路径
    Returns:
        dict: {
            'arch': 'x86_64',
            'bits': 64,
            'endian': 'little',
            'entry_point': 0x400000,
            'base_addr': 0x400000,
            'is_pie': False,
            'is_stripped': False,
            'binary_type': 'ELF',
            'sections': [{'name': '0.__TEXT.__text', 'addr': 4294968568, 'size': 396, 'perm': '-r-x'}, ...],
            'plt_entries': {'printf': 0x400100},
            'got_entries': {'printf': 0x601000}
        }
    """
    with r2_lock:
        r2 = _open_r2pipe(binary_path)
        try:
            result = {
                "arch": None,
                "bits": None,
                "endian": None,
                "entry_point": None,
                "base_addr": None,
                "is_pie": None,
                "is_stripped": None,
                "binary_type": None,
                "sections": [],
                "plt_entries": {},
                "got_entries": {}
            }
            ij = r2.cmdj("ij")
            entryinfo = r2.cmdj("iej")[0]
            if not ij or not isinstance(ij, dict) or not entryinfo or not isinstance(entryinfo, dict):
                return result

            # 基本信息
            bininfo = ij.get("bin", {})

            result["arch"] = bininfo.get("arch", "x86_64")
            result["bits"] = bininfo.get("bits", 64)
            result["endian"] = bininfo.get("endian", "little")
            result["entry_point"] = entryinfo.get("vaddr")
            result["binary_type"] = bininfo.get("bintype")
            result["base_addr"] = bininfo.get("baddr", 0)  # 可能为0，后续用 angr 补全

            # PIE/strip
            result["is_pie"] = bininfo.get("pic", False)
            result["is_stripped"] = bininfo.get("stripped", False)

            # 节区
            sections = r2.cmdj("iSj")
            if sections and isinstance(sections, list):
                result["sections"] = [
                    {
                        "name": s.get("name"),
                        "addr": s.get("vaddr"),
                        "size": s.get("size"),
                        "perm": s.get("perm", "----")
                    } for s in sections if s.get("name") and s.get("vaddr") != 0 and s.get("size") != 0
                ]
            # PLT entries
            result["plt_entries"] = {}
            # 拉取 PLT/GOT 有不同方法：ELF 用 afl~plt，符号表及导入重定向也可补全
            try:
                aflj = r2.cmdj("aflj")
                for f in aflj or []:
                    if f.get("name", "").startswith("sym.imp."):
                        name = f["name"].replace("sym.imp.", "")
                        result["plt_entries"][name] = f["addr"]
            except Exception:
                pass

            # GOT entries（全局偏移表）
            # === 基于区段范围识别 GOT 槽 ===
            result.setdefault("got_entries", {})

            # 1) 从已有的 result["sections"] 中构建 “GOT 相关区段” 的地址区间
            got_ranges = []
            for s in result.get("sections", []):
                n = s.get("name") or ""
                # ELF: .got / .got.plt
                # Mach-O: __DATA,__la_symbol_ptr / __DATA_CONST,__got / 兼容 __DATA.__got
                if (
                    n.endswith(".got") or n.endswith(".got.plt") or
                    n.endswith("__DATA.__la_symbol_ptr") or
                    n.endswith("__DATA_CONST.__got") or
                    n.endswith("__DATA.__got")
                ):
                    lo = s.get("addr"); sz = s.get("size") or 0
                    if lo and sz:
                        got_ranges.append((lo, lo + sz))

            def in_got(addr: int) -> bool:
                return any(lo <= addr < hi for lo, hi in got_ranges)

            # 2) 用 isj 列符号，按 vaddr 落区间筛选（注意：并非所有 GOT 槽都有“符号名”，这里只抓得到名字的）
            try:
                for sym in r2.cmdj("isj") or []:
                    va = sym.get("vaddr")
                    if va and in_got(va):
                        name = sym.get("name") or sym.get("realname")
                        if name:
                            result["got_entries"][name] = va
            except Exception:
                pass

            # base_addr（部分场景用 angr 更为准确，尤其 PIE）
            try:
                proj = angr.Project(binary_path, auto_load_libs=False)
                result["base_addr"] = getattr(proj.loader.main_object, "min_addr", result["entry_point"])
            except Exception:
                # 兜底用 entry_point
                if result["base_addr"] in (0, None):
                    result["base_addr"] = result.get("entry_point")
            return result
        finally:
            r2.quit()

def _emulate_function_target(r2_instance, function_name, max_steps, result_queue):
    """
    Target function for threaded ESIL emulation to allow for timeouts.

    This function is intended to be run in a separate thread. It initializes
    ESIL, steps through the function's instructions, and records the trace.

    Args:
        r2_instance: An active r2pipe instance.
        function_name: The name of the function to emulate.
        max_steps: The maximum number of instructions to emulate.
        result_queue: A queue to store the final result or error.
    """
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
    with r2_lock: # Acquire lock before opening r2pipe
        r2 = _open_r2pipe(binary_path)
        result_queue = queue.Queue()
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        future = executor.submit(_emulate_function_target, r2, function_name, max_steps, result_queue)

        try:
            result = result_queue.get(timeout=timeout)
            if "error" in result:
                return {"success": False, "error": result["error"]}
            return result
        except queue.Empty:
            return {"success": False, "error": f"Emulation timed out after {timeout} seconds."}
        except Exception as e:
            return {"success": False, "error": f"An unexpected error occurred: {str(e)}"}
        finally:
            future.cancel()
            executor.shutdown(wait=False)
            r2.quit()

if __name__ == "__main__":
    import argparse
    import json
    import textwrap

    parser = argparse.ArgumentParser(description="Quick test for r2_utils new RE functions")
    parser.add_argument("-b", "--binary", type=str, default="00_angr_find/00_angr_find_arm", help="Path to binary")
    parser.add_argument("--print-template-lines", type=int, default=20, help="Lines to print for angr template")
    args = parser.parse_args()
    bin_path = args.binary

    print("=" * 40)
    print(f"[1] get_binary_info('{bin_path}')")
    try:
        info = get_binary_info(bin_path)
        print(json.dumps(info, indent=2, default=str))
    except Exception as e:
        print(f"ERROR: {e}")

    print("=" * 40)
    print(f"[2] get_reachable_addresses('{bin_path}', entry_point)")
    try:
        entry = info.get("entry_point", None)
        if entry is None:
            raise ValueError("entry_point missing in get_binary_info()")
        res = get_reachable_addresses(bin_path, entry)
        print(f"Success: {len(res['success_addresses'])}  Fails: {len(res['failure_addresses'])}  Exits: {len(res['exit_points'])}  Loops: {len(res['loops'])}  Unreachable: {len(res['unreachable_from_start'])}")
        print(json.dumps(res, indent=2, default=str))
    except Exception as e:
        print(f"ERROR: {e}")

    print("=" * 40)
    print(f"[3] extract_static_memory('{bin_path}', address_of_first_string_in_rodata, 16)")
    try:
        # 优先找.sections中的.rodata，然后找strings落在其中的第一个
        rodata_addr = None
        rodata_size = None
        for s in info.get("sections", []):
            if ".rodata" in s.get("name", "") or "cstring" in s.get("name", ""):
                rodata_addr = s["addr"]
                rodata_size = s["size"]
                break
        if rodata_addr is None:
            raise ValueError("No .rodata or cstring section found")
        # 获取所有字符串并筛选
        strings = get_strings(bin_path)
        str_addr = None
        str_val = None
        for st in strings:
            va = st.get("vaddr", 0)
            sval = st.get("string", "")
            if rodata_addr <= va < rodata_addr + (rodata_size or 0):
                str_addr = va
                str_val = sval
                break
        if str_addr is None:
            raise ValueError("No string found in .rodata/cstring")
        res = extract_static_memory(bin_path, str_addr, 16)
        print(f"String chosen: {str_val} @ 0x{str_addr:x}")
        print(json.dumps(res, indent=2, default=str))
    except Exception as e:
        print(f"ERROR: {e}")

    print("=" * 40)
    print(f"[4] generate_angr_template('{bin_path}', 'find_path')")
    try:
        res = generate_angr_template(bin_path, "find_path")
        lines = res["template_code"].splitlines()
        for i, l in enumerate(lines):
            if i >= args.print_template_lines:
                print("(...truncated...)")
                break
            print(l)
    except Exception as e:
        print(f"ERROR: {e}")
