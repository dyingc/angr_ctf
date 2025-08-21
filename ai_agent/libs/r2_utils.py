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

from typing import Any, Dict, List, Set, Literal, Optional

# Global lock for r2pipe operations to prevent race conditions
r2_lock = threading.Lock()

def _open_r2pipe(binary_path: str, analyze: bool = True) -> r2pipe.open:
    """
    Opens an r2pipe instance for a given binary and performs initial analysis.

    Args:
        binary_path: The path to the binary file.

    Returns:
        An initialized r2pipe instance after running 'aaa' analysis and disabling color.
    """
    r2 = r2pipe.open(binary_path)
    if analyze:
        r2.cmd("e scr.color=0; aaa")  # Disable color, perform auto-analysis
    else:
        r2.cmd("e scr.color=0")
    return r2

def _resolve_address(binary_path: str, expr: int | str) -> Optional[int]:
    """
    Resolves an address expression to an absolute address.

    Args:
        expr: The expression to resolve, can be an integer address or a string.

    Returns:
        The resolved absolute address or None if it cannot be resolved.
    """
    if isinstance(expr, int):
        return expr

    with r2_lock:
        r2 = _open_r2pipe(binary_path, analyze=True)
        try:
            addr = r2.cmd(f"?v {expr}")
            if addr:
                return int(addr, 16)
        finally:
            r2.quit()

    return None

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
                graph_data = r2.cmdj(f"agcj @ {function_name}")
            else:
                # Get global call graph, JSON output
                graph_data = r2.cmdj("agCj")

            if not graph_data:
                return {"nodes": [], "edges": []}

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
                    nodes.append({"name": node["name"], "addr": node.get("addr", node.get("offset"))})
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
            block_map = {b.get("addr", b.get("offset")): b for b in blocks_data}

            formatted_blocks = []

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

def get_reachable_addresses(
    binary_path: str,
    start_addr_expr: str | int,
    entry_mode: Literal["function", "block"] = "function",
) -> Dict[str, Any]:
    """
    从给定地址开始分析其所在函数的控制流图（CFG），返回一份**高信息密度且跨架构通用**的摘要，
    便于自动化逆向工程与基于 LLM 的推理/规划。

    设计目标
    --------
    - 以“包含 start_addr_expr 的**整个函数**”为分析范围（不随 entry_mode 改变），
    统一抽取路径可达性、出口点、调用点、间接跳转、switch 与字符串引用等关键信息。
    - 出口点（exit_points）的定义是从“**当前函数视角**”出发：当块的所有后继都离开本函数，
    或该块为显式终止（ret/trap/invalid/swi），则视为函数内的**终点**（覆盖尾跳/PLT stub 等）。
    - 结果尽量简洁，但足以支撑常见的 find/avoid、路径裁剪、模糊测试与交互式溯源等任务。

    入口模式
    --------
    - ``function``：起点为函数入口基本块（分析范围仍是该函数的全部基本块）。
    - ``block``：起点为“包含 start_addr_expr 的基本块”（分析范围同上，只改变遍历起点）。

    Parameters
    ----------
    binary_path : str
        二进制文件路径。
    start_addr_expr : str | int
        起始地址（可为整数地址或 r2 可解析的表达式，如符号名/偏移等，如：`0x400100`或`main+0x10`或`4194560`等等）。内部会解析并归一化到所属函数/块。
    entry_mode : {"function", "block"}, optional
        遍历起点模式；默认为 "function"。仅影响 DFS 的起点，不改变分析范围。

    Returns
    -------
    dict
        返回一个包含以下键的字典（所有地址为整型虚拟地址）：

        - ``entry_block`` (int | None)
            实际使用的遍历起点基本块地址。
        - ``exit_points`` (List[Dict[str, Any]])
            函数内“必然终止”块集合。每项形如
            ``{"addr": <block_addr>, "reason": "<ret|trap|invalid|swi|no_successor|external_jump>"} ``。
            - ``external_jump``：该块所有后继均不在本函数内（典型尾跳/跳至导入桩等）。
            - 该定义与架构无关（x86 的 jmp、AArch64 的 b/br 等均适用）。
        - ``partial_exits`` (List[Dict[str, Any]])
            既有指向函数内的后继、又有指向函数外的后继的块，用于标注“可能逃逸”分支。
            形如 ``{"addr": <block_addr>, "out_of_func_targets": [<addr> ...]}``。
        - ``unreachable_from_start`` (List[int])
            在本函数中、但从所选起点**不可达**的基本块地址列表。
        - ``loops`` (List[Dict[str, int]])
            检测到的循环回边，形如 ``{"head": <loop_header_addr>, "back_edge": <source_addr>}``。
        - ``callsites`` (List[Dict[str, Any]])
            调用点摘要。每项形如
            ``{"addr": <insn_addr>, "callee": <str|None>, "target": <int|None>, "indirect": <bool>, "import": <bool>}``。
            - ``indirect``：是否为间接调用或未解析到静态目标。
            - ``import``：callee 名称是否看起来是导入符号（如 ``sym.imp.*`` / ``imp.*``）。
        - ``indirect_jumps`` (List[Dict[str, Any]])
            间接跳转摘要。每项至少包含 ``{"addr": <insn_addr>}``，若能静态取到潜在目标，
            会补充 ``targets_in_func`` 与 ``targets_out_func``（均为地址列表）。
        - ``switches`` (List[Dict[str, Any]])
            switch 信息，形如 ``{"addr": <block_addr>, "cases": [<addr> ...], "default": <addr|None>}``。
        - ``string_refs_in_func`` (List[Dict[str, Any]])
            命中在本函数内的字符串引用点，形如 ``{"ref_addr": <insn_addr>, "ref_function": <str>, "ref_instruction": <str>, "string_value": <str>}``。
            （内部对字符串数量与每个字符串的引用数做了轻量限速，以避免性能问题。）
        - ``summary`` (Dict[str, int])
            汇总计数：``{"reachable_count": N, "unreachable_count": M, "exit_count": K, "loop_count": L}``。

    Example
    -------
    >>> get_reachable_addresses("/path/to/binary", 0x400100, entry_mode="function")
    {
        "entry_block": 4198400,
        "exit_points": [
            {"addr": 4198464, "reason": "ret"},
            {"addr": 4198496, "reason": "external_jump"}
        ],
        "partial_exits": [
            {"addr": 4198452, "out_of_func_targets": [4199000]}
        ],
        "unreachable_from_start": [4198528],
        "loops": [
            {"head": 4198400, "back_edge": 4198448}
        ],
        "callsites": [
            {"addr": 4198440, "callee": "sym.imp.printf", "target": 4199936, "indirect": false, "import": true}
        ],
        "indirect_jumps": [
            {"addr": 4198456, "targets_in_func": [], "targets_out_func": []}
        ],
        "switches": [
            {"addr": 4198460, "cases": [4198472, 4198480], "default": 4198488}
        ],
        "string_refs_in_func": [
            {"ref_addr": 4198468, "ref_function": "main", "ref_instruction": "add x1, x1, str.Good_Job._n", "string_value": "Good Job"},
            {"ref_addr": 4198476, "ref_function": "main", "ref_instruction": "add x1, x1, str.Try_again._n", "string_value": "Try again"}
        ],
        "summary": {
            "reachable_count": 12,
            "unreachable_count": 1,
            "exit_count": 2,
            "loop_count": 1
        }
    }

    Notes
    -----
    - 需先在 radare2 中完成 ``aaa`` 自动分析；内部主要依赖 ``agfj/afbj/pdj/izj/axtj`` 等输出。
    - “出口点”采用**函数内视角**定义：当块不再返回到本函数（如 ret、trap 或全部后继离开本函数）即视为出口。
    - 为兼顾性能，字符串枚举与引用关系提取做了简单限速（如最多 2000 条字符串、每串至多 50 个引用点）。
    - 本函数为**最小噪音**摘要，不提供完整 CFG 或前驱/后继映射；若需全量结构，请使用更详细的图导出流程。
    """
    start_addr_int = _resolve_address(binary_path, start_addr_expr)

    with r2_lock:
        r2 = _open_r2pipe(binary_path)
        result =  {
            "entry_block": None,
            "exit_points": [],
            "partial_exits": [],
            "unreachable_from_start": [],
            "loops": [],
            "callsites": [],
            "indirect_jumps": [],
            "switches": [],
            "string_refs_in_func": [],
            "summary": {
                "reachable_count": 0,
                "unreachable_count": 0,
                "exit_count": 0,
                "loop_count": 0
            }
        }
        try:
            # 1) 取“包含 start_addr 的函数”的图（agfj）
            funcs_or_obj = r2.cmdj(f"agfj @{start_addr_int}")
            if not funcs_or_obj:
                return result

            funcs = funcs_or_obj if isinstance(funcs_or_obj, list) else [funcs_or_obj]
            f0 = funcs[0] if funcs else {}
            blocks = f0.get("blocks", []) or []
            f_entry = f0.get("addr", f0.get("offset"))

            # 2) 建块表（addr -> block）
            node_map: Dict[int, Dict[str, Any]] = {}
            for bb in blocks:
                a = bb.get("addr", bb.get("offset"))
                if isinstance(a, int):
                    node_map[a] = bb

            if not node_map:
                return result

            # 3) 归一化遍历起点
            def _find_block_head_containing(addr: int) -> Optional[int]:
                b = r2.cmdj(f"abj @ {addr}")
                if b and isinstance(b, list):
                    return b[0].get("addr", b[0].get("offset"))
                return None

            if entry_mode == "function" and isinstance(f_entry, int) and f_entry in node_map:
                entry_block_addr = f_entry
            elif entry_mode == "block":
                entry_block_addr = _find_block_head_containing(start_addr_int) or f_entry
            else:
                entry_block_addr = f_entry

            if entry_block_addr not in node_map:
                # 起点异常：保守返回不可达=全体
                result['entry_block'] = entry_block_addr
                result['unreachable_from_start'] = sorted(node_map.keys())
                result['summary']['unreachable_count'] = len(node_map)
                return result

            # 4) 后继枚举（jump/fail/switch 合并）
            def _succ_iter(bb: Dict[str, Any]) -> List[int]:
                succs: List[int] = []
                for k in ("jump", "fail", "switch"):
                    v = bb.get(k)
                    if isinstance(v, list):
                        succs.extend([d for d in v if isinstance(d, int)])
                    elif isinstance(v, int):
                        succs.append(v)
                # 去重（保持顺序）
                return list(dict.fromkeys(succs))

            # 5) DFS 遍历 + 循环检测
            visited: Set[int] = set()
            on_path: Set[int] = set()
            loops: List[Dict[str, int]] = []

            def dfs(a: int) -> None:
                """
                深度优先遍历可达基本块，并检测控制流中的循环回边。

                该函数不返回值，遍历结果会直接更新外层作用域中的状态变量：
                - visited: 记录所有已访问的基本块地址（可达集合）
                - loops: 记录检测到的循环回边
                - on_path: 递归时用于循环检测的当前路径集合（函数结束时会清空）

                参数
                ----
                a : int
                    当前要遍历的基本块（block）的起始地址。

                逻辑说明
                --------
                1. 若当前块 a 已在 visited 中，说明之前访问过，直接返回。
                2. 将 a 加入 visited（已访问）和 on_path（当前路径）。
                3. 遍历该块的所有后继（来自 jump / fail / switch）：
                - 若后继未访问过 → 递归调用 dfs 继续遍历。
                - 若后继已在 on_path 中 → 检测到循环，记录到 loops 列表：
                    {"head": 循环入口地址, "back_edge": 回边源地址}
                4. 回溯时将 a 从 on_path 中移除。

                执行后的变化
                ------------
                - visited 会包含从初始入口可达的所有基本块地址。
                - loops 会追加检测到的所有循环回边信息。
                - on_path 结束时会被清空，仅在递归过程中有值。

                示例（执行过程快照）
                -------------------
                图（边集）：
                    A → B,  B → C,  B → D,  D → A  （D 回到 A 形成环）

                执行过程：
                    • 初始：visited = {}, on_path = {}
                    • 进入 A：visited = {A}, on_path = {A}
                    • 进入 B：visited = {A,B}, on_path = {A,B}
                    • 先走 C：visited = {A,B,C}, on_path = {A,B,C}
                    • C 无后继或都处理完 → 回溯：on_path = {A,B}
                    • 再走 D：visited = {A,B,C,D}, on_path = {A,B,D}
                    • D 的后继是 A，A 已在 on_path → 记录循环 {"head": A, "back_edge": D}
                    • D 处理完回溯：on_path = {A,B}
                    • B 处理完回溯：on_path = {A}
                    • A 处理完回溯：on_path = {}（空）

                最终状态：
                    • visited = {A,B,C,D}（从 A 出发都能到）
                    • loops = [{"head": A, "back_edge": D}]（检测到 D→A 的回边）
                    • on_path = {}（遍历结束，回溯清空）
                """
                if a in visited:
                    return
                visited.add(a)
                on_path.add(a)
                for tgt in _succ_iter(node_map.get(a, {})):
                    if tgt in node_map:
                        if tgt not in visited:
                            dfs(tgt)
                        elif tgt in on_path:
                            loops.append({"head": tgt, "back_edge": a})
                on_path.remove(a)

            dfs(entry_block_addr)

            reachable = visited
            unreachable = sorted(set(node_map.keys()) - reachable)

            # 6) 出口点 / 部分出口判定（跨架构通用）
            exit_points: List[Dict[str, Any]] = []
            partial_exits: List[Dict[str, Any]] = []

            def _exit_reason(bb: Dict[str, Any]) -> Optional[str]:
                ops = bb.get("ops", []) or []
                last = ops[-1] if ops else {}
                typ = (last.get("type") or "").lower()
                opstr = f"{last.get('opcode','')} {last.get('disasm','')}".strip().lower()

                succs = _succ_iter(bb)
                succs_in_func = [s for s in succs if s in node_map]

                # 明确终止类
                if typ == "ret" or " ret" in f" {opstr} ":
                    return "ret"
                if typ in ("trap", "invalid", "swi", "exit"):
                    return typ
                # 无任何后继
                if not succs:
                    return "no_successor"
                # 全部后继离开本函数（尾跳/外跳）
                if not succs_in_func:
                    # 更明确些：若最后指令是 jmp/ujmp/ijmp/尾调用
                    if "jmp" in typ:
                        return "external_jump"
                    return "external_jump"
                return None  # 不是出口（未离开函数）

            for a in sorted(reachable):
                bb = node_map.get(a, {})
                reason = _exit_reason(bb)
                if reason:
                    exit_points.append({"addr": a, "reason": reason})
                else:
                    # 检查“部分出口”：有些后继在函数内，但也有后继在函数外
                    succs = _succ_iter(bb)
                    if succs:
                        in_func = [s for s in succs if s in node_map]
                        out_func = [s for s in succs if s not in node_map]
                        if in_func and out_func:
                            partial_exits.append({
                                "addr": a,
                                "out_of_func_targets": out_func
                            })

            # 7) 调用点、间接跳转、switch 汇总（从块的 ops 中抓取）
            callsites: List[Dict[str, Any]] = []
            indirect_jumps: List[Dict[str, Any]] = []
            switches: List[Dict[str, Any]] = []

            # 构造“函数内地址集合”，便于快速判断目标是否在函数内
            in_func_addrs = set(node_map.keys())

            # 快速判断“导入符号”名称
            # 通过符号名前缀约定（radare2 常见：sym.imp.* / imp.*）
            def _is_import_name(name: Optional[str]) -> bool:
                if not name:
                    return False
                n = name.lower()
                return n.startswith("sym.imp.") or n.startswith("imp.")

            # 为了找 op 的潜在目标（静态直跳/直调），尽量从 op 的元字段里取地址
            def _op_target_addr(op: Dict[str, Any]) -> Optional[int]:
                # r2 的 pdj/ops 里常见：jump（直达目标）、ptr/val（间接经静态可解）、eaddr、target（偶见）
                for k in ("jump", "ptr", "val", "eaddr", "target"):
                    v = op.get(k)
                    if isinstance(v, int):
                        return v
                # 有些 disasm 会在 'reloc' 或 'xrefs' 中携带目标，这里保持简洁不做深挖
                return None

            functions = r2.cmdj("aflj") or []
            # 预处理：addr -> function dict（放在循环外构建一次）
            func_by_addr = {f.get("addr", f.get("offset")): f for f in (functions or []) if isinstance(f.get("addr", f.get("offset")), int)}
            # 预先算好函数/块的区间，便于“包含判断”
            func_ranges = [(bb.get("addr", bb.get("offset")), bb.get("addr", bb.get("offset")) + (bb.get("size") or 0)) for bb in blocks if isinstance(bb.get("addr", bb.get("offset")), int)]
            def _in_func(frm: int) -> bool:
                # 快速路径：fcn_addr 直接等于当前函数入口
                # 注意：axtj 的 ref 可能没这个字段；有则 O(1)，没有再做区间判断
                return any(lo <= frm < hi for (lo, hi) in func_ranges)

            entry_block_size = (node_map.get(entry_block_addr, {}) or {}).get("size") or 0
            def _in_entry_block(frm: int) -> bool:
                return entry_block_addr is not None and entry_block_size > 0 and (entry_block_addr <= frm < entry_block_addr + entry_block_size)

            for bb in blocks:
                ops = bb.get("ops", []) or []

                # switch 信息直接来自 block 的 switch 字段
                sw = bb.get("switch")
                if sw:
                    cases = []
                    default = None
                    # r2 的 agfj/switch 结构可能是 {"cases":[addr,...], "defaddr":...} 或类似
                    c1 = sw.get("cases") or []
                    for c in c1:
                        if isinstance(c, int):
                            cases.append(c)
                        elif isinstance(c, dict) and (("addr" in c and isinstance(c["addr"], int)) or ("offset" in c and isinstance(c["offset"], int))):
                            cases.append(c.get("addr", c.get("offset")))
                    if isinstance(sw.get("defaddr"), int):
                        default = sw["defaddr"]
                    switches.append({
                        "addr": bb.get("addr", bb.get("offset")),
                        "cases": cases,
                        "default": default
                    })

                for op in ops:
                    typ = (op.get("type") or "").lower()
                    dis = (op.get("disasm") or "").lower()
                    a = op.get("addr", op.get("offset"))

                    # 调用点
                    if typ in ("call", "ucall", "icall"):
                        tgt = _op_target_addr(op)

                        callee_name = None
                        is_import = False
                        is_noreturn = False

                        if isinstance(tgt, int):
                            f = func_by_addr.get(tgt)
                            if f:
                                callee_name = f.get("name")
                                is_noreturn = bool(f.get("noreturn"))
                                is_import = _is_import_name(callee_name)
                        # 回退：有些情况下 r2 会在 op 里给出符号名，但没有可解析的数值目标
                        if not callee_name:
                            callee_name = op.get("call")  # 可能是 'sym.imp.printf'
                            is_import = _is_import_name(callee_name)

                        callsites.append({
                            "addr": a,
                            "callee": callee_name,     # 可能为 None
                            "target": tgt,             # 可能为 None（间接）
                            "indirect": typ in ("ucall", "icall") or (tgt is None),
                            "import": is_import,
                            "noreturn": is_noreturn,   # 新增：对后续路径裁剪很有用
                        })

                    # 间接跳转
                    if typ in ("ijmp", "ujmp") or (" br" in f" {dis} " and "ret" not in dis):
                        tgt = _op_target_addr(op)
                        record = {"addr": a}
                        if tgt is not None:
                            record["targets_in_func"] = [tgt] if tgt in in_func_addrs else []
                            record["targets_out_func"] = [tgt] if tgt not in in_func_addrs else []
                        else:
                            record["targets_in_func"] = []
                            record["targets_out_func"] = []
                        indirect_jumps.append(record)

            # 8) 作用域内的字符串引用（函数/块作用域可选）
            string_refs_in_func: List[Dict[str, Any]] = []
            try:
                strings = r2.cmdj("izj") or []
                strings = strings[:2000]  # 轻量限速
                for s in strings:
                    va = s.get("vaddr")
                    sval = s.get("string")
                    if not isinstance(va, int) or not sval:
                        continue
                    refs = r2.cmdj(f"axtj @ {va}") or []
                    for ref in refs[:50]:  # 每个字符串最多 50 个引用
                        frm = ref.get("from")
                        if not isinstance(frm, int):
                            continue

                        keep = False
                        if entry_mode == "function":
                            # 1) 优先用 ref.fcn_addr 判断是否为当前函数
                            fa = ref.get("fcn_addr")
                            if isinstance(fa, int) and isinstance(f_entry, int):
                                keep = (fa == f_entry)
                            else:
                                # 2) 回退：用 “frm 是否落在本函数任一基本块区间”
                                keep = _in_func(frm)
                        else:  # entry_mode == "block"
                            keep = _in_entry_block(frm)

                        if keep:
                            string_refs_in_func.append({
                                "ref_addr": frm,                    # 指令地址
                                "ref_function": ref.get("fcn_name"),# 所在函数
                                "ref_instruction": ref.get("opcode"),# 指令文本
                                "string_value": sval                 # 引用的字符串内容
                            })
                # 去重：按 (addr, string)
                seen = set()
                deduped = []
                for it in string_refs_in_func:
                    key = (it["ref_addr"], it["ref_function"], it["ref_instruction"], it["string_value"])
                    if key not in seen:
                        seen.add(key)
                        deduped.append(it)
                string_refs_in_func = deduped
            except Exception:
                # 字符串解析失败就留空，不影响主流程
                string_refs_in_func = []

            # 9) 汇总计数
            summary = {
                "reachable_count": len(reachable),
                "unreachable_count": len(unreachable),
                "exit_count": len(exit_points),
                "loop_count": len(loops),
            }

            # 10) 返回整理
            result['entry_block'] = entry_block_addr
            result['exit_points'] = exit_points
            result['partial_exits'] = partial_exits
            result['unreachable_from_start'] = unreachable
            result['loops'] = loops
            result['callsites'] = callsites
            result['indirect_jumps'] = indirect_jumps
            result['switches'] = switches
            result['string_refs_in_func'] = string_refs_in_func
            result['summary'] = summary
            return result
        finally:
            r2.quit()

def extract_static_memory(binary_path: str, addr_expr: int | str, size: int) -> Dict[str, Any]:
    """
    读取给定虚拟地址静态内容&所属节区/权限（flag/秘钥硬编码场景），自动补救非ASCII自动编码推断。
    Args:
        binary_path
        addr_expr - 虚拟地址或地址表达式，如：0x1000，"0x1000"，"main + 0x10"
        size
    Returns:
    >>> extract_static_memory("/path/to/binary", 0x1000, 64)
    {
        'content_bytes' = ['0x54', '0x72', '0x79', '0x20', '0x61', '0x67', '0x61', '0x69', '0x6e', '0x2e', '0xa', '0x0', '0x45', '0x6e', '0x74', '0x65']
        'content' = b'Try again.\n'
        'content_hex' = '54727920616761696e2e0a'
        'content_string' = 'Try again.\n'
        'section' = '2.__TEXT.__cstring'
        'permissions' = '-r-x'
    }
    """
    addr = _resolve_address(binary_path, addr_expr)
    with r2_lock:
        r2 = _open_r2pipe(binary_path, analyze=False)
        try:
            # 读 bytes
            content_bytes = r2.cmdj(f"pxj {size} @ {addr}")
            if not content_bytes or not isinstance(content_bytes, list):
                content_bytes = []
            # auto-truncate trailing 0x00
            cut_bytes = []
            content_hex = ""
            for c in content_bytes:
                if c == 0:
                    break
                cut_bytes.append(c)
            if cut_bytes:
                cut_bytes = bytes([b for b in cut_bytes if isinstance(b, int)])  # 保守转换
                content_hex = cut_bytes.hex()
            else:
                cut_bytes = b""

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

            # 节区 & 权限
            section = None
            permissions = None
            sections = r2.cmdj("iSj")
            for sec in sections or []:
                vaddr = sec.get("vaddr", 0)
                vsize = sec.get("size", 0)
                if vaddr <= addr < vaddr + vsize:
                    section = sec.get("name", "")
                    permissions = sec.get("perm", "")
                    break

            return {
                "content_bytes": [hex(h) for h in content_bytes],
                "content": cut_bytes,
                "content_hex": content_hex,
                "content_string": s,
                "section": section,
                "permissions": permissions
            }
        finally:
            r2.quit()

def generate_angr_template(path_to_binary: str, analysis_goal: str) -> Dict[str, Any]:
    """
    Fetch an angr code template by analysis goal.

    IMPORTANT:
    - The returned code is a TEMPLATE, not a ready-to-run script. Do NOT copy/paste and run it as-is.
    - Craft the final angr script using your RE findings (CFG/Strings/symbols/calling convention/I-O model).
      At minimum, customize: target/avoid addresses or success conditions, input sizes/constraints, hooks,
      and any arch-specific registers or function prototypes.

    Args:
    - path_to_binary (str, required): Path to the binary. This will be interpolated into the template code.
    - analysis_goal (str, required): Exact key under `angr_templates` in the YAML (see supported values).

    Supported `analysis_goal`:
    • path_search — Reach a target (addr or condition) while optionally avoiding addresses.
    • state_debug — Inspect/manipulate stashes and print recent constraints at breakpoints.
    • exploration_perf — Add DFS/BFS strategies, LoopSeer/Veritesting/Unicorn, and cap state count.
    • memory_init — Zero-fill defaults, map a scratch page, constrain bytewise secrets, light per-arch setup.
    • input_modeling — Model stdin/argv/env/file plus targeted regs/memory in one place.
    • function_call — Execute a function with concrete/symbolic args; collect return/outputs (arch-aware).
    • concolic_seed — Preconstrain stdin with a seed; optionally remove preconstraints later.
    • api_hooks — Hook libc (strcmp/strlen/printf/malloc/free) and add custom SimProcedures as needed.
    • vuln_detection — Heuristics to flag symbolic RET or stack canary tamper under large stdin.
    • taint_tracking — Track tainted stdin to sinks (system/execve/strcpy) with arch-specific arg0.
    • rop_chain — Find gadgets and build system/execve chains via angrop; payload matches current arch.
    • deobfuscation — Skip common NOPs (x86/x64 0x90, ARM64 0xD503201F) and search for “flag”.
    • protocol_reverse — Find recv/read handlers, set (buf,size) across arches, infer fields, fuzz flips.
    • general_analysis — Parametric harness (timeouts, techniques) returning a structured results dict.

    Architecture support:
    ARM64 (AArch64), x64 (AMD64), and x86 (32-bit) are handled where calling conventions, return registers,
    and NOP/stack conventions matter. Templates include safe defaults and degrade gracefully when a feature
    isn’t applicable.

    Returns:
    dict: {"template_code": "<string with the binary_path already injected>"}
    """
    import os
    import yaml
    config_path = os.path.join(os.path.dirname(__file__), "../angr_templates.yaml")
    with open(config_path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)
    angr_templates = config.get("templates", None)
    if not angr_templates:
        raise RuntimeError("No 'angr templates' section found in angr_templates.yaml")
    key = analysis_goal if analysis_goal in angr_templates else "other"
    if key not in angr_templates:
        raise RuntimeError(f"No template found for analysis_goal='{analysis_goal}' in angr_templates.yaml[angr_templates]")
    code_template = angr_templates[key]
    if "{binary_path}" not in code_template:
        raise RuntimeError("The template string must contain the '{binary_path}' placeholder")
    code = code_template.replace("{binary_path}", path_to_binary)
    return {"template_code": code}

def get_binary_info(binary_path: str) -> Dict[str, Any]:
    """
    提取二进制基础信息，供 angr/脚本初始化分析，包括架构/端序/入口/基址/PIE/strip/节区表/PLT/GOT 表。
    Args:
        binary_path: ELF或Mach-O文件路径
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
                        result["plt_entries"][name] = f.get("addr", f.get("offset"))
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
                    lo = s.get("addr", s.get("offset")); sz = s.get("size") or 0
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
            # Block until the result is available or timeout occurs.
            result = result_queue.get(timeout=timeout)
            if "error" in result:
                return {"success": False, "error": result["error"]}
            return result
        except queue.Empty:
            # This is the primary expected exception: the emulation took too long.
            return {"success": False, "error": f"Emulation timed out after {timeout} seconds."}
        except Exception as e:
            return {"success": False, "error": f"An unexpected error occurred: {str(e)}"}
        finally:
            # Ensure the thread and r2pipe are cleaned up regardless of outcome.
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
        res = get_reachable_addresses(bin_path, entry, entry_mode="function")
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
                rodata_addr = s.get("addr", s.get("offset"))
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
        res = extract_static_memory(bin_path, '0x1000006b4 + 0x30', 0x10)
        res = extract_static_memory(bin_path, '0x1000006b4 + 0x31', 0x10)
        res = extract_static_memory(bin_path, str_addr, 16)
        print(f"String chosen: {str_val} @ 0x{str_addr:x}")
        print(json.dumps(res, indent=2, default=str))
    except Exception as e:
        print(f"ERROR: {e}")

    print("=" * 40)
    print(f"[4] generate_angr_template('{bin_path}', 'path_search')")
    try:
        res = generate_angr_template(bin_path, "path_search")
        lines = res["template_code"].splitlines()
        for i, l in enumerate(lines):
            if i >= args.print_template_lines:
                print("(...truncated...)")
                break
            print(l)
    except Exception as e:
        print(f"ERROR: {e}")
