from .base import BinaryAnalysisBackend
from typing import Dict, Any, List, Optional
# 直接复用现有实现
from ai_agent.libs import rz_utils as impl, rz_emulator

class RizinBackend(BinaryAnalysisBackend):
    """
    Rizin 后端实现，直接委托给 ai_agent.rz_utils 模块。
    """

    def get_call_graph(self, binary_path: str, function_name: Optional[str] = None, **kwargs) -> Dict[str, Any]:
        return impl.get_call_graph(binary_path, function_name)

    def get_cfg_basic_blocks(self, binary_path: str, function_name: str) -> List[Dict[str, Any]]:
        return impl.get_cfg_basic_blocks(binary_path, function_name)

    def get_strings(self, binary_path: str, min_length: int = 4) -> List[Dict[str, Any]]:
        return impl.get_strings(binary_path, min_length)

    def search_string_refs(self, binary_path: str, query: str, ignore_case: bool = True, max_refs: int = 50) -> List[Dict[str, Any]]:
        return impl.search_string_refs(binary_path, query, ignore_case, max_refs)

    def emulate_function(self, binary_path: str, function_name: str, **kwargs) -> Dict[str, Any]:
        # 传递所有参数
        return impl.emulate_function(binary_path, function_name, **kwargs)

    def get_function_list(self, binary_path: str, exclude_builtins: bool = True) -> List[Dict[str, Any]]:
        # 复用 reverse_engineering.py 中的逻辑，但使用本模块的 impl
        rz = impl._open_rzpipe(binary_path)
        try:
            functions = rz.cmd("aflj")
            if not functions or not isinstance(functions, str):
                return []
            func_list = impl.json.loads(functions)
            if exclude_builtins:
                func_list = [f for f in func_list if not f["name"].startswith("sym.imp.") and not f["name"].startswith("func.")]
            shortented_func_list = []
            for func in func_list:
                shortented_func = {
                    "offset": func["offset"],
                    "name": func["name"],
                    "size": func["realsz"],
                    "file": func.get("file", ""),
                    "signature": func["signature"]
                }
                detailed_func = impl._get_function_via_addr(rz, func["offset"])
                if detailed_func:
                    shortented_func["called_by"] = detailed_func.get("called_by", [])
                else:
                    shortented_func["called_by"] = []
                shortented_func_list.append(shortented_func)
            return shortented_func_list
        finally:
            rz.quit()

    def get_disassembly(self, binary_path: str, function_name: str) -> str:
        rz = impl._open_rzpipe(binary_path)
        try:
            disassembly = rz.cmd(f"pdfj @ {function_name}")
            if not disassembly or not isinstance(disassembly, str):
                return ""
            disassembly = impl.json.loads(disassembly)
            return '\n'.join([f"{d['offset']}\t{d['disasm']}" for d in disassembly.get('ops', [])])
        finally:
            rz.quit()

    def get_pseudo_code(self, binary_path: str, function_name: str) -> str:
        rz = impl._open_rzpipe(binary_path)
        try:
            pseudo_code = rz.cmd(f"pdg @ {function_name} | grep -E -v 'WARNING:.*Removing.*unreachable.*block'")
            if not pseudo_code or not isinstance(pseudo_code, str):
                return ""
            return pseudo_code
        finally:
            rz.quit()

