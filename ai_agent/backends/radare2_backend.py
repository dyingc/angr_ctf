from .base import BinaryAnalysisBackend
from typing import Dict, Any, List, Optional
# 直接复用现有实现
from ai_agent.libs import r2_utils as impl

class Radare2Backend(BinaryAnalysisBackend):
    """
    radare2 后端实现，直接委托给 ai_agent.libs.r2_utils 模块。
    """

    def get_call_graph(self, binary_path: str, function_name: Optional[str] = None, **kwargs) -> Dict[str, Any]:
        # 传递 depth 参数（如果提供）
        depth = kwargs.get('depth', 3)
        return impl.get_call_graph(binary_path, function_name, depth)

    def get_cfg_basic_blocks(self, binary_path: str, function_name: str) -> List[Dict[str, Any]]:
        return impl.get_cfg_basic_blocks(binary_path, function_name)

    def get_strings(self, binary_path: str, min_length: int = 4) -> List[Dict[str, Any]]:
        return impl.get_strings(binary_path, min_length)

    def search_string_refs(self, binary_path: str, query: str, ignore_case: bool = True, max_refs: int = 50) -> List[Dict[str, Any]]:
        return impl.search_string_refs(binary_path, query, ignore_case, max_refs)

    def emulate_function(self, binary_path: str, function_name: str, **kwargs) -> Dict[str, Any]:
        # 仅传递 radare2 支持的参数
        max_steps = kwargs.get('max_steps', 100)
        timeout = kwargs.get('timeout', 60)
        return impl.emulate_function(binary_path, function_name, max_steps, timeout)

    def get_function_list(self, binary_path: str, exclude_builtins: bool = True) -> List[Dict[str, Any]]:
        # 复用示例中的逻辑
        r2 = impl._open_r2pipe(binary_path)
        try:
            functions = r2.cmd("aflj")
            if not functions or not isinstance(functions, str):
                return []
            func_list = impl.json.loads(functions)
            if exclude_builtins:
                # 示例中仅过滤 sym. 开头的
                func_list = [f for f in func_list if not f["name"].startswith("sym.")]
            shortented_func_list = []
            for func in func_list:
                shortented_func = {
                    "offset": func["offset"],
                    "name": func["name"],
                    "size": func["realsz"],
                    "file": func.get("file", ""),
                    "signature": func["signature"]
                }
                # 示例中未提供 caller 列表，此处留空
                shortented_func["called_by"] = []
                shortented_func_list.append(shortented_func)
            return shortented_func_list
        finally:
            r2.quit()

    def get_disassembly(self, binary_path: str, function_name: str) -> str:
        r2 = impl._open_r2pipe(binary_path)
        try:
            disassembly = r2.cmd(f"pdfj @ {function_name}")
            if not disassembly or not isinstance(disassembly, str):
                return ""
            disassembly = impl.json.loads(disassembly)
            return '\n'.join([f"{d['offset']}\t{d['disasm']}" for d in disassembly.get('ops', [])])
        finally:
            r2.quit()

    def get_pseudo_code(self, binary_path: str, function_name: str) -> str:
        r2 = impl._open_r2pipe(binary_path)
        try:
            pseudo_code = r2.cmd(f"pdgj @ {function_name}")
            if not pseudo_code or not isinstance(pseudo_code, str):
                return ""
            pseudo_code = impl.json.loads(pseudo_code)
            return pseudo_code.get('code', "")
        finally:
            r2.quit()
