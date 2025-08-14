from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional

class BinaryAnalysisBackend(ABC):
    """
    统一的二进制分析后端抽象基类，屏蔽 Rizin 与 radare2 的实现差异。
    所有具体后端（RizinBackend, Radare2Backend）必须实现这些方法。
    """

    @abstractmethod
    def get_call_graph(self, binary_path: str, function_name: Optional[str] = None, **kwargs) -> Dict[str, Any]:
        """
        生成二进制的调用图。
        Args:
            binary_path: 二进制文件路径。
            function_name: 函数名，若为 None 则生成全局调用图。
            **kwargs: 传递给底层实现的额外参数（如 radare2 的 depth）。
        Returns:
            包含 'nodes' 和 'edges' 的字典。
        """
        pass

    @abstractmethod
    def get_cfg_basic_blocks(self, binary_path: str, function_name: str) -> List[Dict[str, Any]]:
        """
        获取函数的 CFG 基本块信息。
        Args:
            binary_path: 二进制文件路径。
            function_name: 函数名。
        Returns:
            基本块信息列表。
        """
        pass

    @abstractmethod
    def get_strings(self, binary_path: str, min_length: int = 4) -> List[Dict[str, Any]]:
        """
        提取二进制中的字符串。
        Args:
            binary_path: 二进制文件路径。
            min_length: 最小字符串长度。
        Returns:
            字符串信息列表。
        """
        pass

    @abstractmethod
    def search_string_refs(self, binary_path: str, query: str, ignore_case: bool = True, max_refs: int = 50) -> List[Dict[str, Any]]:
        """
        搜索字符串引用。
        Args:
            binary_path: 二进制文件路径。
            query: 搜索查询（子串或正则）。
            ignore_case: 是否忽略大小写。
            max_refs: 每个字符串最多返回的引用数。
        Returns:
            匹配结果列表。
        """
        pass

    @abstractmethod
    def emulate_function(self, binary_path: str, function_name: str, **kwargs) -> Dict[str, Any]:
        """
        模拟函数执行。
        Args:
            binary_path: 二进制文件路径。
            function_name: 函数名。
            **kwargs: 传递给底层实现的额外参数（如 max_steps, timeout, 内存选项）。
        Returns:
            模拟结果字典。
        """
        pass

    @abstractmethod
    def get_function_list(self, binary_path: str, exclude_builtins: bool = True) -> List[Dict[str, Any]]:
        """
        获取二进制中的函数列表。
        Args:
            binary_path: 二进制文件路径。
            exclude_builtins: 是否排除内置函数。
        Returns:
            函数信息列表。
        """
        pass

    @abstractmethod
    def get_disassembly(self, binary_path: str, function_name: str) -> str:
        """
        获取函数的反汇编代码。
        Args:
            binary_path: 二进制文件路径。
            function_name: 函数名。
        Returns:
            反汇编文本。
        """
        pass

    @abstractmethod
    def get_pseudo_code(self, binary_path: str, function_name: str) -> str:
        """
        获取函数的伪代码。
        Args:
            binary_path: 二进制文件路径。
            function_name: 函数名。
        Returns:
            伪代码文本。
        """
        pass
