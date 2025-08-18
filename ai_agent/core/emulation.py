"""
高层仿真调度接口，兼容 Rizin/Radare2，返回统一 schema。
"""

from typing import Dict, Any


def emulate_function(
    binary_path: str,
    function_name: str,
    max_steps: int = 100,
    timeout: int = 60,
    stack_bytes: int = 32,
    stack_size: int = 0x10000,
    stack_base: int = 0x70000000,
    data_size: int = 0x1000,
    data_base: int = 0x60000000,
) -> Dict[str, Any]:
    """
    抽象仿真函数，统一封装 dispatcher，支持多后端。

    Args:
        binary_path: 二进制路径
        function_name: 函数名或入口地址
        max_steps: 最大指令步数
        timeout: 超时时间
        stack_bytes: 每步采集栈空间字节数
        stack_size, stack_base, data_size, data_base: 内存映射相关（如适用）

    Returns:
        dict: {result(后端原始结果), need_refine, prompts}
    """
    from ai_agent.backends.dispatcher import call as _call_backend
    result = _call_backend(
        "emulate_function",
        binary_path,
        function_name,
        max_steps=max_steps,
        timeout=timeout,
        stack_bytes=stack_bytes,
        stack_size=stack_size,
        stack_base=stack_base,
        data_size=data_size,
        data_base=data_base,
    )
    # 全部都封装到 result 字段，便于前端 schema 对齐
    return {
        "result": result,
        "need_refine": False,
        "prompts": []
    }
