import os
import yaml
from typing import Dict, Any, Optional
from .base import BinaryAnalysisBackend
from .rizin_backend import RizinBackend
from .radare2_backend import Radare2Backend

# 全局后端实例缓存
_backend_cache: Dict[str, BinaryAnalysisBackend] = {}

def _load_config() -> Dict[str, Any]:
    """从 config.yaml 加载配置。"""
    config_path = os.path.join(os.path.dirname(__file__), "../config.yaml")
    with open(config_path) as f:
        return yaml.safe_load(f)

def get_backend(engine_hint: Optional[str] = None) -> BinaryAnalysisBackend:
    """
    根据 engine_hint、环境变量或配置文件返回合适的后端实例。
    结果会被缓存以提高性能。
    """
    # 1. 优先使用 engine_hint
    if engine_hint:
        key = engine_hint.lower()
    else:
        # 2. 检查环境变量
        key = os.getenv("AA_BACKEND", "").lower()
        if not key:
            # 3. 读取配置文件
            config = _load_config()
            key = config.get("backend", {}).get("default", "rizin").lower()

    # 缓存键
    cache_key = key

    if cache_key not in _backend_cache:
        if key == "radare2":
            _backend_cache[cache_key] = Radare2Backend()
        else:
            # 默认为 Rizin
            _backend_cache[cache_key] = RizinBackend()

    return _backend_cache[cache_key]

def call(feature: str, *args, engine_hint: Optional[str] = None, **kwargs) -> Any:
    """
    调用指定功能，支持按功能粒度指定后端。
    Args:
        feature: 要调用的功能名（如 'get_call_graph'）。
        *args: 传递给功能的参数。
        engine_hint: 指定后端（"rizin"|"radare2"），可选。
        **kwargs: 传递给功能的额外参数。
    Returns:
        功能的返回值。
    """
    backend = get_backend(engine_hint)
    method = getattr(backend, feature)
    return method(*args, **kwargs)
