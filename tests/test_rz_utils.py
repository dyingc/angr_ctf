import json
import unittest
from unittest.mock import patch

# 被测模块
from ai_agent import rz_utils
from ai_agent.reverse_engineering import (
    _get_call_graph_tool_impl,
    _get_cfg_basic_blocks_tool_impl,
    _get_strings_tool_impl,
    _search_string_refs_tool_impl,
    _emulate_function_tool_impl,
    CallGraphToolInput, # 新增导入
    CFGBasicBlocksToolInput, # 新增导入
    GetStringsToolInput, # 新增导入
    SearchStringRefsToolInput, # 新增导入
    EmulateFunctionToolInput, # 新增导入
)

# -----------------------------------------------------------------------------
# 构造一个 rzpipe 的假对象，用来截获 .cmd() 调用并返回伪造的 JSON 结果
# -----------------------------------------------------------------------------
class RzPipeMock:
    """
    极简 rzpipe stub，只覆盖本轮测试用到的命令：
        agCdj / agfj / afbj / agj / izj / axtj / aeim / aerj / pdj / aei
    """
    def __init__(self):
        # 第一次 aerj 返回带 pc，第二次开始返回空寄存器，用来触发 emulate 退出
        self._aerj_call_cnt = 0

    # 主接口：根据传入的 command 字符串返回预设 JSON / 字符串
    def cmd(self, cmd_str: str):
        # ---- Call-graph ------------------------------------------------------
        if cmd_str.startswith("agCdj"):
            # 局部调用图
            graph = {
                "nodes": [
                    {"name": "main", "addr": 0x401000},
                    {"name": "helper", "addr": 0x401020},
                ],
                "edges": [{"from": 0x401000, "to": 0x401020}],
            }
            return json.dumps(graph)

        if cmd_str == "agfj":
            # 全局调用图（只关心 nodes）
            graph = [
                {"name": "main", "addr": 0x401000, "imports": [], "exports": []},
                {"name": "helper", "addr": 0x401020, "imports": [], "exports": []},
            ]
            return json.dumps(graph)

        # ---- CFG & basic-blocks ---------------------------------------------
        if cmd_str.startswith("afbj"):
            blocks = [
                {"offset": 0x401000, "size": 10, "type": "entry"},
                {"offset": 0x40100a, "size": 8, "type": "cond"},
            ]
            return json.dumps(blocks)

        if cmd_str.startswith("agj"):
            edges = [{"from": 0x401000, "to": 0x40100a, "type": "jmp"}]
            return json.dumps(edges)

        # ---- 字符串提取 / 引用 -------------------------------------------------
        if cmd_str == "izj":
            strs = [
                {
                    "vaddr": 0x402000,
                    "paddr": 0x200,
                    "length": 5,
                    "string": "Hello",
                    "section": ".rodata",
                },
                {
                    "vaddr": 0x402010,
                    "paddr": 0x210,
                    "length": 3,
                    "string": "Hi",
                    "section": ".rodata",
                },
            ]
            return json.dumps(strs)

        if cmd_str.startswith("axtj"):
            refs = [
                {
                    "from": 0x401005,
                    "fcn_name": "main",
                    "opcode": "lea rdi, str.Hello",
                }
            ]
            return json.dumps(refs)

        # ---- ESIL 模拟 -------------------------------------------------------
        if cmd_str.startswith("aeim"):
            return ""  # 初始化无返回即可

        if cmd_str == "aerj":
            # 第一次返回带 pc，随后返回 {} 让 emulate_function 终止
            if self._aerj_call_cnt == 0:
                self._aerj_call_cnt += 1
                return json.dumps({"pc": 0x401000})
            return "{}"

        if cmd_str.startswith("pdj"):
            return json.dumps([{"disasm": "nop"}])

        if cmd_str == "aei":
            return ""  # 单步执行

        # 其他未覆盖命令：返回空字符串
        return ""

    def quit(self):
        pass  # 关闭连接的空实现


# -----------------------------------------------------------------------------
# 单元测试主体
# -----------------------------------------------------------------------------
class TestRzUtilsFunctions(unittest.TestCase):
    """对 ai_agent.rz_utils 及其 reverse_engineering 包装函数进行单元测试"""

    def setUp(self):
        # 给 reverse_engineering 那些 wrapper 用
        self.bin_path = "dummy/path/binary"

        # 动态打补丁：所有 _open_rzpipe 调用都返回我们的 mock
        patcher = patch("ai_agent.rz_utils._open_rzpipe", lambda _: RzPipeMock())
        self.addCleanup(patcher.stop)
        patcher.start()

    # ----------------------------- Call-graph ---------------------------------
    def test_get_call_graph_global(self):
        result = rz_utils.get_call_graph(self.bin_path)
        self.assertEqual(len(result["nodes"]), 2)
        self.assertEqual(result["edges"], [])  # 全局版本我们让 edges 为空
        # 检查 reverse_engineering 的包装器
        wrapper_out = _get_call_graph_tool_impl(
            CallGraphToolInput(binary_path=self.bin_path)
        )
        self.assertEqual(wrapper_out["result"], result)

    def test_get_call_graph_local(self):
        result = rz_utils.get_call_graph(self.bin_path, "main", depth=2)
        self.assertEqual(
            set(n["name"] for n in result["nodes"]), {"main", "helper"}
        )
        self.assertEqual(result["edges"], [(0x401000, 0x401020)])

    # --------------------------- CFG basic blocks -----------------------------
    def test_get_cfg_basic_blocks(self):
        blocks = rz_utils.get_cfg_basic_blocks(self.bin_path, "main")
        # 共两个基本块且第一个块有后继
        self.assertEqual(len(blocks), 2)
        first = blocks[0]
        self.assertEqual(first["offset"], 0x401000)
        self.assertIn(0x40100A, first["succ"])
        # Wrapper
        wrapper_blocks = _get_cfg_basic_blocks_tool_impl(
            CFGBasicBlocksToolInput(
                binary_path=self.bin_path, function_name="main"
            )
        )
        self.assertEqual(wrapper_blocks["result"], blocks)

    # ------------------------------ Strings -----------------------------------
    def test_get_strings_min_len(self):
        strs = rz_utils.get_strings(self.bin_path, min_length=4)
        self.assertEqual(len(strs), 1)
        self.assertEqual(strs[0]["string"], "Hello")
        # 包装器
        wrapper_out = _get_strings_tool_impl(
            GetStringsToolInput(binary_path=self.bin_path, min_length=4)
        )
        self.assertEqual(wrapper_out["result"], strs)

    # ------------------------- Search string refs -----------------------------
    def test_search_string_refs(self):
        refs = rz_utils.search_string_refs(self.bin_path, "hello")
        self.assertEqual(len(refs), 1)
        self.assertEqual(refs[0]["string"], "Hello")
        self.assertEqual(refs[0]["refs"][0]["fcn"], "main")
        # 包装器
        wrapper_out = _search_string_refs_tool_impl(
            SearchStringRefsToolInput(
                binary_path=self.bin_path, query="hello"
            )
        )
        self.assertEqual(wrapper_out["result"], refs)

    # --------------------------- Emulate function -----------------------------
    def test_emulate_function(self):
        result = rz_utils.emulate_function(self.bin_path, "main", max_steps=5, timeout=2)
        self.assertIn("trace", result)
        self.assertGreaterEqual(len(result["trace"]), 1)
        # 包装器
        wrapper_out = _emulate_function_tool_impl(
            EmulateFunctionToolInput(
                binary_path=self.bin_path, function_name="main"
            )
        )
        self.assertEqual(wrapper_out["result"], result)


if __name__ == "__main__":
    unittest.main()
