import json
import unittest
from unittest.mock import patch

# 被测模块
from ai_agent.reverse_engineering import (
    get_function_list,
    get_disassembly,
    get_pseudo_code,
)

# -----------------------------------------------------------------------------
# 构造一个 rzpipe 的假对象，用来截获 .cmd() 调用并返回伪造的 JSON 结果
# -----------------------------------------------------------------------------
class RzPipeMock:
    """
    极简 rzpipe stub，只覆盖本轮测试用到的命令：
        aaa / aflj / axtj / afij / pdfj / pdgj
    """
    def __init__(self):
        self._cmd_history = []

    def cmd(self, cmd_str: str):
        self._cmd_history.append(cmd_str)
        return self._cmd_impl(cmd_str)

    def cmdj(self, cmd_str: str):
        json_str = self._cmd_impl(cmd_str)
        if json_str:
            return json.loads(json_str)
        return None

    def _cmd_impl(self, cmd_str: str):
        if cmd_str == "aaa":
            return "" # 通常无返回

        if cmd_str == "aflj":
            # 模拟 aflj 输出，包含 sym. 和非 sym. 函数
            functions = [
                {"offset": 0x401000, "name": "main", "realsz": 100, "signature": "void main()"},
                {"offset": 0x401064, "name": "sym.imp.printf", "realsz": 16, "signature": "void printf()"},
                {"offset": 0x401080, "name": "my_func", "realsz": 50, "signature": "int my_func(int a)"},
            ]
            return json.dumps(functions)

        if cmd_str.startswith("axtj @"):
            # 模拟 axtj 输出，为 main 函数模拟一个调用者
            if "0x401000" in cmd_str: # main
                xrefs = [
                    {"from": "0x400000", "type": "CALL", "opcode": "call 0x401000"} # 将 0x400000 改为字符串
                ]
                return json.dumps(xrefs)
            return "[]"

        if cmd_str.startswith("afij @"):
            # 模拟 afij 输出，为 0x400000 地址模拟一个函数信息
            if "0x400000" in cmd_str:
                finfo = [{"name": "caller_func", "offset": 0x400000}]
                return json.dumps(finfo)
            return "[]"

        if cmd_str.startswith("pdfj @"):
            # 模拟 pdfj 输出 (disassembly)
            if "main" in cmd_str:
                disassembly = {
                    "offset": 0x401000,
                    "name": "main",
                    "ops": [
                        {"offset": 0x401000, "disasm": "push rbp"},
                        {"offset": 0x401001, "disasm": "mov rbp, rsp"},
                        {"offset": 0x401004, "disasm": "call 0x401064 ; printf"},
                        {"offset": 0x401009, "disasm": "leave"},
                        {"offset": 0x40100a, "disasm": "ret"},
                    ]
                }
                return json.dumps(disassembly)
            return ""

        if cmd_str.startswith("pdgj @"):
            # 模拟 pdgj 输出 (pseudo code)
            if "main" in cmd_str:
                pseudo_code = {
                    "code": "/* main function */\nint main() {\n    printf(\"Hello, World!\\n\");\n    return 0;\n}"
                }
                return json.dumps(pseudo_code)
            return ""

        return ""

    def quit(self):
        pass # 关闭连接的空实现


# -----------------------------------------------------------------------------
# 单元测试主体
# -----------------------------------------------------------------------------
class TestReverseEngineeringFunctions(unittest.TestCase):
    """对 ai_agent.reverse_engineering 中的函数进行单元测试"""

    def setUp(self):
        self.bin_path = "dummy/path/binary"
        # 动态打补丁：所有 rzpipe.open 调用都返回我们的 mock
        patcher = patch("rzpipe.open", lambda _: RzPipeMock())
        self.addCleanup(patcher.stop)
        patcher.start()

        # 模拟 config.yaml 内容
        self.mock_config = {
            "tool_messages": {
                "get_assemly_messages": {
                    "system": "System message for assembly.",
                    "task": "Task message for assembly: {original_assembly_code}"
                },
                "get_pseudo_code_messages": {
                    "system": "System message for pseudo code.",
                    "task": "Task message for pseudo code: {original_pseudo_code}"
                }
            }
        }
        patcher_config = patch("ai_agent.reverse_engineering.config", self.mock_config)
        self.addCleanup(patcher_config.stop)
        patcher_config.start()

    def test_get_function_list(self):
        result = get_function_list(self.bin_path)
        self.assertIn("result", result)
        self.assertIsInstance(result["result"], list)

        # 验证过滤掉 sym. 函数
        self.assertEqual(len(result["result"]), 2)
        func_names = [f["name"] for f in result["result"]]
        self.assertIn("main", func_names)
        self.assertIn("my_func", func_names)
        self.assertNotIn("sym.imp.printf", func_names)

        # 验证 called_by 字段
        main_func = next(f for f in result["result"] if f["name"] == "main")
        self.assertEqual(main_func["called_by"], "caller_func")

    def test_get_disassembly(self):
        result = get_disassembly(self.bin_path, "main")
        self.assertIn("result", result)
        self.assertIsInstance(result["result"], str)
        self.assertIn("push rbp", result["result"])
        self.assertIn("mov rbp, rsp", result["result"])
        self.assertIn("call 0x401064 ; printf", result["result"])
        self.assertIn("leave", result["result"])
        self.assertIn("ret", result["result"])

        self.assertIn("prompts", result)
        self.assertEqual(len(result["prompts"]), 2)
        self.assertIn("System message for assembly.", result["prompts"][0])
        self.assertIn("Task message for assembly:", result["prompts"][1])
        self.assertIn(result["result"], result["prompts"][1])

    def test_get_pseudo_code(self):
        result = get_pseudo_code(self.bin_path, "main")
        self.assertIn("result", result)
        self.assertIsInstance(result["result"], str)
        self.assertIn("int main()", result["result"])
        self.assertIn("printf(\"Hello, World!\\n\");", result["result"])

        self.assertIn("prompts", result)
        self.assertEqual(len(result["prompts"]), 2)
        self.assertIn("System message for pseudo code.", result["prompts"][0])
        self.assertIn("Task message for pseudo code:", result["prompts"][1])
        self.assertIn(result["result"], result["prompts"][1])

if __name__ == "__main__":
    unittest.main()
