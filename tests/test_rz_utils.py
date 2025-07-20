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
    CallGraphToolInput,
    CFGBasicBlocksToolInput,
    GetStringsToolInput,
    SearchStringRefsToolInput,
    EmulateFunctionToolInput,
)

# -----------------------------------------------------------------------------
# 构造一个 rzpipe 的假对象，用来截获 .cmd() 调用并返回伪造的 JSON 结果
# -----------------------------------------------------------------------------
class RzPipeMock:
    """
    极简 rzpipe stub，只覆盖本轮测试用到的命令：
        agC json / afbj / afd / izj / axtj / afij / aezi / arj / pdj / aoip / aezse / s / s-
    """
    def __init__(self):
        self._emulation_pc = 0x401000
        self._emulation_step_count = 0
        self._function_info_cache = {} # 缓存函数信息

    # 主接口：根据传入的 command 字符串返回预设 JSON / 字符串
    def cmd(self, cmd_str: str):
        # ---- Call-graph ------------------------------------------------------
        if cmd_str == "agC json" or cmd_str.startswith("agC json @"):
            # 全局调用图
            graph = {
                "nodes": [
                    {"id": 0, "title": "main", "offset": 0x401000, "out_nodes": [1]},
                    {"id": 1, "title": "helper", "offset": 0x401020, "out_nodes": []},
                ]
            }
            return json.dumps(graph)
        if cmd_str.startswith("agc json") or cmd_str.startswith("agc json @"):
            # 局部调用图
            graph = {
                "nodes": [
                    {"id": 0, "title": "main", "offset": 0x401000, "out_nodes": [1]},
                    {"id": 1, "title": "helper", "offset": 0x401020, "out_nodes": []},
                ]
            }
            return json.dumps(graph)

        # ---- CFG & basic-blocks ---------------------------------------------
        if cmd_str.startswith("afbj @"):
            blocks = [
                {"addr": 0x401000, "size": 10, "ninstr": 3, "inputs": 0, "outputs": 1, "num_of_input_blocks": 0, "num_of_output_blocks": 1, "num_of_instructions": 3, "jump": 0x40100A, "fail": None},
                {"addr": 0x40100A, "size": 8, "ninstr": 2, "inputs": 1, "outputs": 0, "jump": 0x40200A, "fail": None},
                {"addr": 0x40101A, "size": 8, "ninstr": 3, "inputs": 2, "outputs": 2, "fail": 0x40300A, "jump": 0x40400A},
            ]
            return json.dumps(blocks)
        elif cmd_str.startswith("afd @"):
            addr_str = hex(int(cmd_str.split("@")[1].strip()))
            if not addr_str or addr_str == 'null' or '0x' not in addr_str:
                return ""
            addr = int(addr_str, 16)
            if addr == 0x40100A:
                return "sym.imp.some_func + 0x100A"
            elif addr == 0x40200A:
                return "sym.imp.another_func + 0x200A"
            elif addr == 0x40300A:
                return "sym.imp.yet_another_func + 0x300A"
            elif addr == 0x40400A:
                return "sym.imp.final_func + 0x400A"
            return ""

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

        if cmd_str.startswith("axtj @"):
            addr = int(cmd_str.split("@")[1].strip())
            if addr == 0x402000: # References to "Hello" string
                refs = [
                    {"from": 0x401005, "type": "d", "opcode": "lea rdi, [0x402000]"},
                    {"from": 0x401010, "type": "d", "opcode": "mov eax, [0x402000]"},
                ]
                return json.dumps(refs)
            return "[]"

        if cmd_str.startswith("afij @"):
            addr = int(cmd_str.split("@")[1].strip())
            if addr in [0x401005, 0x401010, 0x401000]:
                if addr not in self._function_info_cache:
                    self._function_info_cache[addr] = [{"offset": 0x401000, "name": "main", "realsz": 100, "file": "binary", "signature": "int main()"}]
                return json.dumps(self._function_info_cache[addr])
            return "[]"

        # ---- ESIL 模拟 (RzIL) -------------------------------------------------------
        if cmd_str.startswith("s "): # 跳转到函数
            self._emulation_pc = 0x401000 # Reset PC for emulation
            self._emulation_step_count = 0
            return ""
        elif cmd_str == "aezi": # 初始化RzIL VM
            self._emulation_pc = 0x401000
            self._emulation_step_count = 0
            return ""
        elif cmd_str == "arj": # 获取当前寄存器状态
            return json.dumps({"rip": self._emulation_pc, "rax": self._emulation_step_count})
        elif cmd_str.startswith("pdj 1 @"): # 获取当前指令信息
            addr = int(cmd_str.split('@')[1].strip())
            if addr == 0x401005:
                return json.dumps([{"disasm": "lea rdi, [0x402000]", "opcode": "488d...", "type": "lea"}])
            if addr == 0x401010:
                return json.dumps([{"disasm": "mov eax, [0x402000]", "opcode": "8b05...", "type": "mov"}])

            if self._emulation_pc == 0x401000:
                return json.dumps([{"disasm": "mov rax, 1", "opcode": "48c7c001000000", "type": "mov"}])
            elif self._emulation_pc == 0x401004:
                return json.dumps([{"disasm": "add rax, 1", "opcode": "4883c001", "type": "add"}])
            elif self._emulation_pc == 0x401008:
                return json.dumps([{"disasm": "ret", "opcode": "c3", "type": "ret"}])
            return "[]"
        elif cmd_str.startswith("aoip 1 @"): # 获取RzIL表示
            return "esil_representation"
        elif cmd_str == "aezse 1": # 执行一步RzIL并显示状态变化
            self._emulation_pc += 4 # Simulate PC increment
            self._emulation_step_count += 1
            return f"VM state change at step {self._emulation_step_count}"
        elif cmd_str == "s-": # 重置到原始位置
            return ""

        # 其他未覆盖命令：返回空字符串
        return ""

    def cmdj(self, cmd_str: str):
        # For _get_function_via_addr's xrefs
        if cmd_str.startswith("axtj @"):
            addr = int(cmd_str.split("@")[1].strip())
            if addr == 0x401005: # Caller of "Hello" string ref
                return [{"from": 0x401000}] # main calls it
            elif addr == 0x401010: # Another caller
                return [{"from": 0x401000}]
            return []
        elif cmd_str.startswith("afij @"):
            addr = int(cmd_str.split("@")[1].strip())
            if addr == 0x401000:
                return [{"offset": 0x401000, "name": "main", "realsz": 100, "file": "binary", "signature": "int main()"}]
            return []
        return json.loads(self.cmd(cmd_str)) # Fallback to cmd for JSON output

    def quit(self):
        pass  # 关闭连接的空实现


# -----------------------------------------------------------------------------
# 单元测试主体
# -----------------------------------------------------------------------------
class TestRzUtilsFunctions(unittest.TestCase):
    """对 ai_agent.rz_utils 及其 reverse_engineering 包装函数进行单元测试"""

    def setUp(self):
        # 给 reverse_engineering 那些 wrapper 用
        self.bin_path = "/Users/yingdong/VSCode/angr/angr_ctf/00_angr_find/00_angr_find_arm"

        # 动态打补丁：所有 _open_rzpipe 调用都返回我们的 mock
        patcher = patch("ai_agent.rz_utils._open_rzpipe", lambda _: RzPipeMock())
        self.addCleanup(patcher.stop)
        patcher.start()

    # ----------------------------- Call-graph ---------------------------------
    def test_get_call_graph_global(self):
        result = rz_utils.get_call_graph(self.bin_path)
        self.assertEqual(len(result["nodes"]), 2)
        self.assertEqual(len(result["edges"]), 1)
        # 检查 reverse_engineering 的包装器
        wrapper_out = _get_call_graph_tool_impl(
            CallGraphToolInput(binary_path=self.bin_path)
        )
        self.assertEqual(wrapper_out["result"], result)

    def test_get_call_graph_local(self):
        result = rz_utils.get_call_graph(self.bin_path, "main")

        self.assertEqual(len(result["nodes"]), 2)
        self.assertEqual(result["nodes"][0]["name"], "main")
        self.assertEqual(result["nodes"][1]["name"], "helper")
        self.assertEqual(len(result["edges"]), 1)
        self.assertEqual(result["edges"][0]["from"], 0) # id of main
        self.assertEqual(result["edges"][0]["to"], 1) # id of helper

    # --------------------------- CFG basic blocks -----------------------------
    def test_get_cfg_basic_blocks(self):
        blocks = rz_utils.get_cfg_basic_blocks(self.bin_path, "main")
        self.assertEqual(len(blocks), 3)
        # 检查第一个块
        first_block_key = list(blocks[0].keys())[0]
        first_block = blocks[0][first_block_key]
        self.assertEqual(first_block["addr"], 0x401000)
        self.assertEqual(first_block["size"], 10)
        self.assertEqual(first_block["num_of_instructions"], 3)
        self.assertEqual(first_block["jump_to_addr"], 0x40100A)
        self.assertEqual(first_block["jump_to_func_with_offset"], "sym.imp.some_func + 0x100A")
        self.assertIsNone(first_block.get("fall_through_addr"), None)
        self.assertIsNone(first_block.get("fall_through_func_with_offset"), None)
        self.assertEqual(first_block["num_of_input_blocks"], 0)
        self.assertEqual(first_block["num_of_output_blocks"], 1)
        # 检查第二个块
        second_block_key = list(blocks[1].keys())[0]
        second_block = blocks[1][second_block_key]
        self.assertEqual(second_block["addr"], 0x40100A)
        self.assertEqual(second_block["size"], 8)
        self.assertEqual(second_block["num_of_instructions"], 2)
        self.assertEqual(second_block["jump_to_addr"], 0x40200A)
        self.assertEqual(second_block.get("jump_to_func_with_offset"), "sym.imp.another_func + 0x200A")
        self.assertIsNone(second_block.get("fall_through_addr"))
        self.assertIsNone(second_block.get("fall_through_func_with_offset"))
        # 检查第三个块
        third_block_key = list(blocks[2].keys())[0]
        third_block = blocks[2][third_block_key]
        self.assertEqual(third_block["addr"], 0x40101A)
        self.assertEqual(third_block["size"], 8)
        self.assertEqual(third_block["num_of_instructions"], 3)
        self.assertEqual(third_block["jump_to_addr"], 0x40400A)
        self.assertEqual(third_block["jump_to_func_with_offset"], "sym.imp.final_func + 0x400A")
        self.assertEqual(third_block["fall_through_addr"], 0x40300A)
        self.assertEqual(third_block["fall_through_func_with_offset"], "sym.imp.yet_another_func + 0x300A")
        self.assertEqual(third_block["num_of_input_blocks"], 2)
        self.assertEqual(third_block["num_of_output_blocks"], 2)
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
        refs = rz_utils.search_string_refs(self.bin_path, "Hello") # Use "Hello" to match exactly
        self.assertEqual(len(refs), 1)
        self.assertEqual(refs[0]["string"], "Hello")
        self.assertEqual(refs[0]["str_addr"], 0x402000)
        self.assertEqual(len(refs[0]["refs"]), 2)

        # Check first ref
        self.assertEqual(refs[0]["refs"][0]["caller"], "main")
        self.assertEqual(refs[0]["refs"][0]["calling_addr"], 0x401005)
        self.assertEqual(refs[0]["refs"][0]["disasm"], "lea rdi, [0x402000]")
        self.assertEqual(refs[0]["refs"][0]["opcode"], "488d...")

        # Check second ref
        self.assertEqual(refs[0]["refs"][1]["caller"], "main")
        self.assertEqual(refs[0]["refs"][1]["calling_addr"], 0x401010)
        self.assertEqual(refs[0]["refs"][1]["disasm"], "mov eax, [0x402000]")
        self.assertEqual(refs[0]["refs"][1]["opcode"], "8b05...")

        # 包装器
        wrapper_out = _search_string_refs_tool_impl(
            SearchStringRefsToolInput(
                binary_path=self.bin_path, query="Hello"
            )
        )
        self.assertEqual(wrapper_out["result"], refs)

    # --------------------------- Emulate function -----------------------------
    @patch('ai_agent.rz_emulator._improved_rzil_emulation') # Changed from rz_utils to rz_emulator
    def test_emulate_function(self, mock_emulate):
        # Setup mock for _improved_rzil_emulation
        def mock_emulate_side_effect(rz_instance, function_name, max_steps, result_queue, timeout_seconds):
            result_queue.put({
                "success": True,
                "execution_summary": {
                    "steps_executed": 3,
                    "execution_time": 0.1,
                    "memory_setup_success": True,
                    "architecture": "x86 64-bit"
                },
                "final_registers": {"rip": 0x40100c, "rax": 3},
                "execution_trace": [
                    {"step": 0, "pc": hex(0x401000), "instruction": "mov rax, 1", "opcode": "48c7c001000000", "type": "mov", "registers": {"rax": 0}, "timestamp": 0.0, "step_duration": 0.0},
                    {"step": 1, "pc": hex(0x401004), "instruction": "add rax, 1", "opcode": "4883c001", "type": "add", "registers": {"rax": 1}, "timestamp": 0.0, "step_duration": 0.0},
                    {"step": 2, "pc": hex(0x401008), "instruction": "ret", "opcode": "c3", "type": "ret", "registers": {"rax": 2}, "timestamp": 0.0, "step_duration": 0.0},
                ],
                "vm_state_changes": [
                    {"step": 0, "changes": "VM state change at step 1", "timestamp": 0.0},
                    {"step": 1, "changes": "VM state change at step 2", "timestamp": 0.0},
                    {"step": 2, "changes": "VM state change at step 3", "timestamp": 0.0},
                ],
                "setup_log": ["Setup log entry 1", "Setup log entry 2"],
                "emulation_type": "RzIL_v2"
            })
        mock_emulate.side_effect = mock_emulate_side_effect

        result = rz_utils.emulate_function(self.bin_path, "main", max_steps=5, timeout=10)

        self.assertTrue(result["success"])
        self.assertIn("execution_trace", result)
        self.assertEqual(len(result["execution_trace"]), 3)
        self.assertIn("final_registers", result)
        self.assertIn("vm_state_changes", result)
        self.assertEqual(result["execution_summary"]["steps_executed"], 3)
        self.assertEqual(result["emulation_type"], "RzIL_v2")

        # Check trace content
        self.assertEqual(result["execution_trace"][0]["pc"], hex(0x401000))
        self.assertEqual(result["execution_trace"][0]["instruction"], "mov rax, 1")
        self.assertEqual(result["execution_trace"][0]["registers"]["rax"], 0)

        self.assertEqual(result["execution_trace"][1]["pc"], hex(0x401004))
        self.assertEqual(result["execution_trace"][1]["instruction"], "add rax, 1")
        self.assertEqual(result["execution_trace"][1]["registers"]["rax"], 1)

        self.assertEqual(result["execution_trace"][2]["pc"], hex(0x401008))
        self.assertEqual(result["execution_trace"][2]["instruction"], "ret")
        self.assertEqual(result["execution_trace"][2]["registers"]["rax"], 2)

        # Check final regs
        self.assertEqual(result["final_registers"]["rax"], 3)

        # 包装器
        wrapper_out = _emulate_function_tool_impl(
            EmulateFunctionToolInput(
                binary_path=self.bin_path, function_name="main"
            )
        )
        # Note: The wrapper calls emulate_function, which is now fully mocked at the rzil level
        self.assertTrue(wrapper_out["result"]["success"])
        self.assertEqual(wrapper_out["result"]["execution_summary"]["steps_executed"], 3)


if __name__ == "__main__":
    unittest.main()
