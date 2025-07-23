"""
This module provides RzIL emulation functionalities for binary analysis using the Rizin
framework via the rzpipe library.

It includes functions for memory allocation, RzIL VM setup, and function emulation.
All operations are designed to be thread-safe.
"""
import rzpipe
import json
from typing import Dict, Any, List, Optional, Tuple
import threading
import queue
import time
import asyncio

from ai_agent.libs.lib_emulate import (
    _simulate_external_call_effects,
)

# Global lock for rzpipe operations to prevent race conditions
rz_lock = threading.Lock()

# Two global variables
arch: str = None
bits: int = None

def _open_rzpipe(binary_path: str) -> rzpipe.open:
    """
    Opens an rzpipe instance for a given binary and performs initial analysis.

    Args:
        binary_path: The path to the binary file.

    Returns:
        An initialized rzpipe instance after running 'aaa' analysis and disabling color.
    """
    rz = rzpipe.open(binary_path)
    rz.cmd("e scr.color=0; aaa 2>/dev/null")  # Disable color, perform auto-analysis
    return rz

# ========== UPDATED RZIL EMULATION FUNCTIONS ==========

def _check_rzil_support(rz_instance):
    """
    检查当前架构是否支持 RzIL
    """
    try:
        # 检查架构列表中是否有 'I' 标记（表示支持 RzIL）
        arch_list = rz_instance.cmd("La")
        # print(f"Architecture support list:\n{arch_list}")

        # 检查当前架构
        arch_info = rz_instance.cmdj("ij")
        current_arch = arch_info.get("bin", {}).get("arch", "unknown")
        print(f"Current architecture: {current_arch}")

        return True  # 假设支持，如果不支持会在后续步骤中发现
    except Exception as e:
        print(f"Error checking RzIL support: {e}")
        return False

def _setup_memory_with_malloc(
    rz_instance,
    arch,
    bits,
    stack_size: int, # 移除默认值，由调用者提供
    stack_base: int, # 移除默认值，由调用者提供
    data_size: int, # 移除默认值，由调用者提供
    data_base: int # 移除默认值，由调用者提供
) -> Tuple[str, str, int, bool]:
    """
    使用您验证过的 malloc:// 方法设置内存
    """
    try:
        print("Setting up memory mapping (using malloc:// protocol)...")

        # 1. 检查当前状态
        print("Current file list:")
        current_files = rz_instance.cmd("ol")
        print(current_files)

        # 2. 创建栈内存区域
        # 64KB 栈（比较保守的大小）(stack_size = 0x10000)
        # 使用一个安全的基地址 (stack_base = 0x70000000)

        # 使用: o malloc://size address
        stack_cmd = f"o malloc://{hex(stack_size)} {hex(stack_base)}"
        print(f"Executing stack mapping command: {stack_cmd}")
        stack_result = rz_instance.cmd(stack_cmd) or "Stack mapping command succeeded"
        print(f"Stack mapping result: {stack_result}")

        # 3. 创建额外的数据内存区域
        data_cmd = f"o malloc://{hex(data_size)} {hex(data_base)}"
        print(f"Executing data mapping command: {data_cmd}")
        data_result = rz_instance.cmd(data_cmd) or "Data mapping command succeeded"
        print(f"Data mapping result: {data_result}")

        # 4. 验证映射状态
        print("Verifying memory mapping...")
        files_after = rz_instance.cmd("ol")
        print(f"File list after mapping:\n{files_after}")

        # 5. 尝试启用 io.cache（如果需要的话）
        try:
            cache_result = rz_instance.cmd("e io.cache=true")
            cache_status = rz_instance.cmd("e io.cache")
            print(f"io.cache status: {cache_status.strip()}")
        except Exception as e:
            print(f"Error setting io.cache (may not be needed): {e}")

        # 6. 根据架构确定寄存器名称
        if arch == "arm" and bits == 64:
            stack_pointer = "sp"
            base_pointer = "x29"
            initial_sp = stack_base + stack_size - 0x100  # 距离栈顶256字节
        elif arch == "x86" and bits == 64:
            stack_pointer = "rsp"
            base_pointer = "rbp"
            initial_sp = stack_base + stack_size - 0x100
        elif arch == "x86" and bits == 32:
            stack_pointer = "esp"
            base_pointer = "ebp"
            initial_sp = stack_base + stack_size - 0x100
        else:
            # 通用设置
            stack_pointer = "sp"
            base_pointer = "fp"
            initial_sp = stack_base + stack_size - 0x100

        # 确保16字节对齐
        initial_sp = initial_sp & ~0xF

        return stack_pointer, base_pointer, initial_sp, True

    except Exception as e:
        print(f"Memory mapping setup failed: {e}")
        return "sp", "fp", 0x70000000, False

def _test_memory_access(rz_instance, address):
    """
    测试内存地址是否可以访问
    """
    try:
        # 尝试读取内存
        result = rz_instance.cmd(f"px 16 @ {hex(address)}")
        if "error" in result.lower() or len(result.strip()) == 0:
            return False
        print(f"Memory test successful @ {hex(address)}")
        return True
    except Exception as e:
        print(f"Memory test failed @ {hex(address)}: {e}")
        return False


def _merge_multi_step_changes(all_outputs: List[str]) -> str:
    """
    合并多步执行的状态变化，只保留初始状态和最终状态

    Args:
        all_outputs: 每一步的执行输出列表

    Returns:
        str: 合并后的JSON字符串，包含净变化
    """
    initial_states = {}  # 存储初始状态：{变量名: 初始值}
    final_states = {}    # 存储最终状态：{变量名: 最终值}
    raw_outputs = []     # 存储非JSON输出

    for step_idx, output in enumerate(all_outputs):
        if not output or not output.strip():
            continue

        try:
            changes = json.loads(output)
            if not isinstance(changes, list):
                changes = [changes]

            for change in changes:
                if not isinstance(change, dict):
                    continue

                # 解析不同类型的变化
                change_type = change.get("type", "")

                if change_type == "var_write":
                    # 寄存器/变量写入：{"type": "var_write", "name": "x0", "old": "0x0", "new": "0x123"}
                    var_name = change.get("name")
                    old_value = change.get("old")
                    new_value = change.get("new")

                    if var_name:
                        # 如果是第一次见到这个变量，记录初始状态
                        if var_name not in initial_states:
                            initial_states[var_name] = old_value
                        # 总是更新最终状态
                        final_states[var_name] = new_value

                elif change_type == "pc_write":
                    # PC写入：{"type": "pc_write", "old": "0x1000", "new": "0x1004"}
                    old_pc = change.get("old")
                    new_pc = change.get("new")

                    if "pc" not in initial_states:
                        initial_states["pc"] = old_pc
                    final_states["pc"] = new_pc

                elif change_type == "mem_write":
                    # 内存写入：{"type": "mem_write", "addr": "0x1000", "old": "0x0", "new": "0x123"}
                    addr = change.get("addr")
                    old_value = change.get("old")
                    new_value = change.get("new")

                    if addr:
                        mem_key = f"mem[{addr}]"
                        if mem_key not in initial_states:
                            initial_states[mem_key] = old_value
                        final_states[mem_key] = new_value

                else:
                    # 其他类型的变化，直接保留
                    raw_outputs.append(change)

        except json.JSONDecodeError:
            # 非JSON输出，作为原始输出保留
            raw_outputs.append({"type": "raw_output", "content": output.strip()})

    # 构建最终的变化列表：只包含真正发生变化的项
    net_changes = []

    # 处理变量/寄存器变化
    for var_name in final_states:
        initial_value = initial_states.get(var_name)
        final_value = final_states[var_name]

        # 只记录真正发生变化的项
        if initial_value != final_value:
            if var_name == "pc":
                net_changes.append({
                    "type": "pc_write",
                    "old": initial_value,
                    "new": final_value
                })
            elif var_name.startswith("mem["):
                addr = var_name[4:-1]  # 提取地址，去掉 "mem[" 和 "]"
                net_changes.append({
                    "type": "mem_write",
                    "addr": addr,
                    "old": initial_value,
                    "new": final_value
                })
            else:
                net_changes.append({
                    "type": "var_write",
                    "name": var_name,
                    "old": initial_value,
                    "new": final_value
                })

    # 添加原始输出
    net_changes.extend(raw_outputs)

    return json.dumps(net_changes) if net_changes else ""

def _is_external_function_call(current_op: Dict[str, Any], instruction_disasm: str) -> bool:
    """
    判断是否为外部函数调用

    Args:
        current_op: 当前指令的信息字典
        instruction_disasm: 指令反汇编文本

    Returns:
        bool: 如果是外部函数调用返回True
    """
    # 检查是否调用 sym.imp.* (imported symbols)
    if "sym.imp." in instruction_disasm:
        return True

    # 检查是否调用 reloc.* (relocations)
    if "reloc." in instruction_disasm:
        return True

    # 检查跳转目标是否在外部段
    # 可以通过 flags 字段或者目标地址判断
    flags = current_op.get("flags", [])
    for flag in flags:
        if isinstance(flag, str) and ("imp." in flag or "reloc." in flag):
            return True

    return False

def rzil_step_over(rz, num_steps: int = 1) -> str:
    """
    实现 RzIL 的 step over 功能，支持指定步数。

    Step over 的逻辑：
    1. 判断当前指令是否为 call 指令
    2. 如果是 call：使用 pdj 获取下一条指令地址，然后用 aezsue 跳过调用
    3. 如果不是 call：使用 aezsej 正常单步执行
    4. 重复执行指定的步数

    注意：只有对 call 指令才能安全使用 pdj 获取下一条指令地址，
    因为其他指令（如跳转、分支）可能会离开当前基本块。

    Args:
        rz_instance: rzpipe 实例
        num_steps: 要执行的步数，默认为1

    Returns:
        str: 执行输出（模拟 aezsej 的返回格式）
    """
    all_outputs = []

    for step_idx in range(num_steps):
        print(f"\n=== Step Over {step_idx + 1}/{num_steps} ===")

        # 获取当前PC
        try:
            pc_output = rz.cmd("aezvj PC")
            pc_data = json.loads(pc_output)
            current_pc = int(pc_data.get("PC", "0x0"), 16)
        except Exception as e:
            print(f"Failed to get current PC: {e}")
            return ""

        print(f"Current PC: {hex(current_pc)}")

        # 获取当前指令信息
        try:
            disasm_output = rz.cmd(f"pdj 1 @ {current_pc}")
            if disasm_output.strip():
                instructions = json.loads(disasm_output)
                if not instructions:
                    print(f"No instruction found at {current_pc}")
                    return ""
                current_op = instructions[0]
            else:
                print(f"No instruction found at {current_pc}")
                return ""
        except Exception as e:
            print(f"Failed to get instruction at {current_pc}: {e}")
            return ""

        instruction_type = current_op.get("type", "")
        instruction_disasm = current_op.get("disasm", "")

        print(f"Instruction: {instruction_disasm}")
        print(f"Type: {instruction_type}")

        # 判断是否为函数调用指令
        is_call_instruction = instruction_type == 'call'

        if is_call_instruction:
            print("📞 Detected call instruction - stepping over...")

            # 对于 call 指令，获取下一条指令地址并跳过
            try:
                # 获取当前和下一条指令
                disasm_output = rz.cmd(f"pdj 2 @ {current_pc}")
                if disasm_output.strip():
                    instructions = json.loads(disasm_output)
                    if len(instructions) < 2:
                        print(f"Cannot get next instruction after call at {current_pc}")
                        return ""
                    next_op = instructions[1]
                    next_pc = next_op.get("offset", 0)
                else:
                    print(f"Cannot get instructions at {current_pc}")
                    return ""

                print(f"Stepping over call to: {hex(next_pc)}")

                # 执行到下一条指令
                if _is_external_function_call(current_op, instruction_disasm):
                    print("Simulating external call effects...")
                    exec_output = _simulate_external_call_effects(rz, instruction_disasm, current_op, arch, bits)
                else:
                    exec_output = rz.cmd(f"aezsue hex(next_pc)")
                print(f"Step over execution output: {exec_output}")

                # 验证是否成功到达目标地址
                verify_pc_output = rz.cmd("aezvj PC")
                verify_pc_data = json.loads(verify_pc_output)
                actual_pc = int(verify_pc_data.get("PC", "0x0"), 16)

                if actual_pc != next_pc:
                    print(f"⚠️  PC mismatch: expected {hex(next_pc)}, got {hex(actual_pc)}")
                else:
                    print(f"✅ Successfully stepped over call to {hex(next_pc)}")

                all_outputs.append(exec_output)

            except Exception as e:
                print(f"❌ Failed to step over call: {e}")
                return ""
        else:
            print("👣 Regular instruction - single stepping...")

            # 对于非调用指令，使用正常单步执行
            try:
                exec_output = rz.cmd("aezsej 1")
                print(f"Single step execution output: {exec_output}")

                # 获取执行后的PC用于验证
                after_pc_output = rz.cmd("aezvj PC")
                after_pc_data = json.loads(after_pc_output)
                actual_pc = int(after_pc_data.get("PC", "0x0"), 16)

                print(f"✅ Single stepped from {hex(current_pc)} to {hex(actual_pc)}")

                all_outputs.append(exec_output)

            except Exception as e:
                print(f"❌ Failed to single step: {e}")
                return ""

    # 合并所有输出（如果有多步的话）
    if len(all_outputs) == 1:
        return all_outputs[0]
    else:
        # 对于多步执行，合并状态变化：只保留初始状态和最终状态
        return _merge_multi_step_changes(all_outputs)

def _execute_emulation_loop(
    rz_instance: rzpipe.open,
    max_steps: int,
    timeout_seconds: int,
    start_time: float,
    stack_bytes: int = 32, # 新增参数，用于指定栈快照的字节数
) -> Dict[str, Any]:
    """
    执行 RzIL 模拟的主循环，记录执行轨迹和 VM 状态变化。

    Args:
        rz_instance: 活跃的 rzpipe 实例。
        max_steps: 最大执行步数。
        timeout_seconds: 模拟超时时间（秒）。
        start_time: 模拟开始的时间戳，用于计算相对时间。

    Returns:
        一个字典，包含 'execution_trace' (执行轨迹), 'vm_state_changes' (VM 状态变化),
        和 'final_registers' (最终寄存器状态)。
    """
    trace: List[Dict[str, Any]] = []
    vm_changes: List[Dict[str, Any]] = []

    print("Starting RzIL execution loop...")

    for step in range(max_steps):
        step_start_time = time.time()
        print(f"\n=== Step {step} ===")

        # 获取当前寄存器状态
        try:
            regs_output = rz_instance.cmd("aezvj")
            current_regs = json.loads(regs_output) if regs_output.strip() else {}
        except Exception as e:
            print(f"Failed to get registers: {e}")
            current_regs = {}

        # 获取当前PC
        current_pc = None
        pc_candidates = ["rip", "pc", "eip", "ip", "PC"]
        for pc_reg in pc_candidates:
            if pc_reg in current_regs:
                current_pc = current_regs[pc_reg]
                break

        if current_pc is None:
            print("Cannot determine current PC")
            break

        # 获取当前指令
        try:
            disasm_output = rz_instance.cmd(f"pdj 1 @ {current_pc}")
            current_op = json.loads(disasm_output)[0] if disasm_output.strip() else {}
        except Exception as e:
            print(f"Failed to get instruction: {e}")
            current_op = {}

        # 记录步骤信息
        step_info = {
            "step": step,
            "pc": hex(current_pc) if isinstance(current_pc, int) else str(current_pc),
            "instruction": current_op.get("disasm", "unknown"),
            "opcode": current_op.get("opcode", ""),
            "type": current_op.get("type", ""),
            "registers": current_regs,
            "timestamp": time.time() - start_time,
            "step_duration": 0  # 将在步骤结束时更新
        }

        print(f"PC: {step_info['pc']}, Instruction: {step_info['instruction']}")
        if step_info['instruction'] == 'unknown':
            print("Eric says: debugging")
            pass

        # 获取执行前栈快照
        stack_before_hexdump = None
        sp_value = None
        sp_candidates = ["rsp", "esp", "sp"] # 按照优先级顺序
        for sp_reg in sp_candidates:
            if sp_reg in current_regs:
                sp_value = current_regs[sp_reg]
                break

        if sp_value is not None and isinstance(sp_value, str) and sp_value.startswith("0x"):
            try:
                stack_before_hexdump = rz_instance.cmd(f"pxwj {stack_bytes} @ {sp_value}").strip()
            except Exception as e:
                print(f"Error reading stack before execution: {e}")

        # 执行一步
        try:
            # 尝试带JSON输出的执行
            exec_output = rzil_step_over(rz_instance, 1).strip() # `aezsej 1` 是 step into
            print(f"Execution output: {exec_output}")

            vm_changes_data = []
            if exec_output:
                try:
                    vm_changes_data = json.loads(exec_output)
                except json.JSONDecodeError:
                    # 非JSON格式，直接记录为字符串
                    vm_changes_data = [{"type": "raw_exec_output", "content": exec_output}]

            # 获取执行后栈快照
            stack_after_hexdump = None
            if sp_value is not None and isinstance(sp_value, str) and sp_value.startswith("0x"):
                try:
                    stack_after_hexdump = rz_instance.cmd(f"pxwj {stack_bytes} @ {sp_value}").strip()
                except Exception as e:
                    print(f"Error reading stack after execution: {e}")

            # 对比栈快照，如果发生变化则添加到 vm_changes_data
            if stack_before_hexdump is not None and stack_after_hexdump is not None and stack_before_hexdump != stack_after_hexdump:
                vm_changes_data.append({
                    "type": "stack",
                    "old": stack_before_hexdump,
                    "new": stack_after_hexdump
                })
            elif stack_before_hexdump is None or stack_after_hexdump is None:
                # 如果任一快照获取失败，但之前没有记录错误，则记录
                if "stack_read_error" not in step_info:
                    step_info["stack_read_error"] = "Could not read stack before or after execution"

            if vm_changes_data:
                vm_changes.append({
                    "step": step,
                    "changes": vm_changes_data,
                    "timestamp": time.time() - start_time
                })

        except Exception as e:
            print(f"Execution of step {step} failed: {e}")
            step_info["execution_error"] = str(e)
            # 可以选择是否继续

        # 更新步骤持续时间
        step_info["step_duration"] = time.time() - step_start_time
        trace.append(step_info)

        # 检查超时
        if time.time() - start_time > timeout_seconds:
            print(f"⏰ Execution timeout ({timeout_seconds}s)")
            break

        # 检查是否到达返回指令
        if step_info.get("type") in ["ret", "retn", "retf", "return"]:
            print(f"🔚 Reached return instruction")
            break

    # 获取最终状态
    try:
        final_regs_output = rz_instance.cmd("aezvj")
        final_regs = json.loads(final_regs_output) if final_regs_output.strip() else {}
    except Exception as e:
        print(f"Failed to get final registers: {e}")
        final_regs = {}

    return {
        "execution_trace": trace,
        "vm_state_changes": vm_changes,
        "final_registers": final_regs
    }

def _improved_rzil_emulation(
    rz: rzpipe.open,
    function_name: str,
    max_steps: int,
    result_queue: queue.Queue,
    timeout_seconds: int = 30,
    stack_bytes: int = 32,
    stack_size: int = 0x10000,
    stack_base: int = 0x70000000,
    data_size: int = 0x1000,
    data_base: int = 0x60000000
):
    """
    基于实际环境的改进版 RzIL 模拟，支持外部传入 rzpipe 实例和锁。

    Args:
        rz: 外部传入的 rzpipe 实例，用于共享上下文。
        function_name: 要模拟的函数名。
        max_steps: 最大执行步数。
        result_queue: 用于返回结果的队列。
        timeout_seconds: 超时时间（秒）。
        stack_bytes: 栈快照字节数。
        stack_size: 栈大小。
        stack_base: 栈基址。
        data_size: 数据段大小。
        data_base: 数据段基址。
    """
    start_time = time.time()
    original_offset = None
    setup_log: List[str] = []

    try:
        # 1. 保存原始状态并导航到函数
        original_offset = rz.cmd("s").strip()
        seek_result = rz.cmd(f"s {function_name}") or rz.cmd("s").strip() + " (Done)"
        setup_log.append(f"Navigate to function {function_name}: {seek_result}")

        # 2. 获取架构信息
        binary_info = rz.cmdj("ij")
        if not binary_info:
            result_queue.put({"error": "Failed to get binary information", "success": False})
            return

        arch_info = binary_info.get("bin", {})
        global arch, bits
        arch = arch_info.get("arch", "unknown")
        bits = arch_info.get("bits", 64)
        setup_log.append(f"Detected architecture: {arch} {bits}-bit")

        # 3. 检查 RzIL 支持
        rzil_supported = _check_rzil_support(rz)
        setup_log.append(f"RzIL support check: {rzil_supported}")

        # 4. 初始化 RzIL VM
        print("Initializing RzIL VM...")
        init_result = rz.cmd("aezi") or "Initialization command Succeeded"
        setup_log.append(f"RzIL VM initialization: {init_result}")

        if "error" in init_result.lower():
            result_queue.put({
                "error": f"RzIL VM initialization failed: {init_result}",
                "success": False,
                "setup_log": setup_log
            })
            return

        # 5. 设置内存映射
        stack_pointer, base_pointer, initial_sp, memory_success = _setup_memory_with_malloc(
            rz, arch, bits, stack_size, stack_base, data_size, data_base
        )
        setup_log.append(f"Memory mapping setup: {'success' if memory_success else 'failed'}")

        # 6. 设置寄存器
        print(f"Setting registers: {stack_pointer} = {hex(initial_sp)}")
        sp_result = rz.cmd(f"aezv {stack_pointer} {hex(initial_sp)}")
        bp_result = rz.cmd(f"aezv {base_pointer} {hex(initial_sp)}")
        setup_log.append(f"Stack pointer setup: {sp_result.strip()}")
        setup_log.append(f"Base pointer setup: {bp_result.strip()}")

        # 7. 验证寄存器设置
        sp_verify = rz.cmd(f"aezv {stack_pointer}")
        setup_log.append(f"Stack pointer verification: {sp_verify.strip()}")

        # 8. 测试内存访问
        if memory_success:
            memory_test = _test_memory_access(rz, initial_sp)
            setup_log.append(f"Memory access test: {'passed' if memory_test else 'failed'}")

        # 9. 执行模拟循环
        emulation_results = _execute_emulation_loop(
            rz, max_steps, timeout_seconds, start_time, stack_bytes
        )
        trace = emulation_results["execution_trace"]
        vm_changes = emulation_results["vm_state_changes"]
        final_regs = emulation_results["final_registers"]

        # 10. 返回结果
        result_queue.put({
            "success": True,
            "execution_summary": {
                "steps_executed": len(trace),
                "execution_time": time.time() - start_time,
                "memory_setup_success": memory_success,
                "architecture": f"{arch} {bits}-bit"
            },
            "final_registers": final_regs,
            "execution_trace": trace,
            "vm_state_changes": vm_changes,
            "setup_log": setup_log,
            "emulation_type": "RzIL_v2"
        })

    except Exception as e:
        # 确保 trace 在异常发生时也可用
        partial_trace = locals().get('trace', [])
        result_queue.put({
            "error": str(e),
            "success": False,
            "execution_time": time.time() - start_time,
            "partial_trace": partial_trace,
            "setup_log": setup_log,
            "memory_setup_attempted": True
        })
    finally:
        # 恢复原始偏移量
        if original_offset:
            try:
                rz.cmd(f"s {original_offset}")
            except:
                pass

async def emulate_function_async(
    binary_path: str,
    function_name: str,
    max_steps: int = 5,
    timeout: int = 5,
    stack_bytes: int = 32,
    stack_size: int = 0x10000,
    stack_base: int = 0x70000000,
    data_size: int = 0x1000,
    data_base: int = 0x60000000
) -> Dict[str, Any]:
    """
    emulation_function 的异步版本。
    使用 Rizin 的 RzIL 模拟指定函数的执行，支持指定步数和超时，返回执行轨迹。

    此函数在单独线程中运行模拟，以防止复杂或无限循环导致挂起。模拟包括内存设置、外部调用处理和状态变化跟踪。
    所有操作均为线程安全，使用全局锁保护 rzpipe 操作。

    Args:
        binary_path: 二进制文件的路径。
        function_name: 要模拟的函数名称（例如 'main' 或符号名）。
        max_steps: 最大执行指令步数（默认: 100），防止无限执行。
        timeout: 模拟的最大等待时间（秒，默认: 60）。
        stack_bytes: 栈快照读取的字节数（默认: 32），用于跟踪栈变化。
        stack_size: 栈内存区域的大小（默认: 0x10000，即 64KB）。
        stack_base: 栈内存区域的基地址（默认: 0x70000000）。
        data_size: 额外数据内存区域的大小（默认: 0x1000，即 4KB）。
        data_base: 额外数据内存区域的基地址（默认: 0x60000000）。

    Returns:
        一个字典，包含模拟结果：
            - 'success': bool，是否成功完成模拟。
            - 'final_registers': dict，最终寄存器状态。
            - 'execution_trace': list[dict]，每个步骤的执行信息（包括 PC、指令、寄存器等）。
            - 'vm_state_changes': list[dict]，VM 状态变化记录（寄存器/内存写入等）。
            - 'execution_summary': dict，摘要信息（步骤数、执行时间、架构等）。
            - 'emulation_type': str，模拟类型（例如 'RzIL_v2'）。
            - 'setup_log': list[str]，设置过程日志（可选）。
        如果发生错误或超时：
            - 'error': str，错误消息。
            - 'timeout': bool（如果超时）。
            - 'partial_trace': list[dict]（部分执行轨迹，如果可用）。

    Raises:
        无显式抛出，但内部可能因 rzpipe 错误而异常；结果通过返回字典处理。

    示例:
        result = emulate_function('/path/to/binary', 'main', max_steps=50)
        if result['success']:
            print(result['execution_summary'])
    """
    loop = asyncio.get_running_loop()

    # Run the synchronous parts in a thread
    def sync_emulation():
        with rz_lock:
            rz = _open_rzpipe(binary_path)
            try:
                # 创建结果队列
                result_queue = queue.Queue()

                # 在单独线程中执行模拟
                thread = threading.Thread(
                    target=_improved_rzil_emulation,
                    args=(rz, function_name, max_steps, result_queue, timeout,
                          stack_bytes, stack_size, stack_base, data_size, data_base),
                    daemon=True
                )
                thread.start()
                thread.join(timeout=timeout + 5)

                if thread.is_alive():
                    return {
                        "error": f"Emulation timed out after {timeout} seconds",
                        "success": False,
                        "timeout": True
                    }

                try:
                    return result_queue.get_nowait()
                except queue.Empty:
                    return {
                        "error": f"Emulation completed but no result available",
                        "success": False,
                        "timeout": True
                    }
            finally:
                rz.quit()

    return await loop.run_in_executor(None, sync_emulation)

# ========== 使用示例和测试代码 ==========

def test_external_call_simulation():
    """
    测试外部调用模拟功能的示例代码
    """
    print("🧪 Testing external call simulation...")

    # 示例：模拟不同架构下的printf调用
    test_cases = [
        {
            "arch": "x86",
            "bits": 64,
            "instruction": "call sym.imp.printf",
            "current_op": {"offset": 0x1000, "size": 5}
        },
        {
            "arch": "arm",
            "bits": 64,
            "instruction": "bl sym.imp.printf",
            "current_op": {"offset": 0x2000, "size": 4}
        },
        {
            "arch": "ppc",
            "bits": 32,
            "instruction": "bl reloc.printf",
            "current_op": {"offset": 0x3000, "size": 4}
        }
    ]

    for test_case in test_cases:
        print(f"\n--- Testing {test_case['arch']} {test_case['bits']}-bit ---")

        # 模拟rzpipe实例（在实际使用中这会是真实的rzpipe对象）
        class MockRzInstance:
            def __init__(self, arch, bits):
                self.arch = arch
                self.bits = bits
                self.registers = {}

            def cmd(self, command):
                if command.startswith("aezv") and "0x" in command:
                    # 模拟设置寄存器
                    parts = command.split()
                    if len(parts) >= 3:
                        reg_name = parts[1]
                        value = parts[2]
                        self.registers[reg_name] = value
                        return f"{reg_name}: {value}"
                elif command.startswith("aezv"):
                    # 模拟读取寄存器
                    reg_name = command.split()[1]
                    return self.registers.get(reg_name, "0x0")
                return ""

            def cmdj(self, command):
                if command == "ij":
                    return {
                        "bin": {
                            "arch": self.arch,
                            "bits": self.bits
                        }
                    }
                return {}

        mock_rz = MockRzInstance(test_case["arch"], test_case["bits"])

        # 执行测试
        try:
            result = _simulate_external_call_effects(
                mock_rz,
                test_case["instruction"],
                test_case["current_op"],
                test_case["arch"],
                test_case["bits"]
            )

            print(f"✅ Simulation result: {result}")

        except Exception as e:
            print(f"❌ Test failed: {e}")

async def enhanced_emulate_function_example(binary_path: str, function_name: str, max_steps: int = 20, timeout: int = 60):
    """
    展示如何使用增强版的模拟功能
    """
    print("\n" + "="*60)
    print("🚀 Enhanced RzIL Emulation Example")
    print("="*60)

    # 调用增强版模拟函数，支持自定义参数
    result = await emulate_function_async(
        binary_path=binary_path,
        function_name=function_name,
        max_steps=max_steps,
        timeout=timeout,
        stack_bytes=64,           # 读取64字节的栈快照
        stack_size=0x20000,       # 128KB栈大小
        stack_base=0x70000000,    # 栈基地址
        data_size=0x2000,         # 8KB数据区域
        data_base=0x60000000      # 数据区域基地址
    )

    if result.get("success"):
        print("✅ Enhanced emulation completed successfully!")

        # 分析执行轨迹中的外部调用
        trace = result.get("execution_trace", [])
        external_calls = []

        for step in trace:
            instruction = step.get("instruction", "")
            if any(keyword in instruction.lower() for keyword in ["sym.imp.", "reloc.", "plt"]):
                external_calls.append({
                    "step": step.get("step"),
                    "pc": step.get("pc"),
                    "instruction": instruction,
                    "type": step.get("type")
                })

        if external_calls:
            print(f"\n📞 Found {len(external_calls)} external calls:")
            for call in external_calls:
                print(f"  Step {call['step']}: {call['pc']} - {call['instruction']}")

        # 分析VM状态变化
        vm_changes = result.get("vm_state_changes", [])
        external_effects = 0

        for change_record in vm_changes:
            changes = change_record.get("changes", [])
            for change in changes:
                if isinstance(change, dict) and change.get("type") in ["external_call", "simulation_error"]:
                    external_effects += 1

        if external_effects > 0:
            print(f"🎭 External call effects simulated: {external_effects}")

    else:
        print(f"❌ Enhanced emulation failed: {result.get('error')}")

if __name__ == "__main__":
    # 运行测试
    test_external_call_simulation()

    # 显示使用示例
    binary_path = "/Users/yingdong/VSCode/angr/angr_ctf/00_angr_find/00_angr_find_arm"
    function_name = "main"
    max_steps = 8
    timeout = 3600
    asyncio.run(enhanced_emulate_function_example(binary_path, function_name, max_steps, timeout))
