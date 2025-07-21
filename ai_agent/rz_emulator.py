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

def rzil_step_over(rz_instance, num_steps: int = 1) -> str:
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
            pc_output = rz_instance.cmd("aezvj PC")
            pc_data = json.loads(pc_output)
            current_pc = pc_data.get("PC", "0x0")
        except Exception as e:
            print(f"Failed to get current PC: {e}")
            return ""

        print(f"Current PC: {current_pc}")

        # 获取当前指令信息
        try:
            disasm_output = rz_instance.cmd(f"pdj 1 @ {current_pc}")
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
                disasm_output = rz_instance.cmd(f"pdj 2 @ {current_pc}")
                if disasm_output.strip():
                    instructions = json.loads(disasm_output)
                    if len(instructions) < 2:
                        print(f"Cannot get next instruction after call at {current_pc}")
                        return ""
                    next_op = instructions[1]
                    next_pc = hex(next_op.get("offset", 0))
                else:
                    print(f"Cannot get instructions at {current_pc}")
                    return ""

                print(f"Stepping over call to: {next_pc}")

                # 执行到下一条指令
                if _is_external_function_call(current_op, instruction_disasm):
                    print("Simulating external call effects...")
                    exec_output = _simulate_external_call_effects(rz_instance, instruction_disasm, current_op, arch, bits)
                else:
                    exec_output = rz_instance.cmd(f"aezsue {next_pc}")
                print(f"Step over execution output: {exec_output}")

                # 验证是否成功到达目标地址
                verify_pc_output = rz_instance.cmd("aezvj PC")
                verify_pc_data = json.loads(verify_pc_output)
                actual_pc = verify_pc_data.get("PC", "0x0")

                if actual_pc.lower() != next_pc.lower():
                    print(f"⚠️  PC mismatch: expected {next_pc}, got {actual_pc}")
                else:
                    print(f"✅ Successfully stepped over call to {next_pc}")

                all_outputs.append(exec_output)

            except Exception as e:
                print(f"❌ Failed to step over call: {e}")
                return ""
        else:
            print("👣 Regular instruction - single stepping...")

            # 对于非调用指令，使用正常单步执行
            try:
                exec_output = rz_instance.cmd("aezsej 1")
                print(f"Single step execution output: {exec_output}")

                # 获取执行后的PC用于验证
                after_pc_output = rz_instance.cmd("aezvj PC")
                after_pc_data = json.loads(after_pc_output)
                actual_pc = after_pc_data.get("PC", "0x0")

                print(f"✅ Single stepped from {current_pc} to {actual_pc}")

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
    rz_instance,
    function_name,
    max_steps,
    result_queue,
    timeout_seconds=30,
    stack_bytes: int = 32, # 新增参数
    stack_size: int = 0x10000, # 新增参数
    stack_base: int = 0x70000000, # 新增参数
    data_size: int = 0x1000, # 新增参数
    data_base: int = 0x60000000 # 新增参数
):
    """
    基于实际环境的改进版 RzIL 模拟
    """
    start_time = time.time()
    original_offset = None
    setup_log: List[str] = [] # 明确类型注解

    try:
        # 1. 保存原始状态并导航到函数
        original_offset = rz_instance.cmd("s").strip()
        seek_result = rz_instance.cmd(f"s {function_name}") or rz_instance.cmd("s").strip() + " (Done)"
        setup_log.append(f"Navigate to function {function_name}: {seek_result}")

        # 2. 获取架构信息
        binary_info = rz_instance.cmdj("ij")
        if not binary_info:
            result_queue.put({"error": "Failed to get binary information", "success": False})
            return

        arch_info = binary_info.get("bin", {})
        global arch, bits
        arch = arch_info.get("arch", "unknown")
        bits = arch_info.get("bits", 64)
        setup_log.append(f"Detected architecture: {arch} {bits}-bit")

        # 3. 检查 RzIL 支持
        rzil_supported = _check_rzil_support(rz_instance)
        setup_log.append(f"RzIL support check: {rzil_supported}")

        # 4. 初始化 RzIL VM
        print("Initializing RzIL VM...")
        init_result = rz_instance.cmd("aezi") or "Initialization command Succeeded"
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
            rz_instance, arch, bits, stack_size, stack_base, data_size, data_base # 传递参数
        )
        setup_log.append(f"Memory mapping setup: {'success' if memory_success else 'failed'}")

        # 6. 设置寄存器
        print(f"Setting registers: {stack_pointer} = {hex(initial_sp)}")
        sp_result = rz_instance.cmd(f"aezv {stack_pointer} {hex(initial_sp)}")
        bp_result = rz_instance.cmd(f"aezv {base_pointer} {hex(initial_sp)}")
        setup_log.append(f"Stack pointer setup: {sp_result.strip()}")
        setup_log.append(f"Base pointer setup: {bp_result.strip()}")

        # 7. 验证寄存器设置
        sp_verify = rz_instance.cmd(f"aezv {stack_pointer}")
        setup_log.append(f"Stack pointer verification: {sp_verify.strip()}")

        # 8. 测试内存访问
        if memory_success:
            memory_test = _test_memory_access(rz_instance, initial_sp)
            setup_log.append(f"Memory access test: {'passed' if memory_test else 'failed'}")

        # 9. 执行模拟循环
        emulation_results = _execute_emulation_loop(
            rz_instance, max_steps, timeout_seconds, start_time, stack_bytes # 传递 stack_bytes
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
                rz_instance.cmd(f"s {original_offset}")
            except:
                pass

def emulate_function(
    binary_path: str,
    function_name: str,
    max_steps: int = 100,
    timeout: int = 60,
    stack_bytes: int = 32, # 新增参数
    stack_size: int = 0x10000, # 新增参数
    stack_base: int = 0x70000000, # 新增参数
    data_size: int = 0x1000, # 新增参数
    data_base: int = 0x60000000 # 新增参数
) -> Dict[str, Any]:
    """
    Emulates a function using Rizin's RzIL for a number of steps and returns the trace.

    This function uses a separate thread to run the emulation, allowing for a
    timeout to prevent hangs on complex or infinite loops.

    Args:
        binary_path: The path to the binary file.
        function_name: The name of the function to emulate.
        max_steps: The maximum number of instructions to emulate.
        timeout: The maximum time in seconds to wait for the emulation to complete.

    Returns:
        A dictionary containing the emulation result, including 'success' status,
        'final_registers', 'execution_trace' of execution steps, 'vm_state_changes' (VM state changes),
        'execution_summary', and 'emulation_type'.
        If an error occurs or timeout is reached, an 'error' message is included.
    """
    with rz_lock:
        print(f"🚀 Starting emulation: {binary_path} -> {function_name}")

        rz = _open_rzpipe(binary_path)
        try:
            # 创建结果队列
            result_queue = queue.Queue()

            # 在单独线程中执行模拟
            thread = threading.Thread(
                target=_improved_rzil_emulation,
                args=(rz, function_name, max_steps, result_queue, timeout,
                      stack_bytes, stack_size, stack_base, data_size, data_base), # 传递所有参数
                daemon=True
            )

            thread.start()

            try:
                result = result_queue.get(timeout=timeout + 10)
                return result
            except queue.Empty:
                return {
                    "error": f"Emulation timed out after {timeout} seconds",
                    "success": False,
                    "timeout": True
                }

        finally:
            rz.quit()

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

def enhanced_emulate_function_example():
    """
    展示如何使用增强版的模拟功能
    """
    print("\n" + "="*60)
    print("🚀 Enhanced RzIL Emulation Example")
    print("="*60)

    # 使用示例
    binary_path = "/Users/yingdong/VSCode/angr/angr_ctf/00_angr_find/00_angr_find_arm"
    function_name = "entry0"

    # 调用增强版模拟函数，支持自定义参数
    result = emulate_function(
        binary_path=binary_path,
        function_name=function_name,
        max_steps=100,
        timeout=60,
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
    enhanced_emulate_function_example()

# # ========== LEGACY FUNCTIONS (kept for compatibility) ==========

# def _initialize_rzil_vm(rz_instance, result_queue):
#     """
#     初始化 RzIL VM 并处理初始化失败的情况。
#     """
#     # 3. 初始化 RzIL VM
#     init_result = rz_instance.cmd("aezi")
#     if "error" in init_result.lower() or "fail" in init_result.lower():
#         result_queue.put({
#             "error": f"Failed to initialize RzIL VM: {init_result}",
#             "success": False
#         })
#         return False
#     return True

# def _get_arch_specific_registers(binary_info):
#     """
#     根据二进制信息确定架构和位数，返回相应的栈指针、基指针和初始栈地址。
#     """
#     # 获取架构信息来确定正确的寄存器名称
#     arch_info = binary_info.get("bin", {})
#     arch = arch_info.get("arch", "x86")
#     bits = arch_info.get("bits", 64)

#     # 根据架构设置合适的栈指针
#     if arch == "x86" and bits == 64:
#         # x86_64 架构
#         stack_pointer = "rsp"
#         base_pointer = "rbp"
#         initial_sp = 0x7fffff000000  # 简化的栈地址
#     elif arch == "x86" and bits == 32:
#         # x86_32 架构
#         stack_pointer = "esp"
#         base_pointer = "ebp"
#         initial_sp = 0xbffff000
#     elif arch == "arm" and bits == 64:
#         # ARM64 架构
#         stack_pointer = "sp"
#         base_pointer = "fp"
#         initial_sp = 0x7fffff000000
#     elif arch == "arm" and bits == 32:
#         # ARM32 架构
#         stack_pointer = "sp"
#         base_pointer = "fp"
#         initial_sp = 0xbffff000
#     else:
#         # 默认值
#         stack_pointer = "sp"
#         base_pointer = "fp"
#         initial_sp = 0x7fffff000000

#     # 设置栈指针（确保16字节对齐）
#     aligned_sp = initial_sp & ~0xF
#     return arch, bits, stack_pointer, base_pointer, aligned_sp

# def _set_initial_registers(rz_instance, stack_pointer, base_pointer, aligned_sp):
#     """
#     设置初始寄存器值。
#     """
#     rz_instance.cmd(f"aezv {stack_pointer} {hex(aligned_sp)}")
#     rz_instance.cmd(f"aezv {base_pointer} {hex(aligned_sp)}")

#     # 5. 验证设置
#     current_sp = rz_instance.cmd(f"aezv {stack_pointer}")
#     print(f"Stack pointer ({stack_pointer}) set to: {current_sp.strip()}")

# def _get_current_emulation_state(rz_instance, start_time, step):
#     """
#     获取当前寄存器状态、PC、指令信息和 RzIL 表示。
#     """
#     # 7. 获取当前寄存器状态
#     current_regs = {}
#     try:
#         regs_json = rz_instance.cmd("aezvj")  # 使用 JSON 格式获取 VM 寄存器
#         if not regs_json.strip():
#             # 如果 aezvj 不工作，尝试标准的寄存器命令
#             regs_json = rz_instance.cmd("drj")
#         current_regs = json.loads(regs_json) if regs_json.strip() else {}
#     except json.JSONDecodeError:
#         current_regs = {}

#     # 8. 获取当前PC
#     current_pc = None
#     pc_candidates = ["rip", "pc", "eip", "ip", "PC"]
#     for pc_reg in pc_candidates:
#         if pc_reg in current_regs:
#             current_pc = current_regs[pc_reg]
#             break

#     if current_pc is None:
#         print("Cannot determine current PC, stopping execution")
#         return None, None, None, None, None

#     # 9. 获取当前指令信息
#     current_op = {}
#     try:
#         disasm_json = rz_instance.cmd(f"pdj 1 @ {current_pc}")
#         if disasm_json.strip():
#             current_op = json.loads(disasm_json)[0]
#         else:
#             current_op = {}
#     except (json.JSONDecodeError, IndexError):
#         current_op = {}

#     # 10. 获取RzIL表示（如果可用）
#     rzil_repr = ""
#     try:
#         rzil_repr = rz_instance.cmd(f"aoip 1 @ {current_pc}")
#     except:
#         rzil_repr = "N/A"

#     # 11. 记录当前状态
#     step_info = {
#         "step": step,
#         "pc": hex(current_pc) if isinstance(current_pc, int) else str(current_pc),
#         "op": current_op.get("disasm", ""),
#         "opcode": current_op.get("opcode", ""),
#         "type": current_op.get("type", ""),
#         "rzil": rzil_repr.strip(),
#         "regs": current_regs,
#         "timestamp": time.time() - start_time
#     }
#     return step_info, current_pc, current_op, current_regs, rzil_repr

# def _check_emulation_termination(step_info, step_output, timeout_seconds, start_time, trace):
#     """
#     检查模拟是否应该终止（超时、返回指令、执行错误、无限循环）。
#     返回 True 表示应该终止，False 表示继续。
#     """
#     # 超时检查
#     if time.time() - start_time > timeout_seconds:
#         print(f"Execution timed out after {timeout_seconds} seconds")
#         return True

#     # 检查是否到达函数结尾
#     op_type = step_info.get("type", "")
#     if op_type in ["ret", "retn", "retf", "return"]:
#         print(f"Reached return instruction at step {step_info['step']}")
#         return True

#     # 检查是否有执行错误
#     if step_output and any(keyword in str(step_output).lower() for keyword in ["error", "invalid", "failed"]):
#         print(f"Execution error at step {step_info['step']}: {step_output}")
#         return True

#     # 简单的无限循环检测
#     if step_info['step'] > 0 and len(trace) >= 2:
#         prev_pc = trace[-2]["pc"]
#         if prev_pc == step_info["pc"] and op_type not in ["nop", "call"]:
#             print(f"Possible infinite loop detected at step {step_info['step']}")
#             return True
#     return False

# def _emulate_function_target_rzil(rz_instance, function_name, max_steps, result_queue, timeout_seconds=30):
#     """
#     修正后的 RzIL 模拟函数，移除了不存在的命令并优化了内存处理。

#     NOTE: This is the legacy function - use emulate_function() for the improved version.

#     Args:
#         rz_instance: 活跃的 rzpipe 实例。
#         function_name: 要模拟的函数名称。
#         max_steps: 最大执行步数。
#         result_queue: 用于放置模拟结果的队列。
#         timeout_seconds: 超时时间（秒）。
#     """
#     start_time = time.time()
#     original_offset = None
#     trace = []
#     vm_changes = []

#     try:
#         # 1. 保存当前偏移量并跳转到函数
#         original_offset = rz_instance.cmd("s").strip()
#         rz_instance.cmd(f"s {function_name}")

#         # 2. 获取二进制信息
#         binary_info = rz_instance.cmdj("ij")
#         if not binary_info:
#             result_queue.put({
#                 "error": "Failed to get binary information",
#                 "success": False
#             })
#             return

#         # 3. 初始化 RzIL VM
#         if not _initialize_rzil_vm(rz_instance, result_queue):
#             return

#         # 4. 设置基本的寄存器初始值
#         arch, bits, stack_pointer, base_pointer, aligned_sp = _get_arch_specific_registers(binary_info)
#         _set_initial_registers(rz_instance, stack_pointer, base_pointer, aligned_sp)

#         # 6. 开始执行循环
#         for step in range(max_steps):
#             step_info, current_pc, current_op, current_regs, rzil_repr = _get_current_emulation_state(rz_instance, start_time, step)

#             if current_pc is None:
#                 # Cannot determine current PC, stopping execution (handled in _get_current_emulation_state)
#                 break

#             trace.append(step_info)

#             # 12. 执行一步并记录状态变化
#             try:
#                 step_output = rz_instance.cmd("aezsej 1")
#                 if step_output.strip():
#                     try:
#                         step_output_parsed = json.loads(step_output)
#                     except json.JSONDecodeError:
#                         step_output_parsed = step_output
#                 else:
#                     step_output_parsed = None
#             except Exception as e:
#                 print(f"执行错误: {e}")
#                 break

#             # 记录VM状态变化
#             if step_output_parsed:
#                 vm_changes.append({
#                     "step": step,
#                     "changes": step_output_parsed,
#                     "timestamp": time.time() - start_time
#                 })

#             # 检查是否应该终止模拟
#             if _check_emulation_termination(step_info, step_output, timeout_seconds, start_time, trace):
#                 break

#         # 16. 获取最终状态
#         final_regs = {}
#         try:
#             final_regs_json = rz_instance.cmd("aezvj")
#             if not final_regs_json.strip():
#                 final_regs_json = rz_instance.cmd("arj")
#             final_regs = json.loads(final_regs_json) if final_regs_json.strip() else {}
#         except json.JSONDecodeError:
#             final_regs = {}

#         result_queue.put({
#             "success": True,
#             "final_regs": final_regs,
#             "trace": trace,
#             "vm_changes": vm_changes,
#             "steps_executed": len(trace),
#             "execution_time": time.time() - start_time,
#             "emulation_type": "RzIL_Legacy",
#             "memory_setup": {
#                 "architecture": arch,
#                 "bits": bits,
#                 "stack_pointer": stack_pointer,
#                 "initial_sp": hex(aligned_sp)
#             }
#         })

#     except Exception as e:
#         result_queue.put({
#             "error": str(e),
#             "success": False,
#             "execution_time": time.time() - start_time,
#             "partial_trace": trace if 'trace' in locals() else []
#         })
#     finally:
#         # 清理：恢复到原始偏移量
#         if original_offset:
#             try:
#                 rz_instance.cmd(f"s {original_offset}")
#             except:
#                 pass

# def setup_realistic_memory_layout(rz_instance):
#     """
#     设置更真实的内存布局，包括代码段、数据段和栈段

#     NOTE: This function uses non-existent commands and is kept for legacy compatibility only.
#     Use _setup_memory_with_malloc() instead.
#     """
#     print("WARNING: setup_realistic_memory_layout() uses non-existent 'aezm' command")
#     print("Please use the updated emulate_function() which uses malloc:// protocol")
#     return False

# def emulate_function_with_timeout(rz_instance, function_name, max_steps=1000, timeout=30):
#     """
#     带超时的函数模拟包装器

#     NOTE: This is a legacy function. Use emulate_function() for the improved version.

#     Args:
#         rz_instance: rzpipe实例
#         function_name: 函数名
#         max_steps: 最大步数
#         timeout: 超时时间（秒）

#     Returns:
#         dict: 模拟结果
#     """
#     result_queue = queue.Queue()

#     # 启动模拟线程
#     emulation_thread = threading.Thread(
#         target=_emulate_function_target_rzil,
#         args=(rz_instance, function_name, max_steps, result_queue, timeout)
#     )

#     emulation_thread.daemon = True
#     emulation_thread.start()

#     try:
#         # 等待结果或超时
#         result = result_queue.get(timeout=timeout + 5)  # 给一些缓冲时间
#         return result
#     except queue.Empty:
#         return {
#             "error": f"Emulation timed out after {timeout} seconds",
#             "success": False
#         }
#     finally:
#         if emulation_thread.is_alive():
#             # 线程仍在运行，但我们已经超时了
#             pass


# if __name__ == "__main__":
#     binary_path = "/Users/yingdong/VSCode/angr/angr_ctf/00_angr_find/00_angr_find_arm"  # Example binary path
#     function_name = "entry0"  # Example function name

#     print("=" * 60)
#     print("Rizin Binary Analysis with Improved RzIL Emulation")
#     print("=" * 60)

#     # Test the improved emulation function
#     print(f"\n🚀 Testing improved RzIL emulation:")
#     result = emulate_function(binary_path, function_name, max_steps=100, timeout=3600)

#     print("\n" + "=" * 40)
#     print("🔍 Emulation Results Analysis")
#     print("=" * 40)

#     if result.get("success"):
#         print("✅ Emulation completed successfully!")

#         # Display execution summary
#         summary = result.get("execution_summary", {})
#         print(f"📊 Steps executed: {summary.get('steps_executed', 0)}")
#         print(f"⏱️  Execution time: {summary.get('execution_time', 0):.3f}s")
#         print(f"🏗️  Memory setup: {'✅' if summary.get('memory_setup_success') else '❌'}")
#         print(f"🔧 Architecture: {summary.get('architecture', 'unknown')}")

#         # Display execution trace
#         trace = result.get("execution_trace", [])
#         if trace:
#             print(f"\n📋 Execution trace:")
#             for step_info in trace:
#                 step_num = step_info.get("step", "?")
#                 pc = step_info.get("pc", "?")
#                 instruction = step_info.get("instruction", "?")
#                 duration = step_info.get("step_duration", 0)

#                 status = "✅"
#                 if step_info.get("memory_warning"):
#                     status = "⚠️"
#                 elif step_info.get("execution_error"):
#                     status = "❌"

#                 print(f"  {status} Step {step_num}: {pc} - {instruction} ({duration:.3f}s)")

#                 if step_info.get("memory_warning"):
#                     print(f"    ⚠️  Memory warning: {step_info['memory_warning']}")

#         # Display VM state changes
#         vm_changes = result.get("vm_state_changes", [])
#         if vm_changes:
#             print(f"\n🔄 VM state changes: {len(vm_changes)} changes recorded")

#     else:
#         print("❌ Emulation failed")
#         print(f"Error: {result.get('error', 'Unknown error')}")

#         if result.get("setup_log"):
#             print("\n📋 Setup log:")
#             for log_entry in result["setup_log"]:
#                 print(f"  • {log_entry}")
