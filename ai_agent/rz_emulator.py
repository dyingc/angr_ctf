"""
This module provides RzIL emulation functionalities for binary analysis using the Rizin
framework via the rzpipe library.

It includes functions for memory allocation, RzIL VM setup, and function emulation.
All operations are designed to be thread-safe.
"""
import rzpipe
import json
from typing import Dict, Any, List, Optional
import re
import concurrent.futures
import threading
import queue
import time

# Global lock for rzpipe operations to prevent race conditions
rz_lock = threading.Lock()

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
        print(f"Architecture support list:\n{arch_list}")

        # 检查当前架构
        arch_info = rz_instance.cmdj("ij")
        current_arch = arch_info.get("bin", {}).get("arch", "unknown")
        print(f"Current architecture: {current_arch}")

        return True  # 假设支持，如果不支持会在后续步骤中发现
    except Exception as e:
        print(f"Error checking RzIL support: {e}")
        return False

def _setup_memory_with_malloc(rz_instance, arch, bits):
    """
    使用您验证过的 malloc:// 方法设置内存
    """
    try:
        print("Setting up memory mapping (using malloc:// protocol)...")

        # 1. 检查当前状态
        print("Current file list:")
        current_files = rz_instance.cmd("ol")
        print(current_files)

        # 2. 创建栈内存区域 - 使用您验证过的格式
        stack_size = 0x10000  # 64KB 栈（比较保守的大小）
        stack_base = 0x70000000  # 使用一个安全的基地址

        # 使用您验证过的命令格式: o malloc://size address
        stack_cmd = f"o malloc://{hex(stack_size)} {hex(stack_base)}"
        print(f"Executing stack mapping command: {stack_cmd}")
        stack_result = rz_instance.cmd(stack_cmd)
        print(f"Stack mapping result: {stack_result}")

        # 3. 创建额外的数据内存区域
        data_size = 0x1000  # 4KB 数据区域
        data_base = 0x60000000
        data_cmd = f"o malloc://{hex(data_size)} {hex(data_base)}"
        print(f"Executing data mapping command: {data_cmd}")
        data_result = rz_instance.cmd(data_cmd)
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

def _improved_rzil_emulation(rz_instance, function_name, max_steps, result_queue, timeout_seconds=30):
    """
    基于实际环境的改进版 RzIL 模拟
    """
    start_time = time.time()
    original_offset = None
    trace = []
    vm_changes = []
    setup_log = []

    try:
        # 1. 保存原始状态并导航到函数
        original_offset = rz_instance.cmd("s").strip()
        seek_result = rz_instance.cmd(f"s {function_name}")
        setup_log.append(f"Navigate to function {function_name}: {seek_result}")

        # 2. 获取架构信息
        binary_info = rz_instance.cmdj("ij")
        if not binary_info:
            result_queue.put({"error": "Failed to get binary information", "success": False})
            return

        arch_info = binary_info.get("bin", {})
        arch = arch_info.get("arch", "unknown")
        bits = arch_info.get("bits", 64)
        setup_log.append(f"Detected architecture: {arch} {bits}-bit")

        # 3. 检查 RzIL 支持
        rzil_supported = _check_rzil_support(rz_instance)
        setup_log.append(f"RzIL support check: {rzil_supported}")

        # 4. 初始化 RzIL VM
        print("Initializing RzIL VM...")
        init_result = rz_instance.cmd("aezi")
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
            rz_instance, arch, bits
        )
        setup_log.append(f"Memory mapping setup: {'success' if memory_success else 'failed'}")

        # 6. 设置寄存器
        print(f"Setting registers: {stack_pointer} = {hex(initial_sp)}")
        sp_result = rz_instance.cmd(f"aezv {stack_pointer} {hex(initial_sp)}")
        bp_result = rz_instance.cmd(f"aezv {base_pointer} {hex(initial_sp)}")
        setup_log.append(f"Stack pointer setup: {sp_result}")
        setup_log.append(f"Base pointer setup: {bp_result}")

        # 7. 验证寄存器设置
        sp_verify = rz_instance.cmd(f"aezv {stack_pointer}")
        setup_log.append(f"Stack pointer verification: {sp_verify.strip()}")

        # 8. 测试内存访问
        if memory_success:
            memory_test = _test_memory_access(rz_instance, initial_sp)
            setup_log.append(f"Memory access test: {'passed' if memory_test else 'failed'}")

        # 9. 开始执行循环
        print("Starting RzIL execution...")
        setup_log.append("Starting execution loop")

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

            # 执行一步
            try:
                # 尝试带JSON输出的执行
                exec_output = rz_instance.cmd("aezsej 1")
                print(f"Execution output: {exec_output}")

                if exec_output.strip():
                    try:
                        vm_changes_data = json.loads(exec_output)
                        vm_changes.append({
                            "step": step,
                            "changes": vm_changes_data,
                            "timestamp": time.time() - start_time
                        })
                    except json.JSONDecodeError:
                        # 非JSON格式，直接记录
                        vm_changes.append({
                            "step": step,
                            "changes": exec_output,
                            "timestamp": time.time() - start_time
                        })

                # 检查是否有 StoreW 错误
                if "storew" in exec_output.lower() and ("failed" in exec_output.lower() or "error" in exec_output.lower()):
                    print(f"⚠️  Memory write warning: {exec_output}")
                    # 记录警告但继续执行
                    step_info["memory_warning"] = exec_output

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

        # 10. 获取最终状态
        try:
            final_regs_output = rz_instance.cmd("aezvj")
            final_regs = json.loads(final_regs_output) if final_regs_output.strip() else {}
        except Exception as e:
            print(f"Failed to get final registers: {e}")
            final_regs = {}

        # 11. 返回结果
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
        result_queue.put({
            "error": str(e),
            "success": False,
            "execution_time": time.time() - start_time,
            "partial_trace": trace,
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

def emulate_function(binary_path: str, function_name: str, max_steps: int = 100, timeout: int = 60) -> Dict[str, Any]:
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
                args=(rz, function_name, max_steps, result_queue, timeout),
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

# ========== LEGACY FUNCTIONS (kept for compatibility) ==========

def _initialize_rzil_vm(rz_instance, result_queue):
    """
    初始化 RzIL VM 并处理初始化失败的情况。
    """
    # 3. 初始化 RzIL VM
    init_result = rz_instance.cmd("aezi")
    if "error" in init_result.lower() or "fail" in init_result.lower():
        result_queue.put({
            "error": f"Failed to initialize RzIL VM: {init_result}",
            "success": False
        })
        return False
    return True

def _get_arch_specific_registers(binary_info):
    """
    根据二进制信息确定架构和位数，返回相应的栈指针、基指针和初始栈地址。
    """
    # 获取架构信息来确定正确的寄存器名称
    arch_info = binary_info.get("bin", {})
    arch = arch_info.get("arch", "x86")
    bits = arch_info.get("bits", 64)

    # 根据架构设置合适的栈指针
    if arch == "x86" and bits == 64:
        # x86_64 架构
        stack_pointer = "rsp"
        base_pointer = "rbp"
        initial_sp = 0x7fffff000000  # 简化的栈地址
    elif arch == "x86" and bits == 32:
        # x86_32 架构
        stack_pointer = "esp"
        base_pointer = "ebp"
        initial_sp = 0xbffff000
    elif arch == "arm" and bits == 64:
        # ARM64 架构
        stack_pointer = "sp"
        base_pointer = "fp"
        initial_sp = 0x7fffff000000
    elif arch == "arm" and bits == 32:
        # ARM32 架构
        stack_pointer = "sp"
        base_pointer = "fp"
        initial_sp = 0xbffff000
    else:
        # 默认值
        stack_pointer = "sp"
        base_pointer = "fp"
        initial_sp = 0x7fffff000000

    # 设置栈指针（确保16字节对齐）
    aligned_sp = initial_sp & ~0xF
    return arch, bits, stack_pointer, base_pointer, aligned_sp

def _set_initial_registers(rz_instance, stack_pointer, base_pointer, aligned_sp):
    """
    设置初始寄存器值。
    """
    rz_instance.cmd(f"aezv {stack_pointer} {hex(aligned_sp)}")
    rz_instance.cmd(f"aezv {base_pointer} {hex(aligned_sp)}")

    # 5. 验证设置
    current_sp = rz_instance.cmd(f"aezv {stack_pointer}")
    print(f"Stack pointer ({stack_pointer}) set to: {current_sp.strip()}")

def _get_current_emulation_state(rz_instance, start_time, step):
    """
    获取当前寄存器状态、PC、指令信息和 RzIL 表示。
    """
    # 7. 获取当前寄存器状态
    current_regs = {}
    try:
        regs_json = rz_instance.cmd("aezvj")  # 使用 JSON 格式获取 VM 寄存器
        if not regs_json.strip():
            # 如果 aezvj 不工作，尝试标准的寄存器命令
            regs_json = rz_instance.cmd("drj")
        current_regs = json.loads(regs_json) if regs_json.strip() else {}
    except json.JSONDecodeError:
        current_regs = {}

    # 8. 获取当前PC
    current_pc = None
    pc_candidates = ["rip", "pc", "eip", "ip", "PC"]
    for pc_reg in pc_candidates:
        if pc_reg in current_regs:
            current_pc = current_regs[pc_reg]
            break

    if current_pc is None:
        print("Cannot determine current PC, stopping execution")
        return None, None, None, None, None

    # 9. 获取当前指令信息
    current_op = {}
    try:
        disasm_json = rz_instance.cmd(f"pdj 1 @ {current_pc}")
        if disasm_json.strip():
            current_op = json.loads(disasm_json)[0]
        else:
            current_op = {}
    except (json.JSONDecodeError, IndexError):
        current_op = {}

    # 10. 获取RzIL表示（如果可用）
    rzil_repr = ""
    try:
        rzil_repr = rz_instance.cmd(f"aoip 1 @ {current_pc}")
    except:
        rzil_repr = "N/A"

    # 11. 记录当前状态
    step_info = {
        "step": step,
        "pc": hex(current_pc) if isinstance(current_pc, int) else str(current_pc),
        "op": current_op.get("disasm", ""),
        "opcode": current_op.get("opcode", ""),
        "type": current_op.get("type", ""),
        "rzil": rzil_repr.strip(),
        "regs": current_regs,
        "timestamp": time.time() - start_time
    }
    return step_info, current_pc, current_op, current_regs, rzil_repr

def _check_emulation_termination(step_info, step_output, timeout_seconds, start_time, trace):
    """
    检查模拟是否应该终止（超时、返回指令、执行错误、无限循环）。
    返回 True 表示应该终止，False 表示继续。
    """
    # 超时检查
    if time.time() - start_time > timeout_seconds:
        print(f"Execution timed out after {timeout_seconds} seconds")
        return True

    # 检查是否到达函数结尾
    op_type = step_info.get("type", "")
    if op_type in ["ret", "retn", "retf", "return"]:
        print(f"Reached return instruction at step {step_info['step']}")
        return True

    # 检查是否有执行错误
    if step_output and any(keyword in str(step_output).lower() for keyword in ["error", "invalid", "failed"]):
        print(f"Execution error at step {step_info['step']}: {step_output}")
        return True

    # 简单的无限循环检测
    if step_info['step'] > 0 and len(trace) >= 2:
        prev_pc = trace[-2]["pc"]
        if prev_pc == step_info["pc"] and op_type not in ["nop", "call"]:
            print(f"Possible infinite loop detected at step {step_info['step']}")
            return True
    return False

def _emulate_function_target_rzil(rz_instance, function_name, max_steps, result_queue, timeout_seconds=30):
    """
    修正后的 RzIL 模拟函数，移除了不存在的命令并优化了内存处理。

    NOTE: This is the legacy function - use emulate_function() for the improved version.

    Args:
        rz_instance: 活跃的 rzpipe 实例。
        function_name: 要模拟的函数名称。
        max_steps: 最大执行步数。
        result_queue: 用于放置模拟结果的队列。
        timeout_seconds: 超时时间（秒）。
    """
    start_time = time.time()
    original_offset = None
    trace = []
    vm_changes = []

    try:
        # 1. 保存当前偏移量并跳转到函数
        original_offset = rz_instance.cmd("s").strip()
        rz_instance.cmd(f"s {function_name}")

        # 2. 获取二进制信息
        binary_info = rz_instance.cmdj("ij")
        if not binary_info:
            result_queue.put({
                "error": "Failed to get binary information",
                "success": False
            })
            return

        # 3. 初始化 RzIL VM
        if not _initialize_rzil_vm(rz_instance, result_queue):
            return

        # 4. 设置基本的寄存器初始值
        arch, bits, stack_pointer, base_pointer, aligned_sp = _get_arch_specific_registers(binary_info)
        _set_initial_registers(rz_instance, stack_pointer, base_pointer, aligned_sp)

        # 6. 开始执行循环
        for step in range(max_steps):
            step_info, current_pc, current_op, current_regs, rzil_repr = _get_current_emulation_state(rz_instance, start_time, step)

            if current_pc is None:
                # Cannot determine current PC, stopping execution (handled in _get_current_emulation_state)
                break

            trace.append(step_info)

            # 12. 执行一步并记录状态变化
            try:
                step_output = rz_instance.cmd("aezsej 1")
                if step_output.strip():
                    try:
                        step_output_parsed = json.loads(step_output)
                    except json.JSONDecodeError:
                        step_output_parsed = step_output
                else:
                    step_output_parsed = None
            except Exception as e:
                print(f"执行错误: {e}")
                break

            # 记录VM状态变化
            if step_output_parsed:
                vm_changes.append({
                    "step": step,
                    "changes": step_output_parsed,
                    "timestamp": time.time() - start_time
                })

            # 检查是否应该终止模拟
            if _check_emulation_termination(step_info, step_output, timeout_seconds, start_time, trace):
                break

        # 16. 获取最终状态
        final_regs = {}
        try:
            final_regs_json = rz_instance.cmd("aezvj")
            if not final_regs_json.strip():
                final_regs_json = rz_instance.cmd("arj")
            final_regs = json.loads(final_regs_json) if final_regs_json.strip() else {}
        except json.JSONDecodeError:
            final_regs = {}

        result_queue.put({
            "success": True,
            "final_regs": final_regs,
            "trace": trace,
            "vm_changes": vm_changes,
            "steps_executed": len(trace),
            "execution_time": time.time() - start_time,
            "emulation_type": "RzIL_Legacy",
            "memory_setup": {
                "architecture": arch,
                "bits": bits,
                "stack_pointer": stack_pointer,
                "initial_sp": hex(aligned_sp)
            }
        })

    except Exception as e:
        result_queue.put({
            "error": str(e),
            "success": False,
            "execution_time": time.time() - start_time,
            "partial_trace": trace if 'trace' in locals() else []
        })
    finally:
        # 清理：恢复到原始偏移量
        if original_offset:
            try:
                rz_instance.cmd(f"s {original_offset}")
            except:
                pass

def setup_realistic_memory_layout(rz_instance):
    """
    设置更真实的内存布局，包括代码段、数据段和栈段

    NOTE: This function uses non-existent commands and is kept for legacy compatibility only.
    Use _setup_memory_with_malloc() instead.
    """
    print("WARNING: setup_realistic_memory_layout() uses non-existent 'aezm' command")
    print("Please use the updated emulate_function() which uses malloc:// protocol")
    return False

def emulate_function_with_timeout(rz_instance, function_name, max_steps=1000, timeout=30):
    """
    带超时的函数模拟包装器

    NOTE: This is a legacy function. Use emulate_function() for the improved version.

    Args:
        rz_instance: rzpipe实例
        function_name: 函数名
        max_steps: 最大步数
        timeout: 超时时间（秒）

    Returns:
        dict: 模拟结果
    """
    result_queue = queue.Queue()

    # 启动模拟线程
    emulation_thread = threading.Thread(
        target=_emulate_function_target_rzil,
        args=(rz_instance, function_name, max_steps, result_queue, timeout)
    )

    emulation_thread.daemon = True
    emulation_thread.start()

    try:
        # 等待结果或超时
        result = result_queue.get(timeout=timeout + 5)  # 给一些缓冲时间
        return result
    except queue.Empty:
        return {
            "error": f"Emulation timed out after {timeout} seconds",
            "success": False
        }
    finally:
        if emulation_thread.is_alive():
            # 线程仍在运行，但我们已经超时了
            pass


if __name__ == "__main__":
    binary_path = "/Users/yingdong/VSCode/angr/angr_ctf/00_angr_find/00_angr_find_arm"  # Example binary path
    function_name = "entry0"  # Example function name

    print("=" * 60)
    print("Rizin Binary Analysis with Improved RzIL Emulation")
    print("=" * 60)

    # Test the improved emulation function
    print(f"\n🚀 Testing improved RzIL emulation:")
    result = emulate_function(binary_path, function_name, max_steps=3, timeout=30)

    print("\n" + "=" * 40)
    print("🔍 Emulation Results Analysis")
    print("=" * 40)

    if result.get("success"):
        print("✅ Emulation completed successfully!")

        # Display execution summary
        summary = result.get("execution_summary", {})
        print(f"📊 Steps executed: {summary.get('steps_executed', 0)}")
        print(f"⏱️  Execution time: {summary.get('execution_time', 0):.3f}s")
        print(f"🏗️  Memory setup: {'✅' if summary.get('memory_setup_success') else '❌'}")
        print(f"🔧 Architecture: {summary.get('architecture', 'unknown')}")

        # Display execution trace
        trace = result.get("execution_trace", [])
        if trace:
            print(f"\n📋 Execution trace:")
            for step_info in trace:
                step_num = step_info.get("step", "?")
                pc = step_info.get("pc", "?")
                instruction = step_info.get("instruction", "?")
                duration = step_info.get("step_duration", 0)

                status = "✅"
                if step_info.get("memory_warning"):
                    status = "⚠️"
                elif step_info.get("execution_error"):
                    status = "❌"

                print(f"  {status} Step {step_num}: {pc} - {instruction} ({duration:.3f}s)")

                if step_info.get("memory_warning"):
                    print(f"    ⚠️  Memory warning: {step_info['memory_warning']}")

        # Display VM state changes
        vm_changes = result.get("vm_state_changes", [])
        if vm_changes:
            print(f"\n🔄 VM state changes: {len(vm_changes)} changes recorded")

    else:
        print("❌ Emulation failed")
        print(f"Error: {result.get('error', 'Unknown error')}")

        if result.get("setup_log"):
            print("\n📋 Setup log:")
            for log_entry in result["setup_log"]:
                print(f"  • {log_entry}")

    # Display detailed JSON result (commented out to reduce output)
    # print(f"\n📄 Detailed result (JSON):")
    # print(json.dumps(result, indent=2, ensure_ascii=False))
