from typing import Dict, Any, List
import json

def _simulate_external_call_effects(rz_instance, instruction_disasm: str, current_op: Dict[str, Any], arch: str, bits: int) -> str:
    """
    增强版外部函数调用效果模拟器

    支持更多架构，生成正确的执行输出，并正确调整PC寄存器到下一条指令位置

    Args:
        rz_instance: rzpipe 实例
        instruction_disasm: 指令反汇编文本
        current_op: 当前指令的信息字典（包含offset等信息）
        arch: 架构名称 (如 "x86", "arm", "ppc", 等)
        bits: 位数 (32 或 64)

    Returns:
        str: 模拟外部调用的JSON格式执行输出
    """
    disasm_lower = instruction_disasm.lower()
    changes = []

    # 确定架构特定的寄存器名称
    arch_info = _get_architecture_register_info(arch, bits)

    # 获取当前指令的下一条指令地址（用于PC调整）
    current_offset = current_op.get("offset", 0)
    instruction_size = current_op.get("size", 4)  # 默认4字节指令长度
    next_pc = hex(current_offset + instruction_size)

    print(f"🎭 Simulating external call: {instruction_disasm}")
    print(f"🏗️ Architecture: {arch} {bits}-bit")
    print(f"📍 Current PC: {hex(current_offset)} -> Next PC: {next_pc}")

    try:
        # 1. 首先调整PC到下一条指令
        old_pc = _get_current_pc_value(rz_instance, arch_info["pc_register"])
        rz_instance.cmd(f"aezv {arch_info['pc_register']} {next_pc}")

        changes.append({
            "type": "pc_write",
            "old": old_pc,
            "new": next_pc
        })

        # 2. 模拟特定外部函数的效果
        function_effects = _simulate_specific_function_effects(
            rz_instance, disasm_lower, arch_info, instruction_disasm
        )
        changes.extend(function_effects)

        # 3. 通用调用约定处理（如果没有特定函数处理）
        if not function_effects:
            generic_effects = _simulate_generic_call_effects(
                rz_instance, arch_info, instruction_disasm
            )
            changes.extend(generic_effects)

    except Exception as e:
        print(f"❌ Error simulating external call: {e}")
        changes.append({
            "type": "simulation_error",
            "error": str(e),
            "instruction": instruction_disasm
        })

    return json.dumps(changes) if changes else ""

def _get_architecture_register_info(arch: str, bits: int) -> Dict[str, str]:
    """
    获取架构特定的寄存器信息

    Returns:
        Dict 包含 pc_register, return_register, stack_pointer 等信息
    """
    arch = arch.lower()

    if arch == "x86":
        if bits == 64:
            return {
                "pc_register": "rip",
                "return_register": "rax",  # 返回值寄存器
                "stack_pointer": "rsp",
                "base_pointer": "rbp",
                "arg_registers": ["rdi", "rsi", "rdx", "rcx", "r8", "r9"],  # System V ABI
                "calling_convention": "sysv"
            }
        elif bits == 32:
            return {
                "pc_register": "eip",
                "return_register": "eax",
                "stack_pointer": "esp",
                "base_pointer": "ebp",
                "arg_registers": [],  # x86-32 主要使用栈传参
                "calling_convention": "cdecl"
            }
        else:  # 16-bit
            return {
                "pc_register": "ip",
                "return_register": "ax",
                "stack_pointer": "sp",
                "base_pointer": "bp",
                "arg_registers": [],
                "calling_convention": "cdecl"
            }

    elif arch == "arm":
        if bits == 64:  # AArch64
            return {
                "pc_register": "PC",
                "return_register": "x0",  # ARM64 ABI
                "stack_pointer": "sp",
                "base_pointer": "x29",    # Frame pointer
                "arg_registers": ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"],
                "calling_convention": "aapcs64"
            }
        else:  # AArch32
            return {
                "pc_register": "pc",
                "return_register": "r0",   # ARM AAPCS
                "stack_pointer": "sp",
                "base_pointer": "fp",      # r11 or r7
                "arg_registers": ["r0", "r1", "r2", "r3"],
                "calling_convention": "aapcs"
            }

    elif arch in ["ppc", "powerpc"]:
        if bits == 64:
            return {
                "pc_register": "PC",
                "return_register": "r3",   # PowerPC ABI
                "stack_pointer": "r1",
                "base_pointer": "r1",      # PowerPC 使用 r1 作为栈指针
                "arg_registers": ["r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10"],
                "calling_convention": "powerpc"
            }
        else:  # 32-bit PowerPC
            return {
                "pc_register": "pc",
                "return_register": "r3",
                "stack_pointer": "r1",
                "base_pointer": "r1",
                "arg_registers": ["r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10"],
                "calling_convention": "powerpc"
            }

    elif arch == "mips":
        return {
            "pc_register": "PC",
            "return_register": "v0" if bits == 32 else "v0",  # MIPS O32/N64 ABI
            "stack_pointer": "sp",
            "base_pointer": "fp",
            "arg_registers": ["a0", "a1", "a2", "a3"] if bits == 32 else ["a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"],
            "calling_convention": "o32" if bits == 32 else "n64"
        }

    elif arch == "riscv":
        return {
            "pc_register": "PC",
            "return_register": "x10",   # a0 in RISC-V ABI
            "stack_pointer": "x2",      # sp
            "base_pointer": "x8",       # fp/s0
            "arg_registers": ["x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17"],  # a0-a7
            "calling_convention": "riscv"
        }

    elif arch in ["sparc", "sparc64"]:
        return {
            "pc_register": "PC",
            "return_register": "o0",    # SPARC V9 ABI
            "stack_pointer": "sp",
            "base_pointer": "fp",
            "arg_registers": ["o0", "o1", "o2", "o3", "o4", "o5"],
            "calling_convention": "sparc"
        }

    else:
        # 通用/未知架构的默认值
        print(f"⚠️ Unknown architecture {arch}, using generic register names")
        return {
            "pc_register": "PC",
            "return_register": "r0",
            "stack_pointer": "sp",
            "base_pointer": "fp",
            "arg_registers": ["r0", "r1", "r2", "r3"],
            "calling_convention": "generic"
        }

def _get_current_pc_value(rz_instance, pc_register: str) -> str:
    """
    获取当前PC寄存器的值
    """
    try:
        current_pc_output = rz_instance.cmd(f"aezv {pc_register}")
        # 解析输出，格式通常是 "pc: 0x1234abcd"
        if ":" in current_pc_output:
            return hex(int(current_pc_output.split(":")[1].strip(), 16))
        return hex(int(current_pc_output.strip(), 16))
    except Exception:
        return "0x0"

def _simulate_specific_function_effects(rz_instance, disasm_lower: str, arch_info: Dict[str, str], instruction_disasm: str) -> List[Dict[str, Any]]:
    """
    模拟特定已知函数的效果
    """
    changes = []
    return_reg = arch_info["return_register"]

    try:
        # printf 系列函数
        if any(func in disasm_lower for func in ["printf", "sprintf", "fprintf", "snprintf", "vprintf"]):
            print("🖨️ Simulating printf-family function effects...")
            # printf 通常返回打印的字符数
            old_ret_value = _get_current_pc_value(rz_instance, return_reg)
            rz_instance.cmd(f"aezv {return_reg} 0x10")  # 假设打印了16个字符

            changes.append({
                "type": "var_write",
                "name": return_reg,
                "old": old_ret_value,
                "new": "0x10"
            })

        # scanf 系列函数
        elif any(func in disasm_lower for func in ["scanf", "sscanf", "fscanf", "vscanf"]):
            print("⌨️ Simulating scanf-family function effects...")
            old_ret_value = _get_current_pc_value(rz_instance, return_reg)
            rz_instance.cmd(f"aezv {return_reg} 0x1")   # 假设成功读取了1个项目

            changes.append({
                "type": "var_write",
                "name": return_reg,
                "old": old_ret_value,
                "new": "0x1"
            })

        # 内存分配函数
        elif any(func in disasm_lower for func in ["malloc", "calloc", "realloc"]):
            print("🧠 Simulating memory allocation function effects...")
            old_ret_value = _get_current_pc_value(rz_instance, return_reg)
            # 返回一个模拟的堆地址
            fake_heap_addr = "0x10000000"
            rz_instance.cmd(f"aezv {return_reg} {fake_heap_addr}")

            changes.append({
                "type": "var_write",
                "name": return_reg,
                "old": old_ret_value,
                "new": fake_heap_addr
            })

        # 内存释放函数
        elif "free" in disasm_lower:
            print("🗑️ Simulating free function effects...")
            # free 通常不返回值，但可能修改堆管理器状态
            # 这里我们只是标记一下
            changes.append({
                "type": "heap_operation",
                "operation": "free",
                "function": "free"
            })

        # 字符串函数
        elif any(func in disasm_lower for func in ["strlen", "strcmp", "strcpy", "strcat", "strchr", "strstr"]):
            print("📝 Simulating string function effects...")
            old_ret_value = _get_current_pc_value(rz_instance, return_reg)

            if "strlen" in disasm_lower:
                # strlen 返回字符串长度
                rz_instance.cmd(f"aezv {return_reg} 0x8")  # 假设字符串长度为8
                new_value = "0x8"
            elif "strcmp" in disasm_lower:
                # strcmp 返回比较结果
                rz_instance.cmd(f"aezv {return_reg} 0x0")  # 假设字符串相等
                new_value = "0x0"
            else:
                # strcpy, strcat 等返回目标字符串指针
                # 通常是第一个参数，这里简化为一个地址
                rz_instance.cmd(f"aezv {return_reg} 0x20000000")
                new_value = "0x20000000"

            changes.append({
                "type": "var_write",
                "name": return_reg,
                "old": old_ret_value,
                "new": new_value
            })

        # 数学函数
        elif any(func in disasm_lower for func in ["sin", "cos", "tan", "sqrt", "pow", "log", "exp"]):
            print("🔢 Simulating math function effects...")
            old_ret_value = _get_current_pc_value(rz_instance, return_reg)
            # 数学函数通常返回浮点数，这里简化处理
            rz_instance.cmd(f"aezv {return_reg} 0x3ff00000")  # 模拟浮点数1.0

            changes.append({
                "type": "var_write",
                "name": return_reg,
                "old": old_ret_value,
                "new": "0x3ff00000"
            })

        # 文件操作函数
        elif any(func in disasm_lower for func in ["fopen", "fclose", "fread", "fwrite", "fseek", "ftell"]):
            print("📁 Simulating file operation function effects...")
            old_ret_value = _get_current_pc_value(rz_instance, return_reg)

            if "fopen" in disasm_lower:
                # fopen 返回文件指针
                rz_instance.cmd(f"aezv {return_reg} 0x30000000")
                new_value = "0x30000000"
            elif "fclose" in disasm_lower:
                # fclose 返回0表示成功
                rz_instance.cmd(f"aezv {return_reg} 0x0")
                new_value = "0x0"
            elif any(func in disasm_lower for func in ["fread", "fwrite"]):
                # 返回读写的字节数
                rz_instance.cmd(f"aezv {return_reg} 0x100")
                new_value = "0x100"
            else:
                # 其他文件函数
                rz_instance.cmd(f"aezv {return_reg} 0x0")
                new_value = "0x0"

            changes.append({
                "type": "var_write",
                "name": return_reg,
                "old": old_ret_value,
                "new": new_value
            })

        # 系统调用
        elif any(func in disasm_lower for func in ["exit", "_exit", "abort"]):
            print("🚪 Simulating exit function effects...")
            # exit 函数通常不返回，但在模拟中我们只是记录
            changes.append({
                "type": "system_exit",
                "function": "exit",
                "note": "Program termination simulated"
            })

        # sleep/延迟函数
        elif any(func in disasm_lower for func in ["sleep", "usleep", "nanosleep", "delay"]):
            print("💤 Simulating sleep function effects...")
            old_ret_value = _get_current_pc_value(rz_instance, return_reg)
            rz_instance.cmd(f"aezv {return_reg} 0x0")  # sleep通常返回0

            changes.append({
                "type": "var_write",
                "name": return_reg,
                "old": old_ret_value,
                "new": "0x0"
            })

    except Exception as e:
        print(f"❌ Error in specific function simulation: {e}")
        changes.append({
            "type": "simulation_error",
            "error": str(e),
            "function": "specific_function_simulation"
        })

    return changes

def _simulate_generic_call_effects(rz_instance, arch_info: Dict[str, str], instruction_disasm: str) -> List[Dict[str, Any]]:
    """
    模拟通用函数调用的效果（当没有特定函数处理时）
    """
    changes = []
    return_reg = arch_info["return_register"]

    try:
        print("🔄 Simulating generic external call effects...")

        # 1. 设置一个通用的返回值（通常外部函数会修改返回寄存器）
        old_ret_value = _get_current_pc_value(rz_instance, return_reg)
        generic_return_value = "0x1"  # 假设函数执行成功
        rz_instance.cmd(f"aezv {return_reg} {generic_return_value}")

        changes.append({
            "type": "var_write",
            "name": return_reg,
            "old": old_ret_value,
            "new": generic_return_value
        })

        # 2. 根据调用约定，可能需要恢复一些被调用者保存的寄存器
        # 这里简化处理，只是标记发生了外部调用
        changes.append({
            "type": "external_call",
            "instruction": instruction_disasm,
            "calling_convention": arch_info["calling_convention"],
            "note": "Generic external function call simulated"
        })

    except Exception as e:
        print(f"❌ Error in generic call simulation: {e}")
        changes.append({
            "type": "simulation_error",
            "error": str(e),
            "function": "generic_call_simulation"
        })

    return changes
