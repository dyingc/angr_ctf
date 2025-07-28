#!/usr/bin/env python3
"""
Enhanced ESIL Emulator for radare2 - Optimized for LLM Analysis

专为 LLM 分析优化的模拟器，消除冗余的追踪数据。
只记录实际发生变化的寄存器和内存，大幅减少输出大小。
"""

import json
import logging
from typing import Dict, List, Optional, Union, Any, Tuple, Set, Literal
from dataclasses import dataclass
from enum import Enum


class StopConditionType(Enum):
    """模拟终止条件类型（全中文注释）"""
    ADDRESS = "address"        # 到达指定地址后停止
    FUNCTION_END = "function_end"  # 到达函数结束处停止
    BASIC_BLOCK_END = "basic_block_end"  # 到达基本块结束处停止
    INSTRUCTION_COUNT = "instruction_count"  # 执行指定条数后停止
    EXPRESSION = "expression"  # ESIL 条件表达式为真则停止
    MANUAL = "manual"         # 需手动控制停止


@dataclass
class OptimizedExecutionSnapshot:
    """优化的执行快照，仅包含发生变化的数据（中文注释）"""
    pc: int                                    # 程序计数器
    instruction: str                           # 汇编指令文本
    instruction_type: str                      # 指令类型
    opcode: str                                # 原始操作码字节
    esil_expression: str                       # ESIL 表达式
    step_number: int                           # 步骤编号

    # 只记录有变化的数据（寄存器/内存）
    register_changes: Dict[str, int]           # 本步变化的寄存器
    memory_changes: Dict[int, bytes]           # 本步变化的内存

    # 可选上下文，仅特殊情况下出现
    new_registers: Optional[Set[str]] = None   # 首次出现的寄存器
    accessed_memory: Optional[Set[int]] = None # 被访问但未被修改的内存地址


class ESILEmulator:
    """
    优化的 ESIL 模拟器 - 专为 LLM 分析设计
    消除冗余数据，专注于变化追踪
    """

    def __init__(self, r2_instance):
        """
        初始化 ESIL 模拟器

        Args:
            r2_instance: radare2 instance (r2pipe or similar)
        """
        self.r2 = r2_instance
        self.logger = logging.getLogger(__name__)
        self.external_handlers = {}

        # 追踪模拟状态，仅用于检测寄存器/内存数据的变化
        self.previous_registers = {}        # 上一次快照中的寄存器状态
        self.previous_memory = {}           # 上一次快照中的内存状态
        self.all_seen_registers = set()     # 所有出现过的寄存器名
        self.all_seen_memory = set()        # 所有出现过的内存地址

        # 初始化一些环境、架构相关设置
        self.arch_info = self._get_arch_info()

        # 优化选项开关
        self.track_memory_access = False    # 是否追踪内存被访问但未修改的情况
        self.minimal_mode = True            # 最小变化模式，仅记录关键性变化

        self.setup_environment()            # 初始化 ESIL 环境配置

    def _get_arch_info(self) -> Dict[str, str]:
        """
        使用Radare2的iIj命令获取当前架构的寄存器映射
        返回: 寄存器映射字典
        """
        # 获取二进制文件信息
        info = self.r2.cmdj("iIj")
        arch = info.get('arch', 'unknown').lower()  # 获取架构名
        bits = info.get('bits', 64)                 # 获取位数，默认为64位
        arch_info = {k: v.lower() if isinstance(v, str) else v for k, v in info.items()}

        # 根据架构和位数返回寄存器映射
        if arch == "x86":
            if bits == 64:
                arch_info["registers"] = {
                    "base_reg_name": "rbp",
                    "stack_reg_name": "rsp",
                    "link_reg_name": None,
                    "instruction_reg_name": "rip",
                    "accumulator_reg_name": "rax",
                    "counter_reg_name": "rcx",
                    "data_reg_name": "rdx",
                    "base_index_reg_name": "rbx",
                    "source_index_reg_name": "rsi",
                    "dest_index_reg_name": "rdi",
                    "arg_regs": ["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
                    "caller_saved": ["rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"],
                    "callee_saved": ["rbx", "rbp", "r12", "r13", "r14", "r15"]
                }
            else:  # 32-bit
                arch_info["registers"] = {
                    "base_reg_name": "ebp",
                    "stack_reg_name": "esp",
                    "link_reg_name": None,
                    "instruction_reg_name": "eip",
                    "accumulator_reg_name": "eax",
                    "counter_reg_name": "ecx",
                    "data_reg_name": "edx",
                    "base_index_reg_name": "ebx",
                    "source_index_reg_name": "esi",
                    "dest_index_reg_name": "edi",
                    "arg_regs": [],
                    "caller_saved": ["eax", "ecx", "edx"],
                    "callee_saved": ["ebx", "esi", "edi", "ebp"]
                }

        elif arch == "arm" and bits == 64:
            arch_info["registers"] = {
                "base_reg_name": "x29",      # 帧指针 (FP)
                "stack_reg_name": "sp",      # 栈指针
                "link_reg_name": "x30",      # 链接寄存器 (LR)
                "instruction_reg_name": "pc", # 程序计数器
                "zero_reg_name": "xzr",      # 零寄存器
                "arg_regs": ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"],
                "return_reg_name": "x0",
                "caller_saved": [f"x{i}" for i in range(0, 18)],
                "callee_saved": [f"x{i}" for i in range(19, 29)],
                "temp_regs": [f"x{i}" for i in range(9, 16)]
            }

        elif arch == "arm" and bits == 32:
            arch_info["registers"] = {
                "base_reg_name": "r11",      # 帧指针
                "stack_reg_name": "sp",      # 栈指针 (r13)
                "link_reg_name": "lr",       # 链接寄存器 (r14)
                "instruction_reg_name": "pc", # 程序计数器 (r15)
                "arg_regs": ["r0", "r1", "r2", "r3"],
                "return_reg_name": "r0",
                "caller_saved": ["r0", "r1", "r2", "r3", "r12"],
                "callee_saved": ["r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11"]
            }
        else:
            raise ValueError(f"不支持的架构: {arch} {bits}位")
        return arch_info

    def setup_environment(self):
        """设置 ESIL 优化模拟环境（全中文注释）"""
        self.r2.cmd("e io.cache=true")         # 启用内存缓存，提升读写效率
        self.r2.cmd("e asm.esil=false")        # 默认不显示 ESIL 表达式，避免控制台噪声
        self.r2.cmd("e asm.bytes=true")        # 显示汇编指令字节
        self.r2.cmd("e asm.comments=true")    # 启用自动注释
        self.r2.cmd("e asm.lines=false")     # 禁用控制流图（CFG）的可视化表示，避免干扰LLM分析（只对人工调试有用）
        # 启用更详细的 ESIL 跟踪统计
        self.r2.cmd("e esil.stats=true")

    def set_optimization_level(self, level: Literal["minimal", "normal", "detailed"]) -> None:
        """
        设置优化级别

        Args:
            level: "minimal" - 只记录关键变化
                   "normal" - 记录所有变化但去除冗余
                   "detailed" - 包含访问追踪（适用于详细分析）
        """
        if level == "minimal":
            self.minimal_mode = True
            self.track_memory_access = False
        elif level == "normal":
            self.minimal_mode = False
            self.track_memory_access = False
        elif level == "detailed":
            self.minimal_mode = False
            self.track_memory_access = True

    def emulate_region(self,
                      start_addr: Union[str, int],
                      end_addr: Optional[Union[str, int]] = None,
                      register_inputs: Optional[Dict[str, Union[int, bytes]]] = None,
                      stack_inputs: Optional[Dict[int, Union[bytes, int]]] = None,
                      memory_inputs: Optional[Dict[int, Union[bytes, int]]] = None,
                      skip_external: bool = True,
                      max_steps: int = 10000) -> Dict[str, Any]:
        """
        区域模拟器 - 只返回变化数据
        Args:
            start_addr: 起始地址（可以是函数名如 "sym.encrypt" 或十六进制地址）
            end_addr: 结束地址（None 表示自动检测函数/块边界）
            register_inputs: 寄存器初始值 {"rdi": 0x1234, "rsi": b"data"}
            stack_inputs: 栈数据 {-0x10: b"input", -0x20: 0x1234}（负数表示 ESP 以下）
            memory_inputs: 内存数据 {0x10000: b"test_data", 0x20000: 0x12345678}
            skip_external: 是否自动跳过外部库函数
            max_steps: 最大步数以防止无限循环

        Returns:
            Dict containing:
            - final_registers: Final register state
            - final_memory: Memory snapshot at end
            - execution_trace: List of ExecutionSnapshot for each step
            - steps_executed: Total steps taken
            - stop_reason: Why emulation stopped
        """
        # 1. 初始化 VM 和设置
        self._initialize_vm()
        self._setup_inputs(register_inputs, stack_inputs, memory_inputs)

        # 2. 建立初始状态基线
        self._establish_baseline()

        # 3. 确定停止条件
        stop_condition = self._determine_stop_condition(start_addr, end_addr)

        # 4. 执行优化的监控
        result = self._execute_with_optimized_monitoring(
            start_addr, stop_condition, skip_external, max_steps)

        return result

    def _initialize_vm(self):
        """初始化 ESIL 虚拟机，保证寄存器/栈状态清零，支持跨平台架构"""

        # 清理现有状态
        self.r2.cmd("aei-")
        self.r2.cmd("aei")
        self.r2.cmd("aeim-")

        # 获取架构信息
        arch_info = self.r2.cmdj("ij")
        if not arch_info or "bin" not in arch_info:
            self._initialize_default_stack()
            self.r2.cmd("ar0")
            return

        # 根据架构初始化栈 - aeim会自动设置所有相关寄存器
        stack_config = self._get_stack_config()
        self._initialize_stack(stack_config)

    def _get_stack_config(self) -> Dict[str, str]:
        """根据架构和位数获取栈配置"""

        # 获取架构信息
        arch_info = self.r2.cmdj("ij")

        bin_info = arch_info["bin"]
        arch = bin_info.get("arch", "Unknown").lower()
        bits = bin_info.get("bits", 64)

        stack_configs = {
            # x86架构配置
            ("x86", 32): {
                "base_addr": "0x80000000",  # x86_32内核空间边界下方
                "size": "0x10000",          # 64KB栈
                "sp_reg": "esp",
                "bp_reg": "ebp"
            },
            ("x86", 64): {
                "base_addr": "0x700000000000",  # x86_64用户空间高地址
                "size": "0x20000",              # 128KB栈
                "sp_reg": "rsp",
                "bp_reg": "rbp"
            },

            # ARM64架构配置
            ("arm", 64): {
                "base_addr": "0x400000000000",  # ARM64用户空间
                "size": "0x20000",              # 128KB栈
                "sp_reg": "sp",
                "bp_reg": "x29"                 # ARM64使用x29作为frame pointer
            }
        }

        # 获取架构特定配置，如果不存在则使用默认配置
        return stack_configs.get((arch, bits), {
            "base_addr": "0x80000000",
            "size": "0x10000",
            "sp_reg": "rsp",
            "bp_reg": "rbp"
        })

    def _initialize_stack(self, config):
        """使用给定配置初始化栈"""
        base_addr = config["base_addr"]
        size = config["size"]

        # aeim会自动设置sp、fp等栈相关寄存器为栈中点
        self.r2.cmd(f"aeim {base_addr} {size}")

    def _initialize_default_stack(self):
        """当无法获取架构信息时使用的默认栈初始化"""
        self.r2.cmd("aeim 0x2000 0xffff")

    def _establish_baseline(self):
        """建立当前模拟快照的变化基准（中文注释）"""
        self.previous_registers = self._get_current_registers()     # 记录当前寄存器基线
        self.previous_memory = self._get_relevant_memory()          # 记录当前内存基线

        # 记录所有初始出现的寄存器/内存，便于后续去重统计
        self.all_seen_registers = set(self.previous_registers.keys())
        self.all_seen_memory = set(self.previous_memory.keys())

        self.logger.debug(f"基线建立完成: 有 {len(self.previous_registers)} 个寄存器, "
                         f"{len(self.previous_memory)} 处内存区域")

    def _execute_with_optimized_monitoring(self, start_addr: Union[str, int],
                                         stop_condition: Tuple[StopConditionType, Any],
                                         skip_external: bool,
                                         max_steps: int) -> Dict[str, Any]:
        """
        执行优化的监控 - 只追踪变化
        """
        # 初始化执行
        self.r2.cmd(f"s {start_addr}")
        self.r2.cmd("aeip")

        execution_trace = []
        step_count = 0
        stop_reason = "completed"

        # 用于追踪整体变化统计
        total_register_changes = 0
        total_memory_changes = 0
        unique_registers_modified = set()
        unique_memory_modified = set()

        self.logger.info(f"开始优化模拟 @ {start_addr}, 停止条件: {stop_condition}")

        while step_count < max_steps:
            current_pc = self._get_current_pc()

            # 检查停止条件
            if self._should_stop(current_pc, stop_condition):
                stop_reason = f"reached_{stop_condition[0].value}"
                break

            # 获取指令信息
            try:
                instr_info = self.r2.cmdj(f"pdj 1 @ 0x{current_pc:x}")
                if not instr_info or len(instr_info) == 0:
                    stop_reason = "invalid_instruction"
                    break

                instr = instr_info[0]
                instruction_text = instr.get("opcode", "unknown")
                instruction_type = instr.get("type", "unknown")
                opcode_bytes = instr.get("bytes", "")
                esil_expr = instr.get("esil", "")

            except (json.JSONDecodeError, KeyError, IndexError) as e:
                self.logger.warning(f"解析指令失败 @ 0x{current_pc:x}: {e}")
                instruction_text = self.r2.cmd(f"pi 1 @ 0x{current_pc:x}").strip()
                instruction_type = "unknown"
                opcode_bytes = ""
                esil_expr = ""

            # 执行指令
            step_successful = self._handle_instruction(
                current_pc, instruction_text, instruction_type, skip_external)

            if not step_successful:
                stop_reason = "execution_failed"
                break

            # 捕获优化的执行快照
            snapshot = self._create_optimized_snapshot(
                pc=current_pc,
                instruction=instruction_text,
                instruction_type=instruction_type,
                opcode=opcode_bytes,
                esil_expression=esil_expr,
                step_number=step_count
            )

            # 只在有变化时添加快照
            if self._is_significant_step(snapshot):
                execution_trace.append(snapshot)

                # 更新统计
                total_register_changes += len(snapshot.register_changes)
                total_memory_changes += len(snapshot.memory_changes)
                unique_registers_modified.update(snapshot.register_changes.keys())
                unique_memory_modified.update(snapshot.memory_changes.keys())

            step_count += 1

        if step_count >= max_steps:
            stop_reason = "max_steps_reached"

        # 生成优化的结果
        final_registers = self._get_current_registers()
        final_memory = self._get_relevant_memory()

        # 计算最终状态相对于初始状态的变化
        final_register_changes = self._compute_register_diff(
            self.previous_registers, final_registers)
        final_memory_changes = self._compute_memory_diff(
            self.previous_memory, final_memory)

        return {
            'final_state': {
                'register_changes': final_register_changes,
                'memory_changes': final_memory_changes,
                'total_registers': len(final_registers),
                'total_memory_locations': len(final_memory)
            },
            'execution_trace': execution_trace,
            'execution_stats': {
                'steps_executed': step_count,
                'trace_entries': len(execution_trace),
                'compression_ratio': f"{len(execution_trace)}/{step_count}" if step_count > 0 else "0/0",
                'total_register_changes': total_register_changes,
                'total_memory_changes': total_memory_changes,
                'unique_registers_modified': len(unique_registers_modified),
                'unique_memory_modified': len(unique_memory_modified)
            },
            'stop_reason': stop_reason,
            'stop_condition': stop_condition
        }

    def _create_optimized_snapshot(self, pc: int, instruction: str,
                                 instruction_type: str, opcode: str,
                                 esil_expression: str, step_number: int) -> OptimizedExecutionSnapshot:
        """创建优化的执行快照 - 只包含变化"""

        # 获取当前状态
        current_registers = self._get_current_registers()
        current_memory = self._get_relevant_memory()

        # 计算变化
        register_changes = self._compute_register_diff(self.previous_registers, current_registers)
        memory_changes = self._compute_memory_diff(self.previous_memory, current_memory)

        # 检测新出现的寄存器和内存（可选）
        new_registers = None
        accessed_memory = None

        if not self.minimal_mode:
            new_reg_keys = set(current_registers.keys()) - self.all_seen_registers
            new_registers = new_reg_keys if new_reg_keys else None

            if self.track_memory_access:
                # 追踪被访问但未修改的内存
                all_current_memory = set(current_memory.keys())
                modified_memory = set(memory_changes.keys())
                accessed_memory = all_current_memory - modified_memory - self.all_seen_memory
                accessed_memory = accessed_memory if accessed_memory else None

        # 更新已见集合
        self.all_seen_registers.update(current_registers.keys())
        self.all_seen_memory.update(current_memory.keys())

        # 更新前一状态
        self.previous_registers = current_registers
        self.previous_memory = current_memory

        return OptimizedExecutionSnapshot(
            pc=pc,
            instruction=instruction,
            instruction_type=instruction_type,
            opcode=opcode,
            esil_expression=esil_expression,
            step_number=step_number,
            register_changes=register_changes,
            memory_changes=memory_changes,
            new_registers=new_registers,
            accessed_memory=accessed_memory
        )

    def _compute_register_diff(self, prev_regs: Dict[str, int],
                              curr_regs: Dict[str, int]) -> Dict[str, int]:
        """计算寄存器变化 - 只返回实际改变的寄存器"""
        changes = {}

        # 检查修改的寄存器
        for reg, value in curr_regs.items():
            if reg not in prev_regs or prev_regs[reg] != value:
                changes[reg] = value

        # 在非最小模式下，检查消失的寄存器
        if not self.minimal_mode:
            for reg in prev_regs:
                if reg not in curr_regs:
                    changes[reg] = None  # 表示寄存器被清除

        return changes

    def _compute_memory_diff(self, prev_mem: Dict[int, bytes],
                           curr_mem: Dict[int, bytes]) -> Dict[int, bytes]:
        """计算内存变化 - 只返回实际改变的内存"""
        changes = {}

        # 检查修改的内存
        for addr, data in curr_mem.items():
            if addr not in prev_mem or prev_mem[addr] != data:
                changes[addr] = data

        # 在非最小模式下，检查被清除的内存
        if not self.minimal_mode:
            for addr in prev_mem:
                if addr not in curr_mem:
                    changes[addr] = b''  # 表示内存被清除

        return changes

    def _is_significant_step(self, snapshot: OptimizedExecutionSnapshot) -> bool:
        """判断是否为重要步骤 - 决定是否包含在追踪中"""

        # 总是包含有变化的步骤
        if snapshot.register_changes or snapshot.memory_changes:
            return True

        # 在非最小模式下，包含特殊指令类型
        if not self.minimal_mode:
            important_types = ["call", "ret", "jmp", "cjmp", "int", "syscall"]
            if snapshot.instruction_type in important_types:
                return True

        # 在详细模式下，包含新的访问
        if self.track_memory_access:
            if snapshot.new_registers or snapshot.accessed_memory:
                return True

        return False

    def _get_current_registers(self) -> Dict[str, int]:
        """获取当前寄存器状态 - 使用JSON输出优化版本"""
        try:
            # 使用 aerj 获取 JSON 格式寄存器数据，避免字符串解析
            registers = self.r2.cmdj("aerj")

            if not isinstance(registers, dict):
                self.logger.warning("aerj 返回了非字典类型数据")
                return {}

            # 在最小模式下过滤无意义的寄存器
            if self.minimal_mode:
                # 创建过滤后的字典，只保留重要寄存器
                filtered_registers = {
                    name: value for name, value in registers.items()
                    if not self._is_insignificant_register(name)
                }
                return filtered_registers

            return registers
        except Exception as e:
            self.logger.error(f"获取寄存器快照失败: {e}")
            return {}

    def _is_insignificant_register(self, reg_name: str) -> bool:
        """判断是否为无关紧要的寄存器（最小模式下过滤）"""
        # 过滤掉段寄存器、调试寄存器等
        insignificant = {
            'cs', 'ds', 'es', 'fs', 'gs', 'ss',  # 段寄存器
            'dr0', 'dr1', 'dr2', 'dr3', 'dr6', 'dr7',  # 调试寄存器
            'cr0', 'cr2', 'cr3', 'cr4',  # 控制寄存器
            'tr', 'ldtr', 'gdtr', 'idtr'  # 系统寄存器
        }
        return reg_name.lower() in insignificant

    def _get_relevant_memory(self) -> Dict[int, bytes]:
        """获取相关内存区域 - 智能选择重要区域"""
        memory = {}
        try:
            registers = self._get_current_registers()

            # 追踪栈区域（更小的窗口）
            sp_reg = self._get_stack_config()["sp_reg"]
            sp_reg_val = registers.get(sp_reg, 0)
            if sp_reg_val:
                try:
                    # 追踪栈顶附近共 256 字节
                    stack_hex = self.r2.cmd(f"px 256 @ {sp_reg_val-128}")
                    memory.update(self._parse_hex_dump(stack_hex, sp_reg_val-128))
                except:
                    pass

            # 只追踪明显的指针寄存器
            pointer_regs = ['rdi', 'rsi', 'rdx', 'edi', 'esi', 'eax']

            for reg in pointer_regs:
                if reg in registers and self._is_valid_pointer(registers[reg]):
                    try:
                        ptr_addr = registers[reg]
                        # 减少每个指针追踪的内存大小
                        ptr_hex = self.r2.cmd(f"px 32 @ {ptr_addr}")
                        memory.update(self._parse_hex_dump(ptr_hex, ptr_addr))
                    except:
                        pass

        except Exception as e:
            self.logger.debug(f"内存快照错误: {e}")

        return memory

    def _is_valid_pointer(self, addr: int) -> bool:
        """判断是否为有效指针"""
        # 更严格的指针验证
        if addr < 0x1000:  # 空指针区域
            return False
        if addr >= 0xffffffff00000000:  # 内核空间（64位）
            return False
        if addr >= 0x80000000 and addr < 0xc0000000:  # 典型的无效区域
            return False
        return True

    def _parse_hex_dump(self, hex_output: str, base_addr: int) -> Dict[int, bytes]:
        """解析 radare2 十六进制转储输出"""
        memory = {}
        try:
            for line in hex_output.split('\n'):
                if line.startswith('0x') and ' ' in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        addr = int(parts[0], 16)
                        # 提取所有 Hex 数据
                        valid_parts = [p for p in parts if all(c in '0123456789abcdefABCDEF' for c in p)]
                        hex_bytes = ' '.join(valid_parts[1:])  # 跳过地址部分
                        try:
                            data = bytes.fromhex(hex_bytes.replace(' ', ''))
                            if data != b'\x00' * len(data):  # 跳过全零内存
                                memory[addr] = data
                        except ValueError:
                            pass
        except Exception:
            pass
        return memory

    # 保留原有的其他方法但添加优化
    def _get_current_pc(self) -> int:
        """获取当前程序计数器值"""
        pc_reg = self.arch_info["registers"]["instruction_reg_name"]
        pc_output = self.r2.cmdj("aerj")[pc_reg]
        if not pc_output:
            return 0
        return pc_output

    def _should_stop(self, current_pc: int, stop_condition: Tuple[StopConditionType, Any]) -> bool:
        """
        检查是否应该停止模拟

        Args:
            current_pc: 当前程序计数器值
            stop_condition: 停止条件元组 (StopConditionType, condition_value)

        Returns:
            True if emulation should stop
        """
        condition_type, condition_value = stop_condition

        if condition_type == StopConditionType.ADDRESS and condition_value is not None:
            return current_pc >= condition_value
        elif condition_type in [StopConditionType.FUNCTION_END, StopConditionType.BASIC_BLOCK_END] and condition_value is not None:
            return current_pc >= condition_value
        elif condition_type == StopConditionType.MANUAL:
            # For manual mode, continue until explicit stop
            return False

        return False

    def _determine_stop_condition(self, start_addr: Union[str, int],
                                end_addr: Optional[Union[str, int]]) -> Tuple[StopConditionType, Any]:
        """
        智能确定模拟停止条件

        Args:
            start_addr: 起始地址、符号名（如：main）或表达式（如：main+0x15）
            end_addr: 结束地址（符号名、表达式或整数地址）（可选）

        Returns:
            (StopConditionType, 具体条件) 元组

        停止条件确定逻辑（按优先级顺序）：
            1. 若提供 end_addr，直接停止于该地址
            2. 若起始地址位于已识别函数内，使用函数结束地址作为停止条件
            3. 若起始地址不在函数内但存在基本块信息，使用基本块结束地址
            （适用于：未被识别为函数的代码片段、孤立基本块、函数分析失败等情况）
            4. 若以上条件均不满足，降级为手动模式

        Note:
            基本块回退机制处理以下场景：
            - 手动跳转到的代码片段（非函数入口点）
            - 被混淆或反调试技术影响的函数
            - 动态生成代码或内联汇编片段
            - 位于函数间隙的独立代码块
            - 不完整的函数分析结果

        适用于自动检测函数/代码块范围的模拟终止，提升用例复现和调试效率。
        在复杂二进制分析中提供更强的容错性。
        """
        if end_addr is not None:
            return (StopConditionType.ADDRESS, self._resolve_address(end_addr))

        resolved_start = self._resolve_address(start_addr)

        func_info = self.r2.cmdj(f"afij @ {resolved_start}") # 尝试通过地址、符号名或表达式获取函数信息
        if func_info and len(func_info) > 0:
            func_end = func_info[0]["addr"] + func_info[0]["size"]
            return (StopConditionType.FUNCTION_END, func_end)

        bb_info = self.r2.cmdj(f"abj @ {resolved_start}") # 尝试获取基本块信息
        if bb_info and len(bb_info) > 0:
            bb_end = bb_info[0]["addr"] + bb_info[0]["size"]
            return (StopConditionType.BASIC_BLOCK_END, bb_end)

        return (StopConditionType.MANUAL, None)

    def _resolve_address(self, addr: Union[str, int]) -> int:
        """
        从符号名、表达式、十六进制/十进制字符串或整数解析为内存地址

        Args:
            addr: 地址参数——可为整数、0x前缀的字符串或符号名

        Returns:
            解析后的绝对地址（int）

        示例：
            - "0x1234"     → 0x1234
            - "main"       → 通过 radare2 求值获得符号地址
            - "main + 10"  → 通过 radare2 求值获得表达式地址
            - 5678         → 5678
        """
        result = self.r2.cmd(f"?v {addr}").strip()
        return int(result, 16) if result else 0

    def _setup_inputs(self, register_inputs: Optional[Dict],
                     stack_inputs: Optional[Dict],
                     memory_inputs: Optional[Dict]):
        """
        初始化向模拟注入的输入数据（寄存器/栈/内存）

        Args:
            register_inputs: 寄存器初始值（如 {"rdi": 0x1000, "rsi": b"AAAA"}）
                - 对于 bytes 类型，将先放入内存，再让寄存器指向该地址
            stack_inputs: 栈偏移与填充值（偏移相对 esp/rsp；适合函数参数/返回地址模拟）
            memory_inputs: 直接按地址写入原始内存

        注意：
            - bytes 类型一律以 wx 写入
            - int 类型自动补零、对齐，并以十六进制写入
            - 调用前应保证虚拟机初始化与关键寄存器已准备完毕

        该函数保障测试用例、自动化 Fuzzing 时输入的灵活性与可控性。
        """
        if register_inputs:
            for reg, value in register_inputs.items():
                if isinstance(value, bytes):
                    addr = 0x10000 + len(register_inputs) * 0x1000
                    self.r2.cmd(f"wx {value.hex()} @ {addr}")
                    self.r2.cmd(f"aer {reg}={addr}")
                    self.logger.debug(f"设置 {reg} -> 0x{addr:x} (指向 {len(value)} 字节)")
                else:
                    self.r2.cmd(f"aer {reg}={value}")
                    self.logger.debug(f"设置 {reg} = 0x{value:x}")

        if stack_inputs:
            stack_config = self._get_stack_config()
            sp_reg = stack_config["sp_reg"]
            for offset, value in stack_inputs.items():
                sp_reg_val = self.r2.cmdj(f"aerj")[sp_reg]
                target_addr = sp_reg_val + offset

                if isinstance(value, bytes):
                    self.r2.cmd(f"wx {value.hex()} @ 0x{target_addr:x}")
                else:
                    self.r2.cmd(f"wx {value:08x} @ 0x{target_addr:x}")

        if memory_inputs:
            for addr, value in memory_inputs.items():
                if isinstance(value, bytes):
                    self.r2.cmd(f"wx {value.hex()} @ 0x{addr:x}")
                else:
                    self.r2.cmd(f"wx {value:08x} @ 0x{addr:x}")

    def _handle_instruction(self, pc: int, instruction: str,
                          instr_type: str, skip_external: bool) -> bool:
        """
        处理单条指令执行

        Args:
            pc: 当前程序计数器
            instruction: 汇编指令文本
            instr_type: 来自 radare2 分析的指令类型
            skip_external: 是否跳过外部调用

        Returns:
            True if execution successful, False otherwise
        """
        try:
            # Handle different instruction types based on radare2's classification
            if instr_type == "call":
                return self._handle_call_instruction(instruction, skip_external)
            elif instr_type in ["jmp", "cjmp", "ujmp"]:  # Different jump types
                return self._handle_jump_instruction(instruction)
            elif instr_type == "ret":
                return self._handle_return_instruction()
            elif instr_type in ["int", "syscall"]:  # System calls/interrupts
                return self._handle_syscall_instruction(instruction)
            else:
                # 普通指令，直接单步模拟
                result = self.r2.cmd("aes")
                return "ESIL BREAK" not in result and "INVALID" not in result

        except Exception as e:
            self.logger.error(f"处理指令错误 @ 0x{pc:x}: {e}")
            return False

    def _handle_call_instruction(self, instruction: str, skip_external: bool) -> bool:
        """
        处理 call（调用）类型指令

        Args:
            instruction: 指令文本，如 "call sym.func" 或 "call sym.imp.printf"
            skip_external: 是否跳过外部库调用（如 printf、malloc）

        行为说明：
            - 若遇到外部调用（sym.imp.），且 skip_external=True，则自动模拟返回值并跳过
            - 若为内部符号调用，优先判断是否需要进入（可通过白名单调控）；能跳过则直接 aeso
            - 其他情况下按照常规 aes 步进

        返回:
            指令执行是否成功（bool）

        这一设计便于 LLM 分析减少依赖外部环境及提高模拟覆盖率。
        """
        if "sym.imp." in instruction and skip_external:
            # External library function
            func_name = self._extract_function_name(instruction, "sym.imp.")
            self._handle_external_call(func_name)
            self.r2.cmd("aess")  # Step skip
            self.logger.debug(f"跳过外部调用: {func_name}")
            return True
        elif "sym." in instruction:
            # Internal function - decision point
            func_name = self._extract_function_name(instruction, "sym.")
            if self._should_step_into_function(func_name):
                result = self.r2.cmd("aes")  # Step into
            else:
                self.r2.cmd("aeso")  # Step over
            return True
        else:
            result = self.r2.cmd("aes")
            return "ESIL BREAK" not in result

    def _handle_jump_instruction(self, instruction: str) -> bool:
        """处理跳转指令"""
        result = self.r2.cmd("aes")
        return "ESIL BREAK" not in result

    def _handle_return_instruction(self) -> bool:
        """处理返回指令"""
        result = self.r2.cmd("aes")
        return "ESIL BREAK" not in result

    def _handle_syscall_instruction(self, instruction: str) -> bool:
        """处理系统调用和中断（如 int 0x80，syscall 指令，后续可扩展模拟常用系统调用行为）"""
        result = self.r2.cmd("aes")
        return "ESIL BREAK" not in result

    def _extract_function_name(self, instruction: str, prefix: str) -> str:
        """从调用指令中提取函数名"""
        try:
            parts = instruction.split(prefix)
            if len(parts) > 1:
                return parts[1].split()[0].rstrip(';').rstrip(',')
        except:
            pass
        return "unknown"

    def _should_step_into_function(self, func_name: str) -> bool:
        """决定是否进入用户自定义函数（过滤常见系统启动析构符号，仅进入用户业务逻辑）"""
        skip_functions = {
            '__stack_chk_fail', '_init', '_fini', '__libc_start_main',
            '__do_global_dtors_aux', 'deregister_tm_clones', 'register_tm_clones'
        }
        return func_name not in skip_functions and not func_name.startswith("__")

    def _handle_external_call(self, func_name: str):
        """处理外部函数调用（支持自定义钩子/自动模拟返回值）"""
        regs = self.arch_info["registers"]
        accumulator_reg = regs.get("accumulator_reg_name", regs.get('return_reg_name', 'x0'))
        if func_name in self.external_handlers:
            self.external_handlers[func_name]()  # 调用自定义模拟处理器
        else:
            # 常用库函数的默认模拟（无需副作用，仅设置返回值，方便静态分析）
            default_handlers = {
                'printf': lambda: self.r2.cmd(f"aer {accumulator_reg}=10"), # 注意，考虑到格式化字符串的存在，计算准确的字符串长度并不简单，所以，直接返回一个虚拟的打印输出长度10
                'scanf': lambda: self.r2.cmd(f"aer {accumulator_reg}=1"),
                # 字符串处理函数
                'strlen': lambda: self.r2.cmd(f"aer {accumulator_reg}=8"),
                'strcmp': lambda: self.r2.cmd(f"aer {accumulator_reg}=0"),
                'strcpy': lambda: self.r2.cmd(f"aer {accumulator_reg}=" +
                                            str(self.r2.cmdj("aerj").get(regs['arg_regs'][0], "0x0"))),
                'strcat': lambda: self.r2.cmd(f"aer {accumulator_reg}=" +
                                            str(self.r2.cmdj("aerj").get(regs['arg_regs'][0], "0x0"))),
                'strchr': lambda: self.r2.cmd(f"aer {accumulator_reg}=0x401234"),  # 假设找到
                'strstr': lambda: self.r2.cmd(f"aer {accumulator_reg}=0x401234"),  # 假设找到
                'strncmp': lambda: self.r2.cmd(f"aer {accumulator_reg}=0"),
                'strdup': lambda: self.r2.cmd(f"aer {accumulator_reg}=0x20000"),
                # 常见内存操作函数
                'memmove': lambda: self.r2.cmd(f"aer {accumulator_reg}=" +
                                            str(self.r2.cmdj("aerj").get(regs['arg_regs'][0], "0x0"))),
                'memset': lambda: self.r2.cmd(f"aer {accumulator_reg}=" +
                            str(self.r2.cmdj("aerj").get(regs['arg_regs'][0], "0x0"))),
                'malloc': lambda: self.r2.cmd(f"aer {accumulator_reg}=0x20000"),
                'memcpy': lambda: self.r2.cmd(f"aer {accumulator_reg}=" +
                             self.r2.cmdj("aerj").get(regs['arg_regs'][0])),
                'bzero': lambda: None,  # void返回
                'calloc': lambda: self.r2.cmd(f"aer {accumulator_reg}=0x20000"),
                'realloc': lambda: self.r2.cmd(f"aer {accumulator_reg}=" +
                                            str(self.r2.cmdj("aerj").get(regs['arg_regs'][0], "0x20000"))),
                'alloca': lambda: self.r2.cmd(f"aer {accumulator_reg}=0x20000"),
                'free': lambda: None,  # free 无副作用
                # 文件IO
                'fopen': lambda: self.r2.cmd(f"aer {accumulator_reg}=0x600000"),   # 假设FILE*
                'fclose': lambda: self.r2.cmd(f"aer {accumulator_reg}=0"),
                'fread': lambda: self.r2.cmd(f"aer {accumulator_reg}=1024"),       # 假设读取字节数
                'fwrite': lambda: self.r2.cmd(f"aer {accumulator_reg}=1024"),
                'fprintf': lambda: self.r2.cmd(f"aer {accumulator_reg}=10"),
                'fgets': lambda: self.r2.cmd(f"aer {accumulator_reg}=" +
                                            str(self.r2.cmdj("aerj").get(regs['arg_regs'][0], "0x0"))),
                # 数学函数
                'abs': lambda: self.r2.cmd(f"aer {accumulator_reg}=42"),
                'pow': lambda: self.r2.cmd(f"aer {accumulator_reg}=100"),
                'sqrt': lambda: self.r2.cmd(f"aer {accumulator_reg}=10"),
                'rand': lambda: self.r2.cmd(f"aer {accumulator_reg}=0x1337"),
                'srand': lambda: None,  # 无返回值
                # 系统调用
                'getpid': lambda: self.r2.cmd(f"aer {accumulator_reg}=1234"),
                'time': lambda: self.r2.cmd(f"aer {accumulator_reg}=1640995200"),  # Unix时间戳
                'sleep': lambda: self.r2.cmd(f"aer {accumulator_reg}=0"),
                'exit': lambda: None,  # 程序终止
            }

            if func_name in default_handlers:
                default_handlers[func_name]()
                self.logger.debug(f"模拟 {func_name}")
            else:
                # 任何无法识别的函数一律返回0，无副作用
                self.r2.cmd(f"aer {accumulator_reg}=0")
                self.logger.warning(f"未知外部函数: {func_name}")

    def add_external_handler(self, func_name: str, handler_func):
        """添加自定义外部函数处理器"""
        self.external_handlers[func_name] = handler_func
        self.logger.info(f"添加外部处理器: {func_name}")

    def emulate_algorithm(self, func_name: str,
                         inputs: Dict[str, Union[int, bytes, str]] = None,
                         optimization_level: str = "normal") -> Dict[str, Any]:
        """
        专门用于算法分析的简化接口 - 优化版本

        Args:
            func_name: 函数名 (例如 "sym.encrypt_data")
            inputs: 输入数据，自动参数映射
            optimization_level: "minimal", "normal", "detailed"

        Returns:
            优化的分析结果，专注于算法行为
        """
        # 设置优化级别
        original_level = (self.minimal_mode, self.track_memory_access)
        self.set_optimization_level(optimization_level)

        try:
            # 自动映射输入到调用约定
            register_inputs, memory_inputs = self._map_algorithm_inputs(inputs or {})

            result = self.emulate_region(
                start_addr=func_name,
                register_inputs=register_inputs,
                memory_inputs=memory_inputs,
                skip_external=True
            )

            # 添加算法特定的分析
            result['algorithm_analysis'] = self._analyze_algorithm_behavior_optimized(result)

            return result

        finally:
            # 恢复原始设置
            self.minimal_mode, self.track_memory_access = original_level

    def _map_algorithm_inputs(self, inputs: Dict[str, Union[int, bytes, str]]) -> Tuple[Dict, Dict]:
        """将用户友好的输入映射到寄存器和内存"""
        register_inputs = {}
        memory_inputs = {}
        current_mem_addr = 0x10000

        calling_regs = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']
        reg_index = 0

        arch_info = self.r2.cmdj("ij")
        is_64bit = arch_info and arch_info.get("bin", {}).get("bits", 32) == 64

        for key, value in inputs.items():
            if isinstance(value, (bytes, str)):
                if isinstance(value, str):
                    value = value.encode() + b'\x00'

                memory_inputs[current_mem_addr] = value

                if is_64bit and reg_index < len(calling_regs):
                    register_inputs[calling_regs[reg_index]] = current_mem_addr
                else:
                    register_inputs[f'arg{reg_index}'] = current_mem_addr

                current_mem_addr += len(value) + 16
                reg_index += 1

            elif isinstance(value, int):
                if is_64bit and reg_index < len(calling_regs):
                    register_inputs[calling_regs[reg_index]] = value
                else:
                    register_inputs[f'arg{reg_index}'] = value
                reg_index += 1

        return register_inputs, memory_inputs

    def _analyze_algorithm_behavior_optimized(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """
        优化的算法行为分析 - 专注于关键模式
        """
        analysis = {
            'crypto_indicators': [],
            'loop_patterns': [],
            'data_transformations': [],
            'register_usage_patterns': {},
            'memory_access_patterns': {},
            'execution_hotspots': []
        }

        if 'execution_trace' not in result:
            return analysis

        trace = result['execution_trace']

        # 分析加密相关操作 - 只看有变化的步骤
        crypto_ops = ['xor', 'rol', 'ror', 'shl', 'shr', 'and', 'or']
        crypto_count = {}

        for snapshot in trace:
            instr_lower = snapshot.instruction.lower()
            for op in crypto_ops:
                if op in instr_lower:
                    crypto_count[op] = crypto_count.get(op, 0) + 1
                    analysis['crypto_indicators'].append({
                        'step': snapshot.step_number,
                        'operation': op,
                        'pc': f"0x{snapshot.pc:x}",
                        'register_changes': len(snapshot.register_changes),
                        'memory_changes': len(snapshot.memory_changes)
                    })

        # 检测循环模式 - 基于PC重复访问
        pc_visits = {}
        for snapshot in trace:
            pc = snapshot.pc
            pc_visits[pc] = pc_visits.get(pc, 0) + 1

        # 只报告明显的循环（访问次数 > 2）
        significant_loops = [(pc, count) for pc, count in pc_visits.items() if count > 2]
        analysis['loop_patterns'] = [
            {'pc': f"0x{pc:x}", 'iterations': count, 'likely_loop': count > 5}
            for pc, count in significant_loops
        ]

        # 分析寄存器使用模式
        reg_modification_count = {}
        reg_first_use = {}

        for snapshot in trace:
            for reg in snapshot.register_changes:
                if reg not in reg_modification_count:
                    reg_modification_count[reg] = 0
                    reg_first_use[reg] = snapshot.step_number
                reg_modification_count[reg] += 1

        analysis['register_usage_patterns'] = {
            'most_modified': sorted(reg_modification_count.items(),
                                  key=lambda x: x[1], reverse=True)[:5],
            'first_use_timeline': reg_first_use
        }

        # 分析内存访问模式
        memory_regions = {}
        for snapshot in trace:
            for addr in snapshot.memory_changes:
                region = addr & 0xfffff000  # 4KB页对齐
                if region not in memory_regions:
                    memory_regions[region] = {'count': 0, 'first_step': snapshot.step_number}
                memory_regions[region]['count'] += 1

        analysis['memory_access_patterns'] = {
            'active_regions': len(memory_regions),
            'hotspots': [
                {
                    'region': f"0x{region:x}",
                    'access_count': info['count'],
                    'first_access': info['first_step']
                }
                for region, info in sorted(memory_regions.items(),
                                         key=lambda x: x[1]['count'], reverse=True)[:3]
            ]
        }

        # 识别执行热点 - 基于变化密度
        if len(trace) > 10:
            change_density = []
            window_size = min(10, len(trace) // 3)

            for i in range(len(trace) - window_size + 1):
                window = trace[i:i + window_size]
                total_changes = sum(
                    len(s.register_changes) + len(s.memory_changes)
                    for s in window
                )
                change_density.append({
                    'start_step': window[0].step_number,
                    'end_step': window[-1].step_number,
                    'change_density': total_changes / window_size,
                    'start_pc': f"0x{window[0].pc:x}"
                })

            # 找到变化密度最高的区域
            hotspots = sorted(change_density, key=lambda x: x['change_density'], reverse=True)[:3]
            analysis['execution_hotspots'] = hotspots

        return analysis

    def compare_executions_optimized(self, func_name: str,
                                   input_sets: List[Dict[str, Union[int, bytes, str]]],
                                   optimization_level: str = "minimal") -> Dict[str, Any]:
        """
        优化的执行比较 - 专注于关键差异

        Args:
            func_name: 要分析的函数名
            input_sets: 不同的输入集合列表
            optimization_level: 优化级别

        Returns:
            比较分析结果，突出关键差异
        """
        results = []

        # 设置优化级别
        original_level = (self.minimal_mode, self.track_memory_access)
        self.set_optimization_level(optimization_level)

        try:
            for i, inputs in enumerate(input_sets):
                self.logger.info(f"执行测试用例 {i+1}/{len(input_sets)}")
                result = self.emulate_algorithm(func_name, inputs, optimization_level)
                result['input_index'] = i
                result['inputs'] = inputs
                results.append(result)

        finally:
            # 恢复原始设置
            self.minimal_mode, self.track_memory_access = original_level

        # 进行比较分析
        comparison = self._analyze_execution_differences(results)

        return {
            'individual_results': results,
            'comparative_analysis': comparison,
            'summary': {
                'total_tests': len(input_sets),
                'successful_tests': len([r for r in results if r['stop_reason'] == 'completed']),
                'optimization_level': optimization_level
            }
        }

    def _analyze_execution_differences(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """分析执行差异 - 专注于重要变化"""
        if len(results) < 2:
            return {'error': 'Need at least 2 executions to compare'}

        analysis = {
            'execution_stats_variance': {},
            'algorithm_behavior_comparison': {},
            'divergence_analysis': {},
            'input_sensitivity': {}
        }

        # 比较执行统计
        step_counts = [r['execution_stats']['steps_executed'] for r in results]
        trace_counts = [r['execution_stats']['trace_entries'] for r in results]

        analysis['execution_stats_variance'] = {
            'step_count_range': (min(step_counts), max(step_counts)),
            'step_count_variance': max(step_counts) - min(step_counts),
            'trace_efficiency': {
                'min_compression': min(trace_counts[i] / step_counts[i] if step_counts[i] > 0 else 0
                                     for i in range(len(results))),
                'max_compression': max(trace_counts[i] / step_counts[i] if step_counts[i] > 0 else 0
                                     for i in range(len(results)))
            }
        }

        # 比较算法行为
        if all('algorithm_analysis' in r for r in results):
            crypto_counts = []
            loop_counts = []

            for result in results:
                analysis_data = result['algorithm_analysis']
                crypto_counts.append(len(analysis_data.get('crypto_indicators', [])))
                loop_counts.append(len(analysis_data.get('loop_patterns', [])))

            analysis['algorithm_behavior_comparison'] = {
                'crypto_operations_variance': {
                    'range': (min(crypto_counts), max(crypto_counts)),
                    'consistent': len(set(crypto_counts)) == 1
                },
                'loop_behavior_variance': {
                    'range': (min(loop_counts), max(loop_counts)),
                    'consistent': len(set(loop_counts)) == 1
                }
            }

        # 分析输入敏感性
        final_states = []
        for result in results:
            if 'final_state' in result:
                final_states.append({
                    'register_changes': len(result['final_state'].get('register_changes', {})),
                    'memory_changes': len(result['final_state'].get('memory_changes', {}))
                })

        if final_states:
            reg_changes = [fs['register_changes'] for fs in final_states]
            mem_changes = [fs['memory_changes'] for fs in final_states]

            analysis['input_sensitivity'] = {
                'register_sensitivity': {
                    'range': (min(reg_changes), max(reg_changes)),
                    'variance': max(reg_changes) - min(reg_changes)
                },
                'memory_sensitivity': {
                    'range': (min(mem_changes), max(mem_changes)),
                    'variance': max(mem_changes) - min(mem_changes)
                }
            }

        return analysis

    def export_for_llm_analysis(self, result: Dict[str, Any],
                               include_raw_trace: bool = False) -> Dict[str, Any]:
        """
        导出专为 LLM 分析优化的数据格式

        Args:
            result: 模拟结果
            include_raw_trace: 是否包含原始追踪（通常不需要）

        Returns:
            LLM 友好的分析数据
        """
        export_data = {
            'execution_summary': {
                'total_steps': result['execution_stats']['steps_executed'],
                'traced_steps': result['execution_stats']['trace_entries'],
                'compression_achieved': result['execution_stats'].get('compression_ratio', 'N/A'),
                'stop_reason': result['stop_reason']
            },
            'final_changes': result.get('final_state', {}),
            'algorithm_insights': result.get('algorithm_analysis', {}),
            'execution_metadata': {
                'unique_registers_modified': result['execution_stats'].get('unique_registers_modified', 0),
                'unique_memory_modified': result['execution_stats'].get('unique_memory_modified', 0),
                'total_register_changes': result['execution_stats'].get('total_register_changes', 0),
                'total_memory_changes': result['execution_stats'].get('total_memory_changes', 0)
            }
        }

        # 只在明确请求时包含原始追踪
        if include_raw_trace and 'execution_trace' in result:
            export_data['execution_trace_summary'] = [
                {
                    'step': s.step_number,
                    'pc': f"0x{s.pc:x}",
                    'instruction_type': s.instruction_type,
                    'changes': {
                        'registers': len(s.register_changes),
                        'memory': len(s.memory_changes)
                    }
                }
                for s in result['execution_trace'][:50]  # 只取前50步以限制大小
            ]

        return export_data

    def set_logging_level(self, level):
        """设置日志级别"""
        self.logger.setLevel(level)


# 优化使用示例
if __name__ == "__main__":
    import r2pipe
    import logging

    # Setup logging
    logging.basicConfig(level=logging.INFO)

    r2 = r2pipe.open("./00_angr_find/00_angr_find_arm")
    emulator = ESILEmulator(r2)

    print("=== Example 1: Code Block Analysis ===")
    main_addr = r2.cmdj("aaa; afij @ main")[0]['addr']
    ops = r2.cmdj(f"pdfj @ {main_addr}").get('ops', [])
    scanf_funcs = [(i, cmd) for i, cmd in enumerate(ops) if cmd.get('type', '') == 'call' and '.scanf' in cmd.get('disasm', '')]
    first_scanf = scanf_funcs[0][1]
    after_scanf = ops[scanf_funcs[0][0] + 1] if len(ops) > scanf_funcs[0][0] else None
    printf_funcs = [(i, cmd) for i, cmd in enumerate(ops) if cmd.get('type', '') == 'call' and '.printf' in cmd.get('disasm', '') and i > scanf_funcs[0][0]]
    first_printf = printf_funcs[0][1] if printf_funcs else None
    before_printf = ops[printf_funcs[0][0] - 1] if scanf_funcs[0][0] > 0 else None

    # Analyze specific code block after user input
    result1 = emulator.emulate_region(
        start_addr='main', # after_scanf.get('addr', 0x0),  # After scanf (str wzr, [var_10h])
        end_addr=None, # before_printf.get('addr', 0x0),    # Before output (add x0, x0, 0x6b7)
        register_inputs={},
        stack_inputs={-0x17: b"AAAAAAAA\x00"},
        memory_inputs={0x10000: b"secret_data_here"},
        skip_external=True
    )

    print(f"Block emulation: {result1['steps_executed']} steps")
    print(f"Stop reason: {result1['stop_reason']}")

    # Analyze crypto-like operations
    if result1.get('algorithm_analysis'):
        crypto_ops = result1['algorithm_analysis']['crypto_indicators']
        print(f"Crypto operations detected: {len(crypto_ops)}")

    print("\n=== Example 2: Algorithm Analysis ===")
    # Simplified algorithm analysis
    result2 = emulator.emulate_algorithm(
        func_name="sym.encrypt_data",
        inputs={
            "data": b"AAAAAAAAAAAAAAAA",  # 16 bytes test data
            "key": b"1234567890123456",   # 16 bytes key
            "length": 16
        }
    )

    print(f"Algorithm steps: {result2['steps_executed']}")
    if 'algorithm_analysis' in result2:
        analysis = result2['algorithm_analysis']
        print(f"Crypto indicators: {len(analysis['crypto_indicators'])}")
        print(f"Loop patterns: {len(analysis['loop_patterns'])}")
        print(f"Data transformations: {len(analysis['data_transformations'])}")

    print("\n=== Example 3: Breakpoint Analysis ===")
    # Emulate with breakpoints for detailed analysis
    result3 = emulator.emulate_with_breakpoints(
        start_addr="sym.complex_function",
        breakpoints=["sym.internal_func1", "sym.internal_func2", 0x08048500],
        register_inputs={"rdi": 0x10000},
        memory_inputs={0x10000: b"test_input_data\x00"}
    )

    print(f"Breakpoint hits: {len(result3['breakpoint_hits'])}")
    for i, bp in enumerate(result3['breakpoint_hits']):
        print(f"  BP {i+1}: 0x{bp['address']:x} after {bp['step_count']} steps")

    print("\n=== Example 4: Differential Analysis ===")
    # Compare behavior with different inputs
    test_inputs = [
        {"data": b"AAAAAAAAAAAAAAAA", "key": b"key1111111111111"},
        {"data": b"BBBBBBBBBBBBBBBB", "key": b"key1111111111111"},
        {"data": b"AAAAAAAAAAAAAAAA", "key": b"key2222222222222"},
        {"data": b"1234567890123456", "key": b"abcdefghijklmnop"},
    ]

    comparison = emulator.compare_executions("sym.encrypt_data", test_inputs)

    print(f"Tested {len(test_inputs)} input combinations")
    step_variance = comparison['comparative_analysis']['input_sensitivity']['step_count_variance']
    print(f"Step count variance: {step_variance['min']}-{step_variance['max']} (avg: {step_variance['avg']:.1f})")

    divergence_points = comparison['comparative_analysis']['execution_patterns']['divergence_points']
    print(f"Execution divergence points: {len(divergence_points)}")

    print("\n=== Example 5: Custom External Handler ===")
    # Add custom external function handler
    def custom_random_handler():
        """Simulate rand() returning predictable values for analysis"""
        emulator.r2.cmd("aer rax=0x12345678")
        print("Custom rand() returned 0x12345678")

    emulator.add_external_handler("rand", custom_random_handler)

    # Now emulate code that calls rand()
    result5 = emulator.emulate_region(
        start_addr="sym.function_using_rand",
        skip_external=True  # Will use our custom handler
    )

    print(f"Function with custom rand(): {result5['steps_executed']} steps")

    print("\n=== Example 6: Memory Trace Analysis ===")
    # Detailed memory access analysis
    result6 = emulator.emulate_region(
        start_addr="sym.memory_intensive_func",
        register_inputs={"rdi": 0x20000, "rsi": 0x30000},
        memory_inputs={
            0x20000: b"source_buffer_data_here" + b"\x00" * 100,
            0x30000: b"\x00" * 200  # Destination buffer
        }
    )

    # Analyze memory access patterns
    memory_writes = []
    for snapshot in result6['execution_trace']:
        if snapshot.memory_changes:
            memory_writes.append({
                'step': snapshot.step_number,
                'changes': len(snapshot.memory_changes),
                'addresses': list(snapshot.memory_changes.keys())
            })

    print(f"Memory write operations: {len(memory_writes)}")
    if memory_writes:
        total_addresses = set()
        for write in memory_writes:
            total_addresses.update(write['addresses'])
        print(f"Unique memory addresses touched: {len(total_addresses)}")

    print("\n=== Analysis Complete ===")
    print("The ESILEmulator provides comprehensive analysis capabilities:")
    print("- Code block emulation with precise start/end control")
    print("- Algorithm analysis with automatic calling convention handling")
    print("- Breakpoint-based debugging and analysis")
    print("- Differential analysis for input sensitivity testing")
    print("- Custom external function handling")
    print("- Detailed memory access pattern tracking")
    print("- Crypto-operation detection and loop analysis")

    print("=== 优化的 ESIL 模拟器示例 ===")

    print("\n1. 最小模式分析 - 只追踪关键变化")
    emulator.set_optimization_level("minimal")

    result1 = emulator.emulate_algorithm(
        func_name="sym.encrypt_data",
        inputs={
            "data": b"AAAAAAAAAAAAAAAA",
            "key": b"1234567890123456",
            "length": 16
        }
    )

    # 导出 LLM 友好格式
    llm_data = emulator.export_for_llm_analysis(result1)
    print(f"压缩比: {llm_data['execution_summary']['compression_achieved']}")
    print(f"最终状态变化: {len(llm_data['final_changes'].get('register_changes', {}))} 寄存器, "
          f"{len(llm_data['final_changes'].get('memory_changes', {}))} 内存位置")

    print("\n2. 差异分析 - 比较不同输入")
    test_inputs = [
        {"data": b"AAAAAAAAAAAAAAAA", "key": b"key1111111111111"},
        {"data": b"BBBBBBBBBBBBBBBB", "key": b"key1111111111111"},
        {"data": b"AAAAAAAAAAAAAAAA", "key": b"key2222222222222"},
    ]

    comparison = emulator.compare_executions_optimized("sym.encrypt_data", test_inputs)

    comp_analysis = comparison['comparative_analysis']
    print(f"步数变化范围: {comp_analysis['execution_stats_variance']['step_count_range']}")
    print(f"算法行为一致性: {comp_analysis.get('algorithm_behavior_comparison', {})}")

    print("\n3. 详细模式 - 用于深入分析")
    emulator.set_optimization_level("detailed")

    result3 = emulator.emulate_region(
        start_addr="sym.complex_function",
        register_inputs={"rdi": 0x10000},
        memory_inputs={0x10000000: b"detailed_analysis_input\x00"}
    )

    if 'algorithm_analysis' in result3:
        analysis = result3['algorithm_analysis']
        print(f"执行热点: {len(analysis.get('execution_hotspots', []))}")
        print(f"内存访问模式: {analysis.get('memory_access_patterns', {})}")

    print("\n=== 优化效果总结 ===")
    print("✓ 只追踪实际变化，消除冗余数据")
    print("✓ 智能过滤无关紧要的寄存器和内存")
    print("✓ 提供多级优化选项（minimal/normal/detailed）")
    print("✓ LLM 友好的数据导出格式")
    print("✓ 专注于算法分析的洞察")
    print("✓ 大幅减少需要传输给 LLM 的数据量")
