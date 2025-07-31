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
    register_changes: Dict[str, Dict[str, int]]           # 本步变化的寄存器，包含上一次和这一次的值
    memory_changes: Dict[int, Dict[str, bytes]]           # 本步变化的内存，包含上一次和这一次的值

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
                      max_steps: int = 10000,
                      stop_type: Optional[StopConditionType] = None,
                      robust_function_exit: bool = False,
                      robust_bb_exit: bool = False) -> Dict[str, Any]:
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
            stop_type: 显式指定停止条件类型
            robust_function_exit: 是否使用函数的robust出口检测
            robust_bb_exit: 是否使用基本块的robust出口检测

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
        stop_condition = self._determine_stop_condition(start_addr, end_addr, stop_type, robust_function_exit, robust_bb_exit)

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
                instruction_text = instr.get("disasm", "unknown")
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

            # 检查函数/基本块出口列表停止条件
            condition_type, condition_value = stop_condition
            if condition_type in [StopConditionType.FUNCTION_END, StopConditionType.BASIC_BLOCK_END] and isinstance(condition_value, list):
                if current_pc in condition_value:
                    stop_reason = f"reached_{condition_type.value}"
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
                changes[reg] = {
                    "prev": prev_regs.get(reg, None),
                    "curr": value
                }

        # 在非最小模式下，检查消失的寄存器
        if not self.minimal_mode:
            for reg in prev_regs:
                if reg not in curr_regs:
                    changes[reg] = {
                        "prev": prev_regs.get(reg, None),
                        "curr": None  # 表示寄存器被清除
                    }

        return changes

    def _compute_memory_diff(self, prev_mem: Dict[int, bytes],
                           curr_mem: Dict[int, bytes]) -> Dict[int, bytes]:
        """计算内存变化 - 只返回实际改变的内存"""
        changes = {}

        # 检查修改的内存
        for addr, data in curr_mem.items():
            if addr not in prev_mem or prev_mem[addr] != data:
                changes[addr] = {
                    "prev": prev_mem.get(addr, b''),
                    "curr": data
                }

        # 在非最小模式下，检查被清除的内存
        if not self.minimal_mode:
            for addr in prev_mem:
                if addr not in curr_mem:
                    changes[addr] = {
                        "prev": prev_mem.get(addr, b''),
                        "curr": None  # 表示内存被清除
                    }

        return changes

    def _is_significant_step(self, snapshot: OptimizedExecutionSnapshot) -> bool:
        """判断是否为重要步骤 - 决定是否包含在追踪中"""

        # 总是包含有变化的步骤除非只有PC寄存器变化
        pc_reg = self.arch_info["registers"]["instruction_reg_name"]
        if not snapshot.memory_changes and len(snapshot.register_changes) == 1 and pc_reg in snapshot.register_changes:
            return False
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

            # 动态生成适配架构的指针寄存器集合
            regs_info = self.arch_info.get("registers", {})
            dynamic_ptrs = list(regs_info.get("arg_regs", []))
            for key in ("accumulator_reg_name", "data_reg_name",
                        "source_index_reg_name", "dest_index_reg_name"):
                val = regs_info.get(key)
                if val:
                    dynamic_ptrs.append(val)
            if not dynamic_ptrs:  # fallback (兼容 x86)
                dynamic_ptrs = ['rdi', 'rsi', 'rdx', 'edi', 'esi', 'eax']
            pointer_regs = list(dict.fromkeys(dynamic_ptrs))  # 去重保序

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
                        valid_parts = [p for p in parts[1:] if all(c in '0123456789abcdefABCDEF' for c in p)]  # 跳过地址部分
                        hex_bytes = ' '.join(valid_parts)
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
        检查是否应该停止模拟（仅处理ADDRESS、MANUAL、INSTRUCTION_COUNT类型）

        Args:
            current_pc: 当前程序计数器值
            stop_condition: 停止条件元组 (StopConditionType, condition_value)

        Returns:
            True if emulation should stop
        """
        condition_type, condition_value = stop_condition

        if condition_type == StopConditionType.ADDRESS and condition_value is not None:
            return current_pc >= condition_value
        elif condition_type == StopConditionType.INSTRUCTION_COUNT and condition_value is not None:
            # instruction count should be handled elsewhere, but included for completeness
            return False
        elif condition_type == StopConditionType.MANUAL:
            # For manual mode, continue until explicit stop
            return False
        elif condition_type in [StopConditionType.FUNCTION_END, StopConditionType.BASIC_BLOCK_END]:
            # These are handled in the execution loop by checking next_pc against exit list
            return False

        return False

    def _determine_function_end(self, pc: int, robust: bool = False) -> Union[List[int], None]:
        """
        确定函数结束地址

        Args:
            pc: 当前程序计数器值
            robust: 是否使用robust模式（收集所有外跳出口）

        Returns:
            返回包含所有相关地址的列表（包括函数尾和外跳出口）
        """
        info = self.r2.cmdj(f"afij @ {pc}")
        blocks = self.r2.cmdj(f"afbj @ {pc}")
        if not info:
            return None

        f = info[0]
        base = f["addr"]
        size = f["size"]
        upper = base + size
        last_block = self.r2.cmdj(f"afbj @ {base}")[-1]
        last_instr_addr = last_block.get('instrs', [0])[-1]

        exits = [last_instr_addr]  # 默认最后一个指令的地址作兜底

        if not robust:
            return exits

        # Robust模式：收集所有外跳出口
        try:
            bbs = self.r2.cmdj(f"afbj @ {base}")
            for bb in bbs:
                for k in ("jump", "fail"):
                    tgt = bb.get(k)
                    if tgt is not None and not (base <= tgt < upper):
                        if tgt not in exits:
                            exits.append(tgt)
        except:
            pass

        return exits

    def _determine_basic_block_end(self, pc: int, robust: bool = False) -> Union[List[int], None]:
        """
        确定基本块结束地址

        Args:
            pc: 当前程序计数器值
            robust: 是否使用robust模式（收集所有外跳出口）

        Returns:
            返回包含所有相关地址的列表（包括块尾和外跳出口）
        """
        bb = self.r2.cmdj(f"abj @ {pc}")
        if not bb or len(bb) == 0:
            return None

        bb_info = bb[0]
        base = bb_info["addr"]
        size = bb_info["size"]
        upper = base + size

        last_instr_addr = bb_info.get('instrs', [0])[-1]

        exits = [last_instr_addr]  # 默认最后一个指令的地址作兜底

        if not robust:
            return exits

        # Robust模式：收集所有外跳出口
        try:
            # 收集 jump 和 fail 目标
            for k in ("jump", "fail"):
                tgt = bb_info.get(k)
                if tgt is not None:
                    # 检查是否在基本块范围内
                    if not (base <= tgt < upper):
                        if tgt not in exits:
                            exits.append(tgt)
        except:
            pass

        return exits

    def _determine_stop_condition(self, start_addr: Union[str, int],
                                end_addr: Optional[Union[str, int]],
                                stop_type: Optional[StopConditionType] = None,
                                robust_function_exit: bool = False,
                                robust_bb_exit: bool = False) -> Tuple[StopConditionType, Any]:
        """
        智能确定模拟停止条件

        Args:
            start_addr: 起始地址、符号名（如：main）或表达式（如：main+0x15）
            end_addr: 结束地址（符号名、表达式或整数地址）（可选）
            robust_function_exit: 是否使用函数的robust出口检测
            robust_bb_exit: 是否使用基本块的robust出口检测

        Returns:
            (StopConditionType, 具体条件) 元组（对于函数/基本块情况，具体条件为包含出口地址的列表）

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
        if stop_type == StopConditionType.FUNCTION_END and func_info and len(func_info) > 0:
            # 使用 _determine_function_end 方法来获取函数结束地址列表
            func_end_list = self._determine_function_end(resolved_start, robust=robust_function_exit)
            return (StopConditionType.FUNCTION_END, func_end_list if func_end_list else [])

        bb_info = self.r2.cmdj(f"abj @ {resolved_start}") # 尝试获取基本块信息
        if stop_type == StopConditionType.BASIC_BLOCK_END and bb_info and len(bb_info) > 0:
            # 使用 _determine_basic_block_end 方法来获取基本块结束地址列表
            bb_end_list = self._determine_basic_block_end(resolved_start, robust=robust_bb_exit)
            return (StopConditionType.BASIC_BLOCK_END, bb_end_list if bb_end_list else [])

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
        """可参考 syscall.py 的实现"""
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
        skip_external=True,
        stop_type=StopConditionType.FUNCTION_END,
        max_steps=5000,
        robust_function_exit=True,
        robust_bb_exit=True
    )

    print(f"Block emulation: {result1['execution_stats']['steps_executed']} steps")
    print(f"Stop reason: {result1['stop_reason']}")
