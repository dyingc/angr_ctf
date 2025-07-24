#!/usr/bin/env python3
"""
Enhanced ESIL Emulator for radare2

A comprehensive emulator for code block and function analysis using radare2's ESIL.
Provides robust instruction classification, external function handling, and detailed
execution tracing with memory snapshots at each step.
"""

import json
import logging
from typing import Dict, List, Optional, Union, Any, Tuple
from dataclasses import dataclass
from enum import Enum


class StopConditionType(Enum):
    """Types of stop conditions for emulation."""
    ADDRESS = "address"        # Stop at specific address
    FUNCTION_END = "function_end"  # Stop at function boundary
    INSTRUCTION_COUNT = "instruction_count"  # Stop after N instructions
    EXPRESSION = "expression"  # Stop when ESIL expression is true
    MANUAL = "manual"         # Manual control required


@dataclass
class ExecutionSnapshot:
    """Snapshot of execution state at a single step."""
    pc: int                          # Program counter
    instruction: str                 # Assembly instruction
    instruction_type: str            # Instruction type (call, jump, mov, etc.)
    opcode: str                     # Raw opcode bytes
    registers: Dict[str, int]       # Register state
    memory_changes: Dict[int, bytes] # Memory changes in this step
    esil_expression: str            # ESIL representation
    step_number: int                # Step counter


class ESILEmulator:
    """
    Enhanced ESIL emulator for radare2 with robust instruction handling
    and comprehensive execution tracking.
    """

    def __init__(self, r2_instance):
        """
        Initialize the ESIL emulator.

        Args:
            r2_instance: radare2 instance (r2pipe or similar)
        """
        self.r2 = r2_instance
        self.logger = logging.getLogger(__name__)
        self.external_handlers = {}
        self.memory_snapshot_base = {}
        self.setup_environment()

    def setup_environment(self):
        """Set up optimal ESIL environment configuration."""
        self.r2.cmd("e io.cache=true")       # Enable memory caching
        self.r2.cmd("e asm.esil=false")      # Don't show ESIL by default
        self.r2.cmd("e asm.bytes=true")      # Show instruction bytes
        self.r2.cmd("e asm.comments=false")  # Reduce noise

    def emulate_region(self,
                      start_addr: Union[str, int],
                      end_addr: Optional[Union[str, int]] = None,
                      register_inputs: Optional[Dict[str, Union[int, bytes]]] = None,
                      stack_inputs: Optional[Dict[int, Union[bytes, int]]] = None,
                      memory_inputs: Optional[Dict[int, Union[bytes, int]]] = None,
                      skip_external: bool = True,
                      max_steps: int = 10000) -> Dict[str, Any]:
        """
        Unified region emulator for both code blocks and complete functions.

        Args:
            start_addr: Starting address (can be function name like "sym.encrypt" or hex address)
            end_addr: Ending address (None means auto-detect function/block boundary)
            register_inputs: Register values {"rdi": 0x1234, "rsi": b"data"}
            stack_inputs: Stack data {-0x10: b"input", -0x20: 0x1234} (negative = below ESP)
            memory_inputs: Memory data {0x10000: b"test_data", 0x20000: 0x12345678}
            skip_external: Whether to automatically skip external library functions
            max_steps: Maximum steps to prevent infinite loops

        Returns:
            Dict containing:
            - final_registers: Final register state
            - final_memory: Memory snapshot at end
            - execution_trace: List of ExecutionSnapshot for each step
            - steps_executed: Total steps taken
            - stop_reason: Why emulation stopped
        """
        # 1. Initialize VM and setup
        self._initialize_vm()
        self._setup_inputs(register_inputs, stack_inputs, memory_inputs)

        # 2. Determine stop condition intelligently
        stop_condition = self._determine_stop_condition(start_addr, end_addr)

        # 3. Execute with comprehensive monitoring
        result = self._execute_with_monitoring(start_addr, stop_condition, skip_external, max_steps)

        return result

    def _initialize_vm(self):
        """Initialize ESIL virtual machine with clean state."""
        self.r2.cmd("aei-")      # Deinitialize if already running
        self.r2.cmd("aei")       # Initialize ESIL VM state
        self.r2.cmd("aeim-")     # Remove existing stack
        self.r2.cmd("aeim 0x2000 0xffff")  # Initialize 64KB stack

        # Clear register state for clean start
        self.r2.cmd("ar0")       # Clear all registers

        # Set reasonable defaults
        arch_info = self.r2.cmdj("ij")
        if arch_info and "bin" in arch_info:
            bits = arch_info["bin"].get("bits", 64)
            if bits == 64:
                self.r2.cmd("aer rsp=0xbffffff0")
                self.r2.cmd("aer rbp=0xbffffff0")
            else:
                self.r2.cmd("aer esp=0xbffffff0")
                self.r2.cmd("aer ebp=0xbffffff0")

    def _determine_stop_condition(self, start_addr: Union[str, int],
                                 end_addr: Optional[Union[str, int]]) -> Tuple[StopConditionType, Any]:
        """
        Intelligently determine stop condition based on start/end parameters.

        Args:
            start_addr: Starting address or symbol
            end_addr: Ending address or None for auto-detection

        Returns:
            Tuple of (StopConditionType, condition_value)
        """
        if end_addr is not None:
            # Explicit end address provided
            return (StopConditionType.ADDRESS, self._resolve_address(end_addr))

        # Auto-detect based on start address
        resolved_start = self._resolve_address(start_addr)

        # Check if it's a function
        if isinstance(start_addr, str) and start_addr.startswith("sym."):
            func_info = self.r2.cmdj(f"afij @ {start_addr}")
            if func_info and len(func_info) > 0:
                func_end = func_info[0]["offset"] + func_info[0]["size"]
                return (StopConditionType.FUNCTION_END, func_end)

        # Check if it's within a known function
        func_info = self.r2.cmdj(f"afij @ {resolved_start}")
        if func_info and len(func_info) > 0:
            func_end = func_info[0]["offset"] + func_info[0]["size"]
            return (StopConditionType.FUNCTION_END, func_end)

        # Fall back to basic block analysis
        bb_info = self.r2.cmdj(f"abj @ {resolved_start}")
        if bb_info and len(bb_info) > 0:
            bb_end = bb_info[0]["addr"] + bb_info[0]["size"]
            return (StopConditionType.ADDRESS, bb_end)

        # Default: manual control needed
        return (StopConditionType.MANUAL, None)

    def _resolve_address(self, addr: Union[str, int]) -> int:
        """Resolve address from symbol name or hex string to integer."""
        if isinstance(addr, int):
            return addr
        if isinstance(addr, str):
            if addr.startswith("0x"):
                return int(addr, 16)
            else:
                # Assume it's a symbol, resolve it
                result = self.r2.cmd(f"?v {addr}").strip()
                return int(result, 16) if result else 0
        return 0

    def _setup_inputs(self, register_inputs: Optional[Dict],
                     stack_inputs: Optional[Dict],
                     memory_inputs: Optional[Dict]):
        """
        Set up multiple input types with robust handling.

        Args:
            register_inputs: Register values and data pointers
            stack_inputs: Stack-relative data
            memory_inputs: Absolute memory locations
        """
        # Store initial memory state for change tracking
        self.memory_snapshot_base = self._get_memory_snapshot()

        if register_inputs:
            for reg, value in register_inputs.items():
                if isinstance(value, bytes):
                    # Allocate memory for bytes and point register to it
                    addr = 0x10000 + len(register_inputs) * 0x1000
                    self.r2.cmd(f"wx {value.hex()} @ {addr}")
                    self.r2.cmd(f"aer {reg}={addr}")
                    self.logger.debug(f"Set {reg} -> 0x{addr:x} (points to {len(value)} bytes)")
                else:
                    self.r2.cmd(f"aer {reg}={value}")
                    self.logger.debug(f"Set {reg} = 0x{value:x}")

        if stack_inputs:
            for offset, value in stack_inputs.items():
                # Get current stack pointer
                esp_val = int(self.r2.cmd("aer esp").strip().split()[-1], 16)
                target_addr = esp_val + offset

                if isinstance(value, bytes):
                    self.r2.cmd(f"wx {value.hex()} @ 0x{target_addr:x}")
                    self.logger.debug(f"Stack[{offset:+d}] = {value} @ 0x{target_addr:x}")
                else:
                    self.r2.cmd(f"wx {value:08x} @ 0x{target_addr:x}")
                    self.logger.debug(f"Stack[{offset:+d}] = 0x{value:x} @ 0x{target_addr:x}")

        if memory_inputs:
            for addr, value in memory_inputs.items():
                if isinstance(value, bytes):
                    self.r2.cmd(f"wx {value.hex()} @ 0x{addr:x}")
                    self.logger.debug(f"Memory[0x{addr:x}] = {value}")
                else:
                    self.r2.cmd(f"wx {value:08x} @ 0x{addr:x}")
                    self.logger.debug(f"Memory[0x{addr:x}] = 0x{value:x}")

    def _execute_with_monitoring(self, start_addr: Union[str, int],
                               stop_condition: Tuple[StopConditionType, Any],
                               skip_external: bool,
                               max_steps: int) -> Dict[str, Any]:
        """
        Execute emulation with comprehensive monitoring and tracing.

        Args:
            start_addr: Starting address for emulation
            stop_condition: Tuple of (type, value) for stop condition
            skip_external: Whether to skip external function calls
            max_steps: Maximum steps to execute

        Returns:
            Comprehensive execution results with full trace
        """
        # Seek to start and initialize PC
        self.r2.cmd(f"s {start_addr}")
        self.r2.cmd("aeip")

        execution_trace = []
        step_count = 0
        stop_reason = "completed"

        self.logger.info(f"Starting emulation at {start_addr}, stop condition: {stop_condition}")

        while step_count < max_steps:
            # Get current state
            current_pc = self._get_current_pc()

            # Check stop conditions
            if self._should_stop(current_pc, stop_condition):
                stop_reason = f"reached_{stop_condition[0].value}"
                break

            # Get detailed instruction information using pdj (confirmed to have 'type' field)
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
                self.logger.warning(f"Failed to parse instruction at 0x{current_pc:x}: {e}")
                instruction_text = self.r2.cmd(f"pi 1 @ 0x{current_pc:x}").strip()
                instruction_type = "unknown"
                opcode_bytes = ""
                esil_expr = ""

            # Handle different instruction types
            step_successful = self._handle_instruction(current_pc, instruction_text,
                                                     instruction_type, skip_external)

            if not step_successful:
                stop_reason = "execution_failed"
                break

            # Capture execution snapshot with memory changes
            snapshot = ExecutionSnapshot(
                pc=current_pc,
                instruction=instruction_text,
                instruction_type=instruction_type,
                opcode=opcode_bytes,
                registers=self._get_register_snapshot(),
                memory_changes=self._get_memory_changes(),
                esil_expression=esil_expr,
                step_number=step_count
            )

            execution_trace.append(snapshot)
            step_count += 1

            # Update memory baseline for next step
            self.memory_snapshot_base = self._get_memory_snapshot()

        if step_count >= max_steps:
            stop_reason = "max_steps_reached"

        return {
            'final_registers': self._get_register_snapshot(),
            'final_memory': self._get_memory_snapshot(),
            'execution_trace': execution_trace,
            'steps_executed': step_count,
            'stop_reason': stop_reason,
            'stop_condition': stop_condition
        }

    def _get_current_pc(self) -> int:
        """Get current program counter value."""
        pc_output = self.r2.cmd("aer eip").strip()  # Works for both 32/64 bit
        if not pc_output:
            pc_output = self.r2.cmd("aer rip").strip()  # Try 64-bit variant

        try:
            return int(pc_output.split()[-1], 16)
        except (ValueError, IndexError):
            return 0

    def _should_stop(self, current_pc: int, stop_condition: Tuple[StopConditionType, Any]) -> bool:
        """
        Check if emulation should stop based on current PC and stop condition.

        Args:
            current_pc: Current program counter value
            stop_condition: Tuple of (StopConditionType, condition_value)

        Returns:
            True if emulation should stop
        """
        condition_type, condition_value = stop_condition

        if condition_type == StopConditionType.ADDRESS and condition_value is not None:
            return current_pc >= condition_value
        elif condition_type == StopConditionType.FUNCTION_END and condition_value is not None:
            return current_pc >= condition_value
        elif condition_type == StopConditionType.MANUAL:
            # For manual mode, continue until explicit stop
            return False

        return False

    def _handle_instruction(self, pc: int, instruction: str,
                          instr_type: str, skip_external: bool) -> bool:
        """
        Handle execution of a single instruction with type-aware processing.

        Args:
            pc: Program counter
            instruction: Assembly instruction text
            instr_type: Instruction type from radare2 analysis
            skip_external: Whether to skip external calls

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
                # Regular instruction - step normally
                result = self.r2.cmd("aes")
                return "ESIL BREAK" not in result and "INVALID" not in result

        except Exception as e:
            self.logger.error(f"Error handling instruction at 0x{pc:x}: {e}")
            return False

    def _handle_call_instruction(self, instruction: str, skip_external: bool) -> bool:
        """Handle call instructions with external function detection."""
        if "sym.imp." in instruction and skip_external:
            # External library function
            func_name = self._extract_function_name(instruction, "sym.imp.")
            self._handle_external_call(func_name)
            self.r2.cmd("aeso")  # Step over
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
            # Direct call or computed call
            result = self.r2.cmd("aes")  # Step into by default
            return "ESIL BREAK" not in result

    def _handle_jump_instruction(self, instruction: str) -> bool:
        """Handle jump instructions."""
        result = self.r2.cmd("aes")
        return "ESIL BREAK" not in result

    def _handle_return_instruction(self) -> bool:
        """Handle return instructions."""
        result = self.r2.cmd("aes")
        return "ESIL BREAK" not in result

    def _handle_syscall_instruction(self, instruction: str) -> bool:
        """Handle system calls and interrupts."""
        # Could be extended to simulate specific syscalls
        result = self.r2.cmd("aes")
        return "ESIL BREAK" not in result

    def _extract_function_name(self, instruction: str, prefix: str) -> str:
        """Extract function name from call instruction."""
        try:
            parts = instruction.split(prefix)
            if len(parts) > 1:
                return parts[1].split()[0].rstrip(';').rstrip(',')
        except:
            pass
        return "unknown"

    def _should_step_into_function(self, func_name: str) -> bool:
        """Decide whether to step into a user-defined function."""
        # Skip common system functions but step into user code
        skip_functions = {
            '__stack_chk_fail', '_init', '_fini', '__libc_start_main',
            '__do_global_dtors_aux', 'deregister_tm_clones', 'register_tm_clones'
        }
        return func_name not in skip_functions

    def _handle_external_call(self, func_name: str):
        """Handle external function calls with simulated side effects."""
        if func_name in self.external_handlers:
            self.external_handlers[func_name]()
        else:
            # Default handling for common functions
            default_handlers = {
                'printf': lambda: self.r2.cmd("aer rax=10"),
                'scanf': lambda: self.r2.cmd("aer rax=1"),
                'malloc': lambda: self.r2.cmd("aer rax=0x20000"),
                'strlen': lambda: self.r2.cmd("aer rax=8"),
                'strcmp': lambda: self.r2.cmd("aer rax=0"),
                'memcpy': lambda: self.r2.cmd("aer rax=" + self.r2.cmd("aer rdi").strip().split()[-1]),
                'free': lambda: None,  # No side effects for free
            }

            if func_name in default_handlers:
                default_handlers[func_name]()
                self.logger.debug(f"Simulated {func_name}")
            else:
                # Unknown function - set generic return value
                self.r2.cmd("aer rax=0")
                self.logger.warning(f"Unknown external function: {func_name}")

    def _get_register_snapshot(self) -> Dict[str, int]:
        """Get current register state as dictionary."""
        try:
            reg_output = self.r2.cmd("aer").strip()
            registers = {}

            for line in reg_output.split('\n'):
                if '=' in line:
                    parts = line.split('=', 1)
                    if len(parts) == 2:
                        reg_name = parts[0].strip()
                        reg_value = parts[1].strip()
                        try:
                            registers[reg_name] = int(reg_value, 16)
                        except ValueError:
                            registers[reg_name] = 0

            return registers
        except Exception as e:
            self.logger.error(f"Failed to get register snapshot: {e}")
            return {}

    def _get_memory_snapshot(self) -> Dict[int, bytes]:
        """Get relevant memory regions with intelligent tracking."""
        memory = {}
        try:
            # Get current register values for pointer tracking
            registers = self._get_register_snapshot()

            # Track stack region (256 bytes around ESP)
            esp = registers.get('esp', registers.get('rsp', 0))
            if esp:
                try:
                    stack_hex = self.r2.cmd(f"px 256 @ {esp-128}")
                    memory.update(self._parse_hex_dump(stack_hex, esp-128))
                except:
                    pass

            # Track memory pointed to by registers
            pointer_regs = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9',  # x64
                          'edi', 'esi', 'eax', 'ebx', 'ecx', 'edx']   # x86

            for reg in pointer_regs:
                if reg in registers and registers[reg] > 0x1000:  # Likely valid pointer
                    try:
                        ptr_addr = registers[reg]
                        ptr_hex = self.r2.cmd(f"px 64 @ {ptr_addr}")
                        memory.update(self._parse_hex_dump(ptr_hex, ptr_addr))
                    except:
                        pass

        except Exception as e:
            self.logger.debug(f"Memory snapshot error: {e}")

        return memory

    def _parse_hex_dump(self, hex_output: str, base_addr: int) -> Dict[int, bytes]:
        """Parse radare2 hex dump output into address->bytes mapping."""
        memory = {}
        try:
            for line in hex_output.split('\n'):
                if line.startswith('0x') and ' ' in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        addr = int(parts[0], 16)
                        hex_bytes = ' '.join(parts[1:9])  # First 8 hex pairs
                        try:
                            data = bytes.fromhex(hex_bytes.replace(' ', ''))
                            memory[addr] = data
                        except ValueError:
                            pass
        except Exception:
            pass
        return memory

    def _get_memory_changes(self) -> Dict[int, bytes]:
        """Get memory changes since last snapshot."""
        # Simplified implementation - compare with baseline
        current_memory = self._get_memory_snapshot()
        changes = {}

        # Compare with baseline and identify changes
        for addr, data in current_memory.items():
            if addr not in self.memory_snapshot_base or self.memory_snapshot_base[addr] != data:
                changes[addr] = data

        return changes

    def emulate_algorithm(self, func_name: str,
                         inputs: Dict[str, Union[int, bytes, str]] = None,
                         trace_memory: bool = True) -> Dict[str, Any]:
        """
        Simplified interface specifically for algorithm analysis.

        Args:
            func_name: Function name (e.g., "sym.encrypt_data")
            inputs: Input data with automatic parameter mapping
                   {"input_data": b"test", "key": b"secret", "length": 16}
            trace_memory: Whether to trace memory changes at each step

        Returns:
            Analysis results with algorithm-specific insights
        """
        # Auto-map inputs to calling convention
        register_inputs, memory_inputs = self._map_algorithm_inputs(inputs or {})

        result = self.emulate_region(
            start_addr=func_name,
            register_inputs=register_inputs,
            memory_inputs=memory_inputs,
            skip_external=True
        )

        # Add algorithm-specific analysis
        result['algorithm_analysis'] = self._analyze_algorithm_behavior(result)

        return result

    def _map_algorithm_inputs(self, inputs: Dict[str, Union[int, bytes, str]]) -> Tuple[Dict, Dict]:
        """Map user-friendly inputs to registers and memory according to calling convention."""
        register_inputs = {}
        memory_inputs = {}
        current_mem_addr = 0x10000

        # x86-64 calling convention: rdi, rsi, rdx, rcx, r8, r9
        # x86-32 calling convention: stack-based
        calling_regs = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']
        reg_index = 0

        # Get architecture info
        arch_info = self.r2.cmdj("ij")
        is_64bit = arch_info and arch_info.get("bin", {}).get("bits", 32) == 64

        for key, value in inputs.items():
            if isinstance(value, (bytes, str)):
                # Store in memory and pass pointer
                if isinstance(value, str):
                    value = value.encode() + b'\x00'  # Null-terminate strings

                memory_inputs[current_mem_addr] = value

                if is_64bit and reg_index < len(calling_regs):
                    register_inputs[calling_regs[reg_index]] = current_mem_addr
                else:
                    # Fall back to stack or simplified approach
                    register_inputs[f'arg{reg_index}'] = current_mem_addr

                current_mem_addr += len(value) + 16  # Add padding
                reg_index += 1

            elif isinstance(value, int):
                # Pass directly in register
                if is_64bit and reg_index < len(calling_regs):
                    register_inputs[calling_regs[reg_index]] = value
                else:
                    register_inputs[f'arg{reg_index}'] = value
                reg_index += 1

        return register_inputs, memory_inputs

    def _analyze_algorithm_behavior(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze algorithm-specific behavior patterns."""
        analysis = {
            'crypto_indicators': [],
            'loop_patterns': [],
            'data_transformations': [],
            'suspicious_operations': []
        }

        if 'execution_trace' not in result:
            return analysis

        trace = result['execution_trace']

        # Detect crypto-like operations
        crypto_patterns = ['xor', 'rol', 'ror', 'shl', 'shr', 'and', 'or']
        for snapshot in trace:
            instr_lower = snapshot.instruction.lower()
            for pattern in crypto_patterns:
                if pattern in instr_lower:
                    analysis['crypto_indicators'].append({
                        'step': snapshot.step_number,
                        'operation': pattern,
                        'instruction': snapshot.instruction
                    })

        # Detect loop patterns
        pc_visits = {}
        for snapshot in trace:
            pc = snapshot.pc
            if pc in pc_visits:
                pc_visits[pc] += 1
            else:
                pc_visits[pc] = 1

        loops = [(pc, count) for pc, count in pc_visits.items() if count > 1]
        analysis['loop_patterns'] = loops

        # Detect data transformations
        prev_memory = {}
        for snapshot in trace:
            for addr, data in snapshot.memory_changes.items():
                if addr in prev_memory and prev_memory[addr] != data:
                    analysis['data_transformations'].append({
                        'step': snapshot.step_number,
                        'address': addr,
                        'before': prev_memory[addr],
                        'after': data
                    })
            prev_memory.update(snapshot.memory_changes)

        return analysis

    def set_logging_level(self, level):
        """Set logging level for debugging."""
        self.logger.setLevel(level)


# Advanced usage examples
if __name__ == "__main__":
    import r2pipe
    import logging

    # Setup logging
    logging.basicConfig(level=logging.INFO)

    r2 = r2pipe.open("./binary")
    emulator = ESILEmulator(r2)

    print("=== Example 1: Code Block Analysis ===")
    # Analyze specific code block after user input
    result1 = emulator.emulate_region(
        start_addr=0x08048460,  # After scanf
        end_addr=0x080484A0,    # Before output
        register_inputs={"eax": 0x1234},
        stack_inputs={-0x10: b"password123\x00"},
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