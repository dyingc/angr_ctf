# This one is only to check if any address can be tainted. It won't try to exploit now
import angr
import claripy
import sys
from angr.sim_state import SimState
from angr.sim_procedure import SimProcedure
from angr.project import Project
from claripy.ast.bv import BV
from typing import List, Any
from angr.block import CapstoneInsn
from angr.analyses.cfg.cfg_fast import CFGFast

cfg: CFGFast = None

def get_prev_instruction_addr(project: Project, addr: int, debug: bool = False) -> int:
    """
    通过反向扫描找到前一条有效指令

    原理:
    1. 从 addr-1 开始往前扫描(最多15字节)
    2. 对每个候选地址,检查它是否是有效的指令起始地址
    3. 找到的第一个有效地址就是答案!
    """
    global cfg # 使用全局 cfg，这不仅是为了性能，也是为了确保一致性，尤其是如果本函数被 hook function 调用时，CFGFast 会将 hook 地址识别为基本块的边界，从而彻底打乱执行流程

    if debug:
        print(f"查找 0x{addr:x} 的前一条指令:")

    for offset in range(1, 16):
        candidate_addr = addr - offset

        node = cfg.model.get_any_node(candidate_addr, anyaddr=True)
        if not node:
            if debug:
                print(f"  0x{candidate_addr:x}: 没有节点")
            continue

        try:
            block = project.factory.block(node.addr)
            insn_addrs = block.instruction_addrs

            if candidate_addr in insn_addrs:
                if debug:
                    print(f"  0x{candidate_addr:x}: ✓ 找到!")
                return candidate_addr
            else:
                if debug:
                    print(f"  0x{candidate_addr:x}: 无效(不在指令列表中)")

        except Exception as e:
            if debug:
                print(f"  0x{candidate_addr:x}: 异常 - {e}")
            continue

    raise Exception(f"在前 15 字节内找不到地址 0x{addr:x} 的前一条指令")

def get_prev_instruction(project: Project, addr: int, debug: bool = False) -> CapstoneInsn:
    """
    通过反向扫描找到前一条有效指令
    """
    global cfg # 使用全局 cfg，这不仅是为了性能，也是为了确保一致性，尤其是如果本函数被 hook function 调用时，CFGFast 会将 hook 地址识别为基本块的边界，从而彻底打乱执行流程

    if debug:
        print(f"查找 0x{addr:x} 的前一条指令:")

    for offset in range(1, 16):
        candidate_addr = addr - offset

        node = cfg.model.get_any_node(candidate_addr, anyaddr=True)
        if not node:
            if debug:
                print(f"  0x{candidate_addr:x}: 没有节点")
            continue

        try:
            block = project.factory.block(node.addr)

            # 找到候选地址对应的指令
            for insn in block.capstone.insns:
                if insn.address == candidate_addr:
                    if debug:
                        print(f"  0x{candidate_addr:x}: ✓ 找到!")
                    return insn

            if debug:
                print(f"  0x{candidate_addr:x}: 无效(不在指令列表中)")

        except Exception as e:
            if debug:
                print(f"  0x{candidate_addr:x}: 异常 - {e}")
            continue

    raise Exception(f"在前 15 字节内找不到地址 0x{addr:x} 的前一条指令")

def get_next_instruction(project: Project, addr: int, debug: bool = False) -> CapstoneInsn:
    """
    获取下一条指令(假设指令连续)
    """
    block = project.factory.block(addr)

    # 找到包含 addr 的指令
    for i, insn in enumerate(block.capstone.insns):
        if insn.address <= addr < insn.address + insn.size:
            if debug:
                print(f"当前指令: 0x{insn.address:x}, 长度: {insn.size}")

            # 返回下一条指令
            if i + 1 < len(block.capstone.insns):
                next_insn = block.capstone.insns[i + 1]
                if debug:
                    print(f"下一条指令: 0x{next_insn.address:x}")
                return next_insn
            else:
                raise Exception(f"地址 0x{addr:x} 已是块中最后一条指令")

    raise Exception(f"无法找到地址 0x{addr:x} 所在的指令")

def is_controlled(state: SimState, addr: BV) -> bool:
    if not state.solver.symbolic(addr):
        return False
    # Get the name of the symbolic variable
    sym_name = list(addr.variables)[0]
    # Check if the symbolic variable name indicates user control
    if 'user_input' in sym_name:
        return True
    return False

def hook_read_input_ret(proj: Project):
    def _hook_read_input_ret(state: SimState):
        # We'll check if the return value is controlled. Monitoring only
        ret_addr = state.memory.load(state.regs.esp, 4, endness=proj.arch.memory_endness)
        if is_controlled(state, ret_addr):
            print(f"[!] Detected tainted return address from read_input at 0x{state.addr:x}!")
            print(f"    Caller address: 0x{state.globals['caller_addr']:x}")
            _dump_stack_and_registers(state, num_qwords=2)

    return _hook_read_input_ret

def hook_read_input_begin(proj: Project):
    def _hook_read_input_begin(state: SimState):
        # This is used to store the caller's address for later use
        ret_addr = state.memory.load(state.regs.esp, 4, endness=proj.arch.memory_endness)
        state.globals['caller_ret_addr'] = ret_addr
        caller_addr = get_prev_instruction_addr(proj, ret_addr.concrete_value)
        state.globals['caller_addr'] = caller_addr
        print(f"[+] read_input called from 0x{caller_addr:x}")

    return _hook_read_input_begin

# Hook symbol __isoc99_scanf to our custom hook
class ScanfHook(SimProcedure):
    def run(self, fmt_ptr, buf_ptr):
        # Return addr
        ret_addr = self.state.memory.load(self.state.regs.esp, 4, endness=self.project.arch.memory_endness)
        caller_addr = get_prev_instruction_addr(self.project, ret_addr.concrete_value)
        # Create a symbolic variable for the input
        size = 30 # assuming we read up to 30 bytes - the buf size should be 25, plus 4 bytes for the ebp. Overflow happens to the ret addr if we read more than that
        sym_var = claripy.BVS("user_input", 8 * size)
        # Store it in the buffer
        self.state.memory.store(buf_ptr, sym_var)
        # Store the user_input variable into globals for tracking
        self.state.globals['tainted_input'] = sym_var # We won't use it in this example as we don't exploit
        print(f"[+] __isoc99_scanf called from 0x{caller_addr:x}")
        return 1 # number of items successfully read

def install_hooks(proj: Project):
    read_input_sym = proj.loader.find_symbol('read_input')
    read_input_addr = read_input_sym.rebased_addr
    proj.hook(read_input_addr, hook_read_input_begin(proj), length=0)
    proj.hook(read_input_addr + 0x1c, hook_read_input_ret(proj), length=0)
    proj.hook_symbol('__isoc99_scanf', ScanfHook())

# Some helper functions
def _output(state: SimState, obj: Any):
    if isinstance(obj, BV):
        if obj.symbolic:
            if is_controlled(state, obj):
                return f"TAINTED symbolic expression: {obj}"
            else:
                return f"symbolic expression: {obj}"
        else:
            return f"concrete value: {obj.concrete_value:#x}"
    return str(obj)

def _dump_stack_and_registers(state: SimState, num_qwords: int = 4):
    # Get the stack layout - 4 qwords from the top of the stack
    qwords = [state.memory.load(state.regs.esp + i * 4, 4, endness=state.arch.memory_endness) for i in range(num_qwords)]
    print("  Stack:")
    for i, qw in enumerate(qwords):
        # Output the qwords
        print(f"    [esp + {i*4:#x}]: {_output(state, qw)}")
    # Output the major common registers - no need to check if tainted
    print("  Registers:")
    for reg_name in ['ebp', 'esp', 'eip']:
        reg_val = getattr(state.regs, reg_name)
        print(f"    {reg_name}: {_output(state, reg_val)}")

def main(argv: List[str]):
    global cfg
    binary_path = argv[1] if len(argv) > 1 else "./binary/x32/17_angr_arbitrary_jump"
    proj = angr.Project(binary_path, auto_load_libs=False)

    cfg = proj.analyses.CFGFast()

    initial_state = proj.factory.entry_state(
        add_options={
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
        })

    install_hooks(proj)

    simgr = proj.factory.simulation_manager(initial_state)
    addr = 0x485043c9 # ready to call read_input
    addr = 0x48504384 # entered read_input
    addr = 0x48504396 # ready to call __isoc99_scanf in the read_input
    addr = 0x4850439b # right after calling __isoc99_scanf
    addr = 0x485043ea # end of the main - unreachable if taint more than 25 bytes
    simgr.explore(find=addr)

    if simgr.found:
        print("[+] 找到可达状态!")
        s = simgr.found[0]

    else:
        print("[-] 未找到可达状态.")

if __name__ == "__main__":
    main(sys.argv)
