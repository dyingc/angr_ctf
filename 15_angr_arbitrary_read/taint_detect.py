import angr
import claripy
from angr.sim_state import SimState
from angr.sim_procedure import SimProcedure
from angr.project import Project
from typing import List
from angr.analyses.cfg.cfg_fast import CFGFast

cfg: CFGFast = None

# hooking for scanf
class Scanf(SimProcedure):

    def __init__(self, project: Project):
        super().__init__()
        self.project = project

    def run(self, fmt: str, input1_ptr: claripy.BVV, input2_ptr: claripy.BVV):
        # The fmt is "%u %20s"
        # The first input should be an unsigned integer
        input1 = self.state.solver.BVS("input1", 32)
        self.state.memory.store(input1_ptr, input1, endness=self.arch.memory_endness)

        # The second input should be a string of max length 20
        input2 = self.state.solver.BVS("input2", 20 * 8)
        self.state.memory.store(input2_ptr, input2)

        # Store the two inputs into globals for later retrieval
        self.state.globals['input1'] = input1
        self.state.globals['input2'] = input2

        return 2 # two inputs read

# hooking for puts - detect taint here
class Puts(SimProcedure):

    def run(self, s: claripy.BVV):
        # Check if the string being printed is tainted
        if self.state.solver.symbolic(s):
            # taint detected, we need to store the state
            ret_addr = self.state.regs.esp  # return address is at esp when the function is just called (entered)
            ret_addr_value = self.state.memory.load(ret_addr, 4, endness=self.arch.memory_endness).concrete_value
            self.state.globals['taint_ret_addr'] = ret_addr_value
        return 0 # we didn't really output anything

def install_hooks(project: Project):
    project.hook_symbol("__isoc99_scanf", Scanf(project))
    project.hook_symbol("puts", Puts())

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

def main(argv: List[str]):
    # Load the binary
    binary = argv[1] if len(argv) > 1 else "./binary/x32/15_angr_arbitrary_read"
    project = angr.Project(binary, auto_load_libs=False)

    # Prepare the CFGFast analysis globally
    global cfg
    cfg = project.analyses.CFGFast()

    # Install hooks
    install_hooks(project)

    # Create initial state
    initial_state = project.factory.entry_state(
        args=[binary],
        add_options={
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
        }
    )

    # Define the SUC condition
    def is_successful(state: SimState) -> bool:
        if state.globals.get('taint_ret_addr') is not None:
            return True
        return False

    # Create simulation manager
    simgr = project.factory.simulation_manager(initial_state)
    simgr.explore(find=is_successful)

    if simgr.found:
        found_state = simgr.found[0]
        print("Taint detection successful!")

        # Get the two intpus that cause the taint
        input1 = found_state.solver.eval(found_state.globals['input1'], cast_to=int)
        input2 = found_state.solver.eval(found_state.globals['input2'], cast_to=bytes)
        taint_ret_addr = found_state.solver.eval(found_state.globals['taint_ret_addr'], cast_to=int)
        # Let's get the address of the instruction right before the taint_ret_addr - the calling instruction address
        calling_addr = get_prev_instruction_addr(project, taint_ret_addr)
        # Output the calling address that caused the taint
        print(f"\"puts\" is called with taint data from instruction at: 0x{calling_addr:08x}")

        print(f"Input 1 (unsigned int): 0x{input1:08x}")
        print(f"Input 2 (string): {input2.decode('utf-8', errors='ignore')}")
    else:
        print("Taint detection failed.")


if __name__ == "__main__":
    import sys
    main(sys.argv)