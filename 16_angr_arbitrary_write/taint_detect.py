import angr
import claripy
from angr.sim_state import SimState
from angr.sim_procedure import SimProcedure
from angr.project import Project
from typing import List

def get_prev_instruction_addr(project: Project, addr: int) -> int:
    cfg = project.analyses.CFGFast()

    # 找到包含目标地址的 CFG 节点
    node = cfg.model.get_any_node(addr, anyaddr=True)

    if node:
        block = project.factory.block(node.addr)
        insn_addrs = block.instruction_addrs

        if addr == node.addr:  # 如果是基本块的第一条指令
            # 需要找前驱基本块的最后一条指令
            predecessors = cfg.graph.predecessors(node)
            for pred in predecessors:
                pred_block = project.factory.block(pred.addr)
                prev_insn_addr = pred_block.instruction_addrs[-1]
                return prev_insn_addr
            raise Exception("没有前驱基本块，无法找到前一条指令地址")
    else:
        # 在同一基本块内处理
        idx = insn_addrs.index(addr)
        prev_insn_addr = insn_addrs[idx - 1]
        return prev_insn_addr

# Hook strncpy as a "monitored" function to track if the 1st paramter, the dest buffer, is controlled by us - polluted.
# This is a pure monitoring hook - the hooking length is 0, so the original function will be executed.
def hook_strncpy(s: SimState):
    # Get the dest buffer (1st argument) which is at: esp + 4
    dest_buf_ptr_stack_loc = s.regs.esp + 4
    # Get the length of the source buffer (2nd argument) which is at: esp + 0xc
    length_ptr = s.regs.esp + 0xc
    length_val = s.memory.load(length_ptr, 4, endness=s.arch.memory_endness)
    # Load the actual source buffer
    dest_buf_ptr = s.memory.load(dest_buf_ptr_stack_loc, 4, endness = s.arch.memory_endness)
    dest_buf = s.memory.load(dest_buf_ptr, length_val)
    # Check if the source buffer is symbolic (controlled by us)
    ret_addr = s.memory.load(s.regs.esp, 4, endness=s.arch.memory_endness).concrete_value
    print(f"    strncpy called, return address: {hex(ret_addr)}")
    if s.solver.symbolic(dest_buf):
        print("[*] strncpy called with a symbolic source buffer!")
        # Get the return address from the stack (esp)
        ret_addr_ptr = s.regs.esp
        ret_addr = s.memory.load(ret_addr_ptr, 4, endness=s.arch.memory_endness).concrete_value
        print(f"    Return address: {hex(ret_addr)}")
        # Store the return address in globals for later retrieval
        s.globals['strncpy_ret_addr'] = ret_addr

def hook_testing(s: SimState):
    print(f"Current instruction address: {hex(s.addr)}")
    # Get the value of the first stack data (esp)
    first_stack_data_ptr = s.regs.esp
    first_stack_data = s.memory.load(first_stack_data_ptr, 4, endness=s.arch.memory_endness)
    # Check if it's symbolic
    if s.solver.symbolic(first_stack_data):
        print("[*] The first stack data is symbolic!")
        # Add constraint that it should be equal to 0x47424e48
        s.add_constraints(first_stack_data == 0x47424e48)
        print("[*] Added constraint that first stack data == 0x47424e48")

# Hook strncmp as a "monitored" function to track if the 1st paramter, is controlled by us (from the PCode, the 2nd one is a literal string).
# This is a pure monitoring hook - the hooking length is 0, so the original function will be executed.
def hook_strncmp(s: SimState):
    # Get the source buffer (1st argument) which is at: esp + 4
    src_buf_ptr_loc = s.regs.esp + 4
    # Get the length of the source buffer (3rd argument) which is at: esp + 0xc
    length_ptr = s.regs.esp + 0xc
    length_val = s.memory.load(length_ptr, 4, endness=s.arch.memory_endness)
    # Load the actual source buffer
    src_buf_ptr = s.memory.load(src_buf_ptr_loc, 4, endness = s.arch.memory_endness)
    src_buf = s.memory.load(src_buf_ptr, length_val)
    # Check if the source buffer is symbolic (controlled by us)
    ret_addr = s.memory.load(s.regs.esp, 4, endness=s.arch.memory_endness).concrete_value
    print(f"    strncmp called, return address: {hex(ret_addr)}")
    if s.solver.symbolic(src_buf):
        print("[*] strncmp called with a symbolic source buffer!")
        # Get the return address from the stack (esp)
        ret_addr_ptr = s.regs.esp
        ret_addr = s.memory.load(ret_addr_ptr, 4, endness=s.arch.memory_endness).concrete_value
        print(f"    Return address: {hex(ret_addr)}")
        # Store the return address in globals for later retrieval
        s.globals['strncmp_ret_addr'] = ret_addr
        s.solver.add(src_buf == 'IDGNGCXX')
        s.globals['pwd'] = src_buf
        if s.solver.satisfiable():
            key = s.solver.eval(s.globals['input1'], cast_to=int)
            user_input_2 = s.solver.eval(s.globals['input2'], cast_to=bytes)
            print(f"    [*] Found a satisfiable condition: {key} {user_input_2.decode()}")
        else:
            print("    [-] No satisfiable condition found!")
        pass
    else:
        src_buf_8_str = src_buf.concrete_value.to_bytes(length_val.concrete_value)

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

        # Add constraint to ensure the input2 is visible ASCII characters
        for i in range(20):
            char = input2.get_byte(i)
            self.state.add_constraints(char >= 0x20)  # space
            self.state.add_constraints(char <= 0x7e)  # tilde
        # Store the second input into memory
        self.state.memory.store(input2_ptr, input2)

        # Store the two inputs into globals for later retrieval
        self.state.globals['input1'] = input1
        self.state.globals['input2'] = input2
        self.state.globals['full_input'] = claripy.Concat(input1, ' ', input2)

        return 2 # two inputs read

def install_hooks(project: angr.Project):
    # Get the address of strncpy
    strncpy_sym = project.loader.find_symbol('strncpy')
    # Hook strncpy if found
    if strncpy_sym is not None:
        strncpy_addr = 0x08049070 # I've got this from radare2 but why this value is different with strncpy_sym.rebased_addr (which is 0x47500010)?
        project.hook(strncpy_addr, hook_strncpy, length=0)
    else:
        raise Exception("strncpy symbol not found in the binary.")

    strncmp_addr = 0x08049090 # Again, I've got this from radare2
    project.hook(strncmp_addr, hook_strncmp, length=0)

    # Hook scanf
    project.hook_symbol("__isoc99_scanf", Scanf(project))

    # Hook testing
    testing_addrs = [0x0804920e, 0x0804920e, 0x08049279, 0x08049291]
    for addr in testing_addrs:
        project.hook(addr, hook_testing, length=0)

def main(argv: List[str]):
    # Load the binary
    binary_path = argv[1] if len(argv) > 1 else "./binary/x32/16_angr_arbitrary_write"

    # Create an angr project
    project = angr.Project(binary_path, auto_load_libs=False)

    # Install hooks
    install_hooks(project)

    # Create an initial state
    state = project.factory.entry_state(
        add_options={
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
        }
    )

    # SUC condition - till output "Good Job."
    # This might not be really found but we can get the taints using
    # all possible paths exploration
    def is_successful(state: SimState) -> bool:
        stdout_output = state.posix.dumps(1)
        return b"Good Job." in stdout_output

    simgr = project.factory.simulation_manager(state)
    # simgr.explore(find=is_successful)
    simgr.explore(find=0x080492ae)

    if simgr.found:
        s = simgr.found[0]
        print("[*] Found a successful state!")
        input = s.solver.eval(s.globals['full_input'], cast_to=bytes)
        print(f"[*] Input causing the success: {input}")
        pwd = s.solver.eval(s.globals['pwd'], cast_to=bytes)
        print(f"[*] Password used: {pwd}")

        # Check if we detected any taint during execution
        if 'strncpy_ret_addr' in s.globals:
            strncpy_ret_addr = s.globals['strncpy_ret_addr']
            prev_insn_addr = get_prev_instruction_addr(project, strncpy_ret_addr)
            print(f"[*] Tainted write detected! Return address: {hex(strncpy_ret_addr)}, Previous instruction address: {hex(prev_insn_addr)}")
        else:
            print("[-] No tainted writes detected.")
    else:
        # If no successful state found, we can analyze all paths for taints
        print("[-] No successful state found. Analyzing all paths for taints...")
        for deadended in simgr.deadended:
            if 'strncpy_ret_addr' in deadended.globals:
                strncpy_ret_addr = deadended.globals['strncpy_ret_addr']
                prev_insn_addr = get_prev_instruction_addr(project, strncpy_ret_addr)
                print(f"[*] Tainted write detected! Return address: {hex(strncpy_ret_addr)}, Previous instruction address: {hex(prev_insn_addr)}")
            if 'strncmp_ret_addr' in deadended.globals:
                strncmp_ret_addr = deadended.globals['strncmp_ret_addr']
                prev_insn_addr = get_prev_instruction_addr(project, strncmp_ret_addr)
                print(f"[*] Tainted write detected! Return address: {hex(strncmp_ret_addr)}, Previous instruction address: {hex(prev_insn_addr)}")

if __name__ == "__main__":
    import sys
    main(sys.argv)