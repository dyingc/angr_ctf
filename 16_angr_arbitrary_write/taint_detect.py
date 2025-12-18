import angr
import claripy
from angr.sim_state import SimState
from angr.sim_procedure import SimProcedure
from angr.project import Project
from typing import List

def get_prev_instruction_addr(project: Project, addr: int, debug: bool = False) -> int:
    """
    通过反向扫描找到前一条有效指令

    原理:
    1. 从 addr-1 开始往前扫描(最多15字节)
    2. 对每个候选地址,检查它是否是有效的指令起始地址
    3. 找到的第一个有效地址就是答案!
    """
    cfg = project.analyses.CFGFast()

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

# Hook strncpy as a "monitored" function to track if the 1st paramter, the dest buffer, is controlled by us - polluted.
# This is a pure monitoring hook - the hooking length is 0, so the original function will be executed.
# Here we need to control both:
# What to copy - the content of the source buffer
# Where to copy - the destination buffer (the pointer)

def _is_controlled(s: SimState, var: claripy.ast.bv.BV) -> bool:
    if s.solver.symbolic(var):
        sym_name = list(var.variables)[0]
        if 'input1' in sym_name or 'input2' in sym_name:
            return True # controlled by us
    return False

def hook_strncpy(proj: angr.Project):
    def _hook_strncpy(s: SimState):
        # Get the dest buffer
        dest_buf_stack_loc = s.regs.esp + 4 # The dest buffer is the first argument which is stored at: esp + 4
        # Load the actual dest buffer
        dest_buf = s.memory.load(dest_buf_stack_loc, 4, endness = s.arch.memory_endness)

        # Get the contents of the source buffer
        src_buf_stack_loc = s.regs.esp + 8 # The source buffer is the second argument which is stored at: esp + 8
        src_buf = s.memory.load(src_buf_stack_loc, 4, endness = s.arch.memory_endness) # the source buffer (pointer)
        src_buf_contents = s.memory.load(src_buf, 8) # Load 8 bytes from the source buffer as we need to constraint it later

        # Check if the dest buffer (a pointer) is symbolic (controlled by us)
        if _is_controlled(s, dest_buf) and _is_controlled(s, src_buf_contents):
            ret_addr_ptr = s.regs.esp
            ret_addr = s.memory.load(ret_addr_ptr, 4, endness=s.arch.memory_endness).concrete_value
            print(f"    strncpy called, return address: {hex(ret_addr)}")
            print("[*] strncpy called with a symbolic source buffer!")
            # Get the return address from the stack (esp)
            print(f"    Return address: {hex(ret_addr)}")
            # Store the return address in globals for later retrieval
            s.globals['strncpy_ret_addr'] = ret_addr
            # Add a constraint to set the dest buffer to the password_buffer
            password_buffer_sym = proj.loader.find_symbol('password_buffer')
            if password_buffer_sym is None:
                raise Exception("password_buffer symbol not found in the binary.")
            password_buffer_addr = password_buffer_sym.rebased_addr
            s.add_constraints(dest_buf == password_buffer_addr)
            # Also constrain the source buffer content to be the correct password
            s.add_constraints(src_buf_contents == b'IDGNGCXX')
            if s.solver.satisfiable():
                key = s.solver.eval(s.globals['input1'], cast_to=int)
                print(f"    [*] Found a satisfiable condition: {key}")
                user_input_2 = s.solver.eval(s.globals['input2'], cast_to=bytes)
                print(f"    [*] Found a satisfiable condition: input2 {user_input_2}")
                print(f"    [*] Found a satisfiable condition: {key} {user_input_2.decode()}")
            else:
                print("    [-] No satisfiable condition found!")

    return _hook_strncpy

# Hook strncmp as a "monitored" function to track if the 1st paramter, is controlled by us (from the PCode, the 2nd one is a literal string).
# This is a pure monitoring hook - the hooking length is 0, so the original function will be executed.
def hook_strncmp(s: SimState):
    # Get the content of the source buffer (1st argument) which is at: esp + 4
    src_buf_loc = s.regs.esp + 4
    # Get the length of the source buffer (3rd argument) which is at: esp + 0xc
    length_ptr = s.regs.esp + 0xc
    length_val = s.memory.load(length_ptr, 4, endness=s.arch.memory_endness)
    # Load the source buffer (a pointer)
    src_buf = s.memory.load(src_buf_loc, 4, endness = s.arch.memory_endness)
    # Load the source buffer content
    src_buf_contents = s.memory.load(src_buf, length_val)
    # Check if the source buffer or the source buffer content is controlled by us
    if _is_controlled(s, src_buf) or _is_controlled(s, src_buf_contents):
        # Now we know the source buffer is controlled by us
        ret_addr = s.memory.load(s.regs.esp, 4, endness=s.arch.memory_endness).concrete_value
        print(f"    strncmp called, return address: {hex(ret_addr)}")
        print("[*] strncmp called with a symbolic source buffer!")
        # Get the return address from the stack (esp)
        ret_addr_ptr = s.regs.esp
        ret_addr = s.memory.load(ret_addr_ptr, 4, endness=s.arch.memory_endness).concrete_value
        print(f"    Return address: {hex(ret_addr)}")
        # Store the return address in globals for later retrieval
        s.globals['strncmp_ret_addr'] = ret_addr
        s.solver.add(src_buf_contents == b'IDGNGCXX')
        s.globals['key'] = src_buf_contents
        if s.solver.satisfiable():
            key = s.solver.eval(s.globals['input1'], cast_to=int)
            print(f"    [*] Found a satisfiable condition: {key}")
            user_input_2 = s.solver.eval(s.globals['input2'], cast_to=bytes)
            print(f"    [*] Found a satisfiable condition: input2 {user_input_2}")
            print(f"    [*] Found a satisfiable condition: {key} {user_input_2.decode()}")
        else:
            print("    [-] No satisfiable condition found!")
        pass
    else:
        src_buf_8_str = src_buf.concrete_value.to_bytes(length_val.concrete_value)
        print(f"    strncmp called with a concrete source buffer: {src_buf_8_str}")

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
        # strncpy_addr = strncpy_sym.rebased_addr # This doesn't work (probably GOT rather than PLT, the needed one) - need to use the radare2 found address
        strncpy_addr = 0x08049070 # I've got this from radare2 but why this value is different with strncpy_sym.rebased_addr (which is 0x47500010)?
        project.hook(strncpy_addr, hook_strncpy(project), length=0)
    else:
        raise Exception("strncpy symbol not found in the binary.")

    strncmp_addr = 0x08049090 # Again, I've got this from radare2
    project.hook(strncmp_addr, hook_strncmp, length=0)

    # Hook scanf
    project.hook_symbol("__isoc99_scanf", Scanf(project))

    # # Hook testing
    # testing_addrs = [0x0804920e, 0x0804920e, 0x08049279, 0x08049291]
    # for addr in testing_addrs:
    #     project.hook(addr, hook_testing, length=0)

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
    simgr.explore(find=is_successful)
    # simgr.explore(find=0x080492ae)

    if simgr.found:
        s = simgr.found[0]
        print("[*] Found a successful state!")
        key = s.solver.eval(s.globals['input1'], cast_to=int)
        print(f"[*] Input causing the success: {key}")
        pwd = s.solver.eval(s.globals['input2'], cast_to=bytes)
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