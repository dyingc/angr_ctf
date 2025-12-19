import angr
import claripy
import sys
from angr.sim_state import SimState
from angr.sim_procedure import SimProcedure
from angr.storage.file import SimPackets, SimFileStream
from angr.project import Project
from claripy.ast.bv import BV
from typing import List, Any

# Hook __isoc99_scanf using SimProcedure
class MyScanf(SimProcedure):
    def run(self, fmt_ptr: int, key_ptr: int, buf_ptr: int) -> int:
        # Create two symbolic variables for the inputs
        input1 = claripy.BVS("input1", 32) # 4 bytes for an unsigned int
        buf_len = 21 # the fmt string is "%u %20s", so max length of string is 20 + null terminator
        input2 = claripy.BVS("input2", buf_len * 8) # buf_len bytes for the string
        # Constraints to ensure input2 is a valid string
        last_char = input2.get_byte(buf_len - 1)
        self.state.solver.add(last_char == 0) # null terminator
        for i in range(buf_len - 1):
            char = input2.get_byte(i)
            self.state.solver.add(char >= 0x41) # 'A'
            self.state.solver.add(char <= 0x7a) # 'z'
        # input2 = claripy.BVV(b"aaaabbbbccccdddd1234")  # fixed input string for simplicity
        # Store the symbolic variables into the provided memory locations
        self.state.memory.store(key_ptr, input1, endness=self.state.arch.memory_endness)
        self.state.memory.store(buf_ptr, input2) # the string is byte-addressable

        # Store the symbolic inputs globally for later retrieval
        self.state.globals['input1'] = input1
        self.state.globals['input2'] = input2

        return 2 # number of inputs read

def hook_test(state: SimState)->None:
    pass

def install_hooks(project: Project) -> None:
    project.hook_symbol("__isoc99_scanf", MyScanf())
    project.hook(0x0804853d, hook_test)  # Hook the address where segfault occurs
    project.hook(0x08048540, hook_test)  # Hook the next instruction as well

def main(argv: List[str]) -> None:
    # Create an angr project with the specified binary
    binary_path = argv[1] if len(argv) > 1 else "./binary/x32/xx_angr_segfault"

    project = angr.Project(binary_path, auto_load_libs=False)

    install_hooks(project)

    # Create the initial state with symbolic stdin
    initial_state = project.factory.full_init_state(
        args=[binary_path],
        add_options={
            angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
            angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
        },
    )

    # Create a simulation manager
    simgr = project.factory.simulation_manager(initial_state)

    simgr.stashes["found"] = []
    i = 0

    def _mv_to_found_if_err(simgr: angr.sim_manager.SimulationManager) -> None:
        # Iterate all states in all stashes except 'found'
        for stash_name, stash in simgr.stashes.items():
            if stash_name == "found":
                continue
            for state in stash:
                stderr_output = state.posix.dumps(sys.stderr.fileno())
                stdout_output = state.posix.dumps(sys.stdout.fileno())
                if len(stderr_output) > 0 or b'Segmentation fault' in stdout_output:
                    # Move this state to the 'found' stash
                    simgr.move(stash_name, "found", filter_func=lambda st: st == state)

    while (simgr.active or simgr.unconstrained):
        print(f"Step {i}:")
        i += 1

        # Treat every state that writes to stderr as a found state
        _mv_to_found_if_err(simgr)

        for a_state in list(simgr.active):
            if a_state.addr in [0x08048529, 0x0804853d]:
                # avoid
                simgr.move('active', 'deadended', filter_func=lambda st: st == a_state)
            if a_state.addr in [0x08048534, 0x08048546]: #
                # find
                # simgr.copy('active', 'found', filter_func=lambda st: st == a_state)
                simgr.stashes['found'].append(a_state)
                pass

        for u_state in simgr.unconstrained:
            if u_state.solver.symbolic(u_state.regs.eip):
                pass

        if len(simgr.stashes["found"]) > 1:
            break

        simgr.step()

    if simgr.stashes["found"]:
        found_state = simgr.stashes["found"][0]
        flag1 = found_state.solver.eval(found_state.globals['input1'], cast_to=int)
        flag2 = found_state.solver.eval(found_state.globals['input2'], cast_to=bytes)
        print(f"Flag1: {flag1:d}")
        print(f"Flag2: {flag2}")
    else:
        print("No solution found.")

if __name__ == "__main__":
    main(sys.argv)