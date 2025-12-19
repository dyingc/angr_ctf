# This code uses the unconstrained state to solve the arbitrary jump challenge
import angr
import claripy
import sys
from angr.sim_state import SimState
from angr.sim_procedure import SimProcedure
from angr.storage.file import SimPackets, SimFileStream
from angr.project import Project
from claripy.ast.bv import BV
from typing import List, Any

def main(binary_path: str):
    # Load the binary into an angr project
    project = angr.Project(binary_path, auto_load_libs=False)

    # Create symbolic variable for input
    input_size = 50 # In fact the least bytes is: 25 + 4 + 4 and the highest working number (after testing) is 60
    input_buffer = claripy.BVS('input', input_size * 8)
    # Create a symbolic packet stream for stdin
    input_packets = SimPackets(name='input_packets', write_mode=False, content=[(input_buffer, input_size)])

    # Create an unconstrained state at the entry point
    state = project.factory.entry_state(
        stdin=input_packets,
        add_options={
            angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
            angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
        }
    )

    # To simplify the process, constraint the input_buffer to visible ASCII characters
    for byte in input_buffer.chop(bits=8):
        state.add_constraints(
            byte >= 0x20,
            byte <= 0x7e
        )

    # Create a simulation manager with the initial state
    simgr = project.factory.simulation_manager(state)
    simgr.stashes['found'] = []

    # Get the print_good function address
    print_good_sym = project.loader.find_symbol('print_good')
    if print_good_sym is None:
        print("Could not find print_good symbol.")
        return
    print_good_addr = print_good_sym.rebased_addr

    # Explore the binary manually
    while (simgr.active or simgr.unconstrained) and not simgr.found: # 找到第一个可用解就退出
        if simgr.unconstrained:
            for s in list(simgr.unconstrained):  # 复制列表避免迭代冲突
                s.add_constraints(s.regs.eip == print_good_addr)
                if s.solver.satisfiable():
                    simgr.move(from_stash='unconstrained', to_stash='found',
                            filter_func=lambda st: st == s)
                else:
                    simgr.move(from_stash='unconstrained', to_stash='not_needed',
                            filter_func=lambda st: st == s)
        simgr.step()

    if simgr.found:
        found_state = simgr.found[0]
        # Retrieve the value of 'flag' from the found state
        flag_addr = found_state.solver.eval(input_buffer, cast_to=bytes)
        print("Flag:", flag_addr)
    else:
        print("No solution found.")

if __name__ == "__main__":
    binary_path = sys.argv[1] if len(sys.argv) > 1 else "./binary/x32/17_angr_arbitrary_jump"
    main(binary_path)