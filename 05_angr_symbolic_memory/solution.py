import angr
import claripy

from angr.storage.file import SimFile

def main():
    # Create a blank Angr project with a simple binary
    project = angr.Project('./binary/x32/05_angr_symbolic_memory', auto_load_libs=False)

    # Create symbolic variables for input
    input_size = 8
    sym_input0 = claripy.BVS('sym_input0', 8 * input_size)
    sym_input1 = claripy.BVS('sym_input1', 8 * input_size)
    sym_input2 = claripy.BVS('sym_input2', 8 * input_size)
    sym_input3 = claripy.BVS('sym_input3', 8 * input_size)
    symbolic_input = claripy.Concat(
        sym_input0,
        sym_input1,
        sym_input2,
        sym_input3
    )

    # Search "userinput" symbol in the binary to find where the input is read
    userinput_addr = project.loader.find_symbol('user_input').rebased_addr

    # Create an initial state
    start_addr = 0x804928c
    init_state: angr.sim_state.SimState  = project.factory.blank_state(
        addr = start_addr,
        add_options = {angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                       angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
    )

    # Set the value, starting from the userinput address, to the symbolic variables, totally 4 * input_size bytes
    init_state.memory.store(userinput_addr, symbolic_input, size=4 * input_size, endness=project.arch.memory_endness)

    # Create a simulation manager to explore the binary
    simgr = project.factory.simulation_manager(init_state)

    # Explore the binary until we find a state that reaches the desired address
    win_address = 0x80492f5   # Replace with the actual target address
    avoid_address = 0x80492e3   # Replace with the actual avoid address
    simgr.explore(find=win_address, avoid=avoid_address)

    if simgr.found:
        found_state = simgr.found[0]
        solution = found_state.solver.eval(symbolic_input, cast_to=bytes)
        print(f'Solution found: {solution}')
    else:
        print('No solution found.')

if __name__ == '__main__':
    main()