import angr
import claripy

def main():
    # Load the binary
    project = angr.Project('./binary/x32/07_angr_symbolic_file', auto_load_libs=False)

    # Create a symbolic bitvector for the input
    input_size = 64  # Adjust size as needed
    symbolic_input = claripy.BVS('file_input', input_size * 8)

    # Create an initial state with the symbolic input
    start_addr = 0x804944f # After unlink the file
    init_state: angr.sim_state.SimState = project.factory.blank_state(
        addr = start_addr,
        add_options = {angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                       angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
    )

    # Set the buffer contents as the symbolic input
    # Find the buffer address in the binary
    buffer_addr = project.loader.find_symbol('buffer').rebased_addr
    init_state.memory.store(buffer_addr, symbolic_input, size=len(symbolic_input) // 8)

    # Create a simulation manager
    simgr = project.factory.simulation_manager(init_state)

    # Explore the binary to find the desired state
    succ_addr = 0x80494be
    avoid_addr = 0x80494a4
    simgr.explore(find=succ_addr, avoid=avoid_addr)

    if simgr.found:
        found_state = simgr.found[0]
        solution = found_state.solver.eval(symbolic_input, cast_to=bytes)
        # print(f'Solution found: {solution}')
        print(solution.decode().split('\x00')[0])  # Print up to the first null byte
    else:
        print('No solution found.')

if __name__ == '__main__':
    main()