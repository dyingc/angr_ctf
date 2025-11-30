import angr
import claripy

def main():
    # Load the binary
    project = angr.Project('./binary/x32/06_angr_symbolic_dynamic_memory', auto_load_libs=False)

    # Create two symbolic bitvectors for the input
    input_size = 9  # The last byte is for the null terminator
    input0 = claripy.BVS('input0', 8 * (input_size - 1))
    input1 = claripy.BVS('input1', 8 * (input_size - 1))

    # Create an initial state with the symbolic input
    start_addr = 0x80492e3 # Address after __isoc99_scanf("%8s %8s",buffer0,buffer1) which we need to set up manually
    state: angr.sim_state.SimState = project.factory.blank_state(
        addr = start_addr,
        add_options = {angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                       angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
    )

    # Create a simulation manager
    simgr = project.factory.simulation_manager(state)

    # Allocate two dynamic memory buffers for the inputs
    heap_buffer0 = state.heap.allocate(input_size)
    heap_buffer1 = state.heap.allocate(input_size)

    # Store input0 and input1 symbolic variables into the allocated buffers
    state.memory.store(heap_buffer0, input0, size=len(input0) // 8, endness=project.arch.memory_endness)
    state.memory.store(heap_buffer1, input1, size=len(input1) // 8, endness=project.arch.memory_endness)
    # Null-terminate the strings
    state.memory.store(heap_buffer0 + (input_size - 1), claripy.BVV(0, 8), size=1)
    state.memory.store(heap_buffer1 + (input_size - 1), claripy.BVV(0, 8), size=1)

    # Automatically find the address of "buffer0" and "buffer1" in the binary
    buffer0 = project.loader.find_symbol('buffer0').rebased_addr
    buffer1 = project.loader.find_symbol('buffer1').rebased_addr

    # Store the symbolic inputs into the allocated buffers
    state.memory.store(buffer0, heap_buffer0, size=4, endness=project.arch.memory_endness)
    state.memory.store(buffer1, heap_buffer1, size=4, endness=project.arch.memory_endness)

    # Explore the binary to find the desired state
    succ_addr = 0x80493a6
    avoid_addr = 0x8049394
    simgr.explore(find=succ_addr, avoid=avoid_addr)

    if simgr.found:
        found_state = simgr.found[0]

        symbolic_input = claripy.Concat(input0, ' ', input1)
        solution = found_state.solver.eval(symbolic_input, cast_to=bytes)
        print(f'Solution found: {solution}')
    else:
        print('No solution found.')

if __name__ == '__main__':
    main()