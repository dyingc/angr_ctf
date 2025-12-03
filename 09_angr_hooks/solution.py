import angr
import claripy
from angr.storage.file import SimFile, SimPackets
from angr.sim_state import SimState
from angr import options as o
import re
from archinfo import Endness

# Note, unlike the reference solution (scaffold09.py), the solution add constraint in the hook function and thus only one state is needed, which is superior to the reference solution regarding performance.

def main():
    # Load the binary
    project = angr.Project('./binary/x32/09_angr_hooks', auto_load_libs=False)

    # # Create a symbolic file to simulate input
    # input_size = 32
    # symbolic_input = claripy.BVS('symbolic_input', input_size * 8)
    # simfile = SimFile('input_file', content=symbolic_input, size=input_size)
    # simfile = SimPackets(name="simfile")

    # Create the initial state with the symbolic file as stdin
    state = project.factory.full_init_state(
        # args=['./binary/x32/09_angr_hooks'],
        # stdin=simfile,
        add_options={
            o.ZERO_FILL_UNCONSTRAINED_MEMORY,
            o.ZERO_FILL_UNCONSTRAINED_REGISTERS,
        }
    )

    # Set up hooks here if needed
    # 1. Find the address of check_equals function and reference_string
    check_equals_func_symbol = [sym for sym in project.loader.symbols if re.match(r'^check_equals_.*', sym.name)]

    reference_string_symbol = [sym for sym in project.loader.symbols if sym.name == 'password']
    if not reference_string_symbol:
        raise Exception("Could not find the reference string symbol 'password'.")
    reference_string_symbol = reference_string_symbol[0]

    if not check_equals_func_symbol:
        raise Exception("Could not find the check_equals function symbol.")

    check_equals_func_symbol = check_equals_func_symbol[0]
    check_equals_func = check_equals_func_symbol.rebased_addr
    print(f"Found check_equals function ({check_equals_func_symbol.name}) at: {hex(check_equals_func)}")

    # 2. Hook the check_equals function

    bytes_to_skip = check_equals_func_symbol.size # the size of the function in bytes

    @project.hook(check_equals_func, length=bytes_to_skip)
    def hook_check_equals(state: SimState):
        # Find the address of the reference string to check against

        # Extract the parameters from the state
        stack_ptr = state.regs.get('esp')
        # The second parameter (length) is at esp + 8
        string_len = state.memory.load(stack_ptr + 0x8, 4, endness=state.arch.memory_endness) # or Endness.LE. The point is, this is a MUST. The default one is Endness.BE which is WRONG for x86
        print(f"Length of string to check: {string_len.concrete_value}")
        # The first parameter (buffer) is at esp + 4
        buffer_addr = state.memory.load(stack_ptr + 0x4, 0x4, endness=Endness.LE) # or state.arch.memory_endness. The point is, this is a MUST. The default one is Endness.BE which is WRONG for x86
        print(f"Address of \"buffer\": {hex(buffer_addr.concrete_value)}")

        # Load the user input from memory
        user_input = state.memory.load(buffer_addr, string_len)

        # Load the reference string from the memory
        # reference_string = state.memory.load(reference_string_symbol.rebased_addr, string_len)
        # print(f"Reference value: {hex(reference_string.concrete_value)}")
        reference_string = "JVFWZKBIAFZNPNXN"
        print(f"Reference value: {reference_string}")

        # Add constraint to check equality

        # for i in range(string_len.concrete_value):
        #     state.solver.add(user_input.get_byte(i) == reference_string.get_byte(i))
        # # state.solver.add(user_input == reference_string)

        # Set the return value in eax

        # state.regs.eax = claripy.BVV(1, 32) # because we've constrained equality, it will always be equal

        state.regs.eax = claripy.If(
            user_input == reference_string,
            claripy.BVV(1, 32),
            claripy.BVV(0, 32)
        )


        # 显示所有 stash
        print("\nAll stashes:")
        for stash_name in simgr.stashes:
            num = len(simgr.stashes[stash_name])
            if num == 0:
                continue
            print(f"  {stash_name}: {len(simgr.stashes[stash_name])}")
        print(f"The total number of constraints now: {len(state.solver.constraints)}")

    # Create a simulation manager to explore the binary
    simgr = project.factory.simulation_manager(state)

    # Explore the binary until a certain condition is met
    # simgr.explore(find=lambda s: b'Good Job.' in s.posix.dumps(1))
    simgr.explore(find=0x80493f0)

    if simgr.found:
        found_state = simgr.found[0]
        # solution = found_state.solver.eval(symbolic_input, cast_to=bytes)
        solution = found_state.posix.dumps(0)
        print(f'Solution found: {solution}')
    else:
        print('No solution found.')

if __name__ == '__main__':
    main()