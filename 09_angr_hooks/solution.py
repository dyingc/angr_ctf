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

    # Create a symbolic file to simulate input
    input_size = 32
    symbolic_input1 = claripy.BVS('symbolic_input', input_size // 2 * 8)
    symbolic_input2 = claripy.BVS('symbolic_input', input_size // 2 * 8)

    # Note, we create a single SimPackets with two parts to simulate two phases of input
    # This is a MUST because there're two "scanf" calls in the binary, and each call will read from stdin.
    simpackets = SimPackets(name="simfile",
                         write_mode=False,
                         content=[(symbolic_input1, input_size // 2), (symbolic_input2, input_size // 2)])
    # Create the initial state with the symbolic file as stdin
    state = project.factory.full_init_state(
        # args=['./binary/x32/09_angr_hooks'],
        stdin=simpackets,
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
    check_equals_func_addr = check_equals_func_symbol.rebased_addr
    print(f"Found check_equals function ({check_equals_func_symbol.name}) at: {hex(check_equals_func_addr)}")

    # 2. Hook the check_equals function

    # We have two options here:
    # a) Hook the function itself
    # b) Hook the call site(s) of the function
    # Besides the hooking address and skipping size difference,
    # it's very important to note that the stack layout differs in these two cases.
    # Hooking the function itself means the return address is already pushed onto the stack,
    # while hooking the call site means the return address is not yet pushed.
    bytes_to_skip = check_equals_func_symbol.size - 1 # VERY IMPORTANT: -1 to avoid skipping the RET instruction (we need this to pop the return address from the stack and return to the caller)
    check_equals_called_address = 0x0804933e # the call site of check_equals function, if we choose option b
    instruction_to_skip_length = 5 # size of the CALL instruction, if we choose option b
    @project.hook(check_equals_func_addr, length=bytes_to_skip)  # option a
    # @project.hook(check_equals_called_address, length=instruction_to_skip_length)  # option b
    def hook_check_equals(state: SimState):
        # Find the address of the reference string to check against

        # Extract the parameters from the state
        stack_ptr = state.regs.get('esp')
        # The second parameter (length) is at esp + 8, if we're hooking the function itself (esp + 0 is return address, esp + 4 is first parameter)
        string_len = state.memory.load(stack_ptr + 0x8, 4, endness=state.arch.memory_endness) # or Endness.LE. The point is, this is a MUST. The default one is Endness.BE which is WRONG for x86
        # option b:
        # string_len = state.memory.load(stack_ptr + 0x4, 4, endness=state.arch.memory_endness)
        print(f"Length of string to check: {string_len.concrete_value}")
        # The first parameter (buffer) is at esp + 4. It'll be "esp" if we are hooking the calling site because the return address is not yet pushed.
        user_input_buffer_address = state.memory.load(stack_ptr + 0x4, 0x4, endness=Endness.LE) # or state.arch.memory_endness. The point is, this is a MUST. The default one is Endness.BE which is WRONG for x86
        # option b:
        # user_input_buffer_address = state.memory.load(stack_ptr, 0x4, endness=Endness.LE)
        print(f"Address of \"buffer\": {hex(user_input_buffer_address.concrete_value)}")

        # Load the user input from memory
        user_input_buffer_length = string_len
        mutated_user_input = state.memory.load(user_input_buffer_address, user_input_buffer_length)

        # Load the reference string from the memory
        reference_string = state.memory.load(reference_string_symbol.rebased_addr, user_input_buffer_length)
        print(f"Reference value: {hex(reference_string.concrete_value)}")
        print(f"Reference value: {reference_string.concrete_value.to_bytes(user_input_buffer_length.concrete_value, byteorder='big')}")

        # Add constraint to check equality
        # Note, surprisingly, adding byte-by-byte constraints is a little more efficient than adding a big constraint directly
        for i in range(string_len.concrete_value - 1):
            state.solver.add(mutated_user_input.get_byte(i) == reference_string.get_byte(i))

        # state.solver.add(mutated_user_input == reference_string)

        # Set the return value in eax

        state.regs.eax = claripy.BVV(1, 32) # because we've constrained equality, it will always be equal

        # # Alternatively, we could use claripy.If to set eax based on equality, but it's less efficient as it creates one more branch
        # state.regs.eax = claripy.If(
        #     mutated_user_input == reference_string,
        #     claripy.BVV(1, 32),
        #     claripy.BVV(0, 32)
        # )


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
    simgr.explore(find=lambda s: b'Good Job.' in s.posix.dumps(1))

    if simgr.found:
        found_state = simgr.found[0]
        solution = found_state.solver.eval(symbolic_input1, cast_to=bytes) + found_state.solver.eval(symbolic_input2, cast_to=bytes)
        # solution = found_state.posix.dumps(0)
        print(f'Solution found: {solution}')
    else:
        print('No solution found.')

if __name__ == '__main__':
    main()