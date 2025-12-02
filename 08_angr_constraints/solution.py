import angr
import claripy
from angr.sim_type import SimState
from archinfo import Endness
import re

# Not started from the beginning of the binary, but after scanf

def main():
    # Load the binary
    project = angr.Project('./binary/x32/08_angr_constraints', auto_load_libs=False)

    # Create an initial state
    start_addr = 0x80492e0 # After __iso99_scanf
    state: SimState = project.factory.blank_state(
        addr=start_addr,
        add_options={
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
        }
    )

    # Set the password memory
    # Find the "password" symbol from the binary
    password_addr = project.loader.find_symbol('password').rebased_addr
    # store the password array
    state.memory.store(password_addr, 0x4b555353, size=4, endness=state.arch.memory_endness) # Endness.LE
    state.memory.store(password_addr + 4, 0x574b4a44, size=4, endness=state.arch.memory_endness) # Endness.LE
    state.memory.store(password_addr + 8, 0x4f475a53, size=4, endness=state.arch.memory_endness) # Endness.LE
    state.memory.store(password_addr + 12, 0x594a4f4f, size=4, endness=state.arch.memory_endness) # Endness.LE

    for i in range(0, 16, 4):
        print(hex(state.memory.load(password_addr + i, size=4).concrete_value))
        for j in range(4):
            print(hex(state.memory.load(password_addr + i + j, size=1).concrete_value), end=' ')
        print()

    # Create a symbolic variable with 17 bytes, terminated by null byte
    input_size = 17
    user_input = claripy.BVS('user_input', (input_size - 1) * 8)
    desired_value = state.memory.load(password_addr, size=16)
    for i in range(0, input_size - 1):
        # Ensure capital letters A-Z (Optional)
        state.solver.add(user_input.get_byte(i) > 0x40)
        state.solver.add(user_input.get_byte(i) < 0x5b)

    # Append null byte at the end
    user_input = claripy.Concat(
        user_input,
        claripy.BVV(b'\x00')
    )

    # Set the user_input to "buffer" variable in memory. Fetch the address of "buffer" from the binary symbols first
    buffer_addr = project.loader.find_symbol('buffer').rebased_addr
    state.memory.store(buffer_addr, user_input, endness=Endness.BE)

    # Create a simulation manager
    simgr = project.factory.simulation_manager(state)

    # Explore the binary to find a specific address (e.g., 0x400800)
    for symbol in project.loader.symbols:
        if re.match(r'^check_equals.*$', symbol.name):
            pwd_compare_func_addr = symbol.rebased_addr
            break
    if not pwd_compare_func_addr:
        raise Exception('Could not find the password comparison function address')

    simgr.explore(find=pwd_compare_func_addr)

    if simgr.found:

        found_state = simgr.found[0]
        mutated_password = found_state.memory.load(buffer_addr, size=16)

        for i in range(0, input_size - 1):
            # Add constraint that the mutated password matches with desired value
            found_state.solver.add(mutated_password.get_byte(i) == desired_value.get_byte(i).concrete_value)

        solution = found_state.solver.eval(user_input, cast_to=bytes)

        print(f'Solution found: {solution[:-1].decode()}')  # Exclude null terminator
    else:
        print('No solution found.')

if __name__ == '__main__':
    main()