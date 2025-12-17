import angr
import claripy
from angr.sim_state import SimState
from angr.sim_procedure import SimProcedure

# Hook the __iso99_scanf function

class ScanfHook(SimProcedure):
    def run(self, fmt_str_ptr, key: claripy.BVV, user_input_2: claripy.BVV):
        # The fmt_str_ptr points to "%u %20s"
        # The first four bytes, as an unsigned integer to the "key"
        key_value = claripy.BVS('key_value', 4 * 8)
        user_input_2_value = claripy.BVS('user_input_2_value', 20 * 8)

        # Constraint the first 16 bytes of user_input_2_value to visible ASCII characters
        for i in range(16):
            self.state.solver.add(user_input_2_value.get_byte(i) > 0x20)
            self.state.solver.add(user_input_2_value.get_byte(i) < 0x7e)

        # Store the two values into the two pointers
        # VERY IMPORTANT: specify the endness when storing multi-byte, non-string values
        self.state.memory.store(key, key_value, endness=self.arch.memory_endness)
        # Store user_input_2_value as a string (null-terminated) - no endness needed as it's byte by byte
        self.state.memory.store(user_input_2, user_input_2_value)

        # Store the two values into globals for later retrieval
        self.state.globals['key_value'] = key_value
        self.state.globals['user_input_2_value'] = user_input_2_value

def main(argv):
    # Get binary path
    binary_path = argv[1] if len(argv) > 1 else 'binary/x32/15_angr_arbitrary_read'

    # Create the angr project
    project = angr.Project(
        thing = binary_path,
        auto_load_libs = False
    )

    # Hook the __isoc99_scanf function
    project.hook_symbol('__isoc99_scanf', ScanfHook())

    # Create the initial state at the entry point of the binary
    initial_state = project.factory.entry_state(
        add_options = {
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS
        }
    )

    good_job_symbol = project.loader.find_symbol('good_job')
    if good_job_symbol is None:
        raise Exception('Cannot find good_job symbol')
    good_job_symbol_addr = good_job_symbol.rebased_addr

    # SUC condition
    def is_successful(s: SimState) -> bool:
        addr = s.addr
        if addr != 0x080491f9: # It must first fall into `key == 0x3f91342` check
            return False
        good_job_addr = s.memory.load(good_job_symbol_addr, 4, endness=s.arch.memory_endness).concrete_value
        print(f"Good job addr: 0x{good_job_symbol_addr:08x}")
        print(f"Good job value: 0x{good_job_addr:08x}")
        # Load the contents in the "another_try_again" (ebp - 0xc)
        another_try_again_addr = s.regs.ebp - 0xc
        another_try_again_value = s.memory.load(another_try_again_addr, 4, endness=s.arch.memory_endness)

        ## Either of the following two methods works

        # suc = claripy.If(another_try_again_value == good_job_addr, claripy.true(), claripy.false())
        # suc = s.solver.satisfiable(extra_constraints=(suc == claripy.true(),)) # won't change the current containts, just check satisfiability
        # return suc

        s.solver.add(another_try_again_value == good_job_addr) # IMPORTANT: We need to use "good_job_addr" (in the .rodata) here instead of "good_job_symbol_addr" (in the .data)
        return True

    # Explore the binary to find the successful state
    simgr = project.factory.simgr(initial_state)
    simgr.explore(find=is_successful)

    if simgr.found:
        solution_state = simgr.found[0]

        # Retrieve the symbolic variables from the solution state
        key_value = solution_state.solver.eval(solution_state.globals['key_value'], cast_to=int)
        user_input_2_value = solution_state.solver.eval(solution_state.globals['user_input_2_value'], cast_to=bytes)

        print(f'Solution found:')
        print(f"User input should be: {key_value} {user_input_2_value.decode()}")
        print(f'Key: {key_value}')
        print(f'User Input 2: {user_input_2_value.decode()}')
        with open('/tmp/15_solution.dat', 'wb') as f:
            f.write(f"{key_value} {user_input_2_value.decode()}".encode())
    else:
        print('Could not find the solution')

if __name__ == '__main__':
    import sys
    main(sys.argv)