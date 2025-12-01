import angr
import claripy
from angr.sim_state import SimState
from angr.storage import SimFile

def main():
    # Create a blank state for the binary
    project = angr.Project('./binary/x32/07_angr_symbolic_file', auto_load_libs=False)

    # password symbolic variable
    password_size = 0x40
    password = claripy.BVS('password', password_size * 8)

    # Create a symbolic file of size 0x40
    file_size = password_size
    password_file = SimFile(
        name='IFCONZGB.txt',
        content=password
    )

    # Create the initial state
    start_addr = 0x080493fd
    state: SimState = project.factory.blank_state(
        addr=start_addr,
        add_options={
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
        }
    )

    # Insert the symbolic file into the state's filesystem
    state.fs.insert(password_file.name, password_file)

    # You can now perform further analysis with the state
    simgr = project.factory.simulation_manager(state)
    succ_addr = 0x80494be
    avoid_addr = 0x80494a4
    simgr.explore(
        find=succ_addr,
        avoid=avoid_addr
    )

    # Print out the results
    if simgr.found:
        for found in simgr.found:
            solution = found.solver.eval(password, cast_to=bytes)
            print(solution.decode().split('\x00')[0])  # Print up to the first null byte
    else:
        print('No solution found.')

if __name__ == '__main__':
    main()