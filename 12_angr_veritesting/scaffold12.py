# When you construct a simulation manager, you will want to enable Veritesting:
# project.factory.simgr(initial_state, veritesting=True)
# Hint: use one of the first few levels' solutions as a reference.

import angr
import claripy
import sys
from angr.exploration_techniques.veritesting import Veritesting
from angr.sim_state import SimState

def main(argv):
    path_to_binary = argv[1] if len(argv) > 1 else './binary/x32/12_angr_veritesting'
    project = angr.Project(path_to_binary, auto_load_libs=False)

    state = project.factory.entry_state(
        add_options={angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                     angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
    )

    simgr = project.factory.simgr(state, veritesting=True)

    def suc(state: SimState) -> bool:
        return b'Good Job.' in state.posix.dumps(1)
    def fail(state: SimState) -> bool:
        return b'Try again.' in state.posix.dumps(1)
    simgr.explore(find=suc, avoid=fail)

    if simgr.found:
        found = simgr.found[0]
        solution = found.solver.eval(state.posix.stdin, cast_to=bytes)
        print(f'Solution: {solution}')
    else:
        print('No solution found.')

if __name__ == '__main__':
    main(sys.argv)