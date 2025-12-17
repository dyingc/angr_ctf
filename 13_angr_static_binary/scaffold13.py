# This challenge is the exact same as the first challenge, except that it was
# compiled as a static binary. Normally, Angr automatically replaces standard
# library functions with SimProcedures that work much more quickly.
#
# To solve the challenge, manually hook any standard library c functions that
# are used. Then, ensure that you begin the execution at the beginning of the
# main function. Do not use entry_state.
#
# Here are a few SimProcedures Angr has already written for you. They implement
# standard library functions. You will not need all of them:
# angr.SIM_PROCEDURES['libc']['malloc']
# angr.SIM_PROCEDURES['libc']['fopen']
# angr.SIM_PROCEDURES['libc']['fclose']
# angr.SIM_PROCEDURES['libc']['fwrite']
# angr.SIM_PROCEDURES['libc']['getchar']
# angr.SIM_PROCEDURES['libc']['strncmp']
# angr.SIM_PROCEDURES['libc']['strcmp']
# angr.SIM_PROCEDURES['libc']['scanf']
# angr.SIM_PROCEDURES['libc']['printf']
# angr.SIM_PROCEDURES['libc']['puts']
# angr.SIM_PROCEDURES['libc']['exit']
#
# As a reminder, you can hook functions with something similar to:
# project.hook(malloc_address, angr.SIM_PROCEDURES['libc']['malloc']())
#
# There are many more, see:
# https://github.com/angr/angr/tree/master/angr/procedures/libc
#
# Additionally, note that, when the binary is executed, the main function is not
# the first piece of code called. In the _start function, __libc_start_main is
# called to start your program. The initialization that occurs in this function
# can take a long time with Angr, so you should replace it with a SimProcedure.
# angr.SIM_PROCEDURES['glibc']['__libc_start_main']
# Note 'glibc' instead of 'libc'.


import angr
import claripy
from angr.sim_state import SimState
from angr.sim_procedure import SimProcedure
from angr import SIM_LIBRARIES
from angr import SIM_PROCEDURES
from angr import SIM_TYPE_COLLECTIONS
from typing import Dict, List
from cle.backends.symbol import Symbol

# Get all the symbols
def symbol_filter(p: angr.Project) -> Dict[int, Symbol]:
    symbols = p.loader.symbols
    interested_symbol_names = ['strcmp', 'printf', 'exit', '__isoc99_scanf', 'puts']
    chosens : Dict[int, Symbol] = dict()
    for sym in symbols:
        if 'builtin_strncpy' in sym.name:
            print(sym.name)
        if not sym.is_function or not sym.name in interested_symbol_names:
            continue
        addr = sym.rebased_addr
        if not addr in chosens.keys():
            chosens[addr] = sym
    return chosens

def hook_simprocedures(p: angr.Project, syms: Dict[int, SimProcedure]) -> None:
    for addr, s in syms.items():
        simproc = s()
        p.hook(addr, simproc)

def get_simprocedure_by_name(syms: Dict[int, Symbol]) -> Dict[int, SimProcedure]:
    simprocedures = SIM_PROCEDURES['libc']
    matched : Dict[int, SimProcedure] = dict()
    for addr, sym in syms.items():
        name = sym.name.replace('__isoc99_', '')  # Adjust for naming differences
        simproc = simprocedures.get(name, None)
        if simproc is not None:
            matched[addr] = simproc
        else:
            print(f"Cannot find simprocedure for symbol name: {name}")
    return matched

def main(argv: List[str]) -> None:
    binary_path = 'binary/x32/13_angr_static_binary'
    binary_path = argv[1] if len(argv) > 1 else binary_path
    project = angr.Project(binary_path, auto_load_libs=False)
    interested_symbols = symbol_filter(project)
    syms = get_simprocedure_by_name(interested_symbols)
    hook_simprocedures(project, syms)

    state = project.factory.entry_state(
        addr=project.loader.find_symbol('main').rebased_addr,
        add_options={
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,}
    )

    simgr = project.factory.simulation_manager(state)

    simgr.explore(find=lambda s: b"Good Job." in s.posix.dumps(1),
                  avoid=lambda s: b"Try again." in s.posix.dumps(1))

    if simgr.found:
        found = simgr.found[0]
        flag = found.posix.dumps(0).decode().strip()
        print(f"Flag: {flag}")

if __name__ == '__main__':
    import sys
    main(sys.argv)
