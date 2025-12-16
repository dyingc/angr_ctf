# When you construct a simulation manager, you will want to enable Veritesting:
# project.factory.simgr(initial_state, veritesting=True)
# Hint: use one of the first few levels' solutions as a reference.

import angr
import claripy
import sys
from angr.exploration_techniques.veritesting import Veritesting
from angr.sim_state import SimState
from typing import List

# Skip the entire loop to avoid path explosion from excessive branching.
# However, this loop calls "complex_function" on each iteration, which we still
# need to execute to maintain correct program semantics.
#
# Reference: https://docs.angr.io/extending-angr/simprocedures
#
# Unlike SimProcedure, which provides a "self.call()" method for invoking original
# functions with automatic continuation via "continue_at", simple hook functions
# lack this mechanism. To work around this limitation, we employ a two-hook pattern:
#
# 1. First hook: Prepares the function call by:
#    - Setting up function arguments (registers/stack per calling convention)
#    - Pushing a "continuation address" onto the stack as the return address
#    - Redirecting execution to the target function (complex_function)
#    - Returning a successor state list with exactly one state configured as above
#    - Setting state.scratch.guard = claripy.true() (required for successors)
#    - Setting state.history.jumpkind = 'Ijk_Call' (NOTE: Documentation incorrectly
#      says state.scratch.jumpkind, but the actual implementation in UserHook reads
#      from state.history.jumpkind. See angr/procedures/stubs/UserHook.py line ~30)
#    Note: The 'length' parameter is irrelevant since we manually control flow via
#          the returned successor state (not by letting execution fall through)
#
# 2. Second hook: Installed at the "continuation address" to:
#    - Regain control after complex_function returns
#    - Access the function's return value (e.g., from RAX/EAX)
#    - Process results and execute the remaining logic
#    - Jump to the actual destination by setting state.regs.pc
#    - Return a successor state with state.history.jumpkind = 'Ijk_Boring'
#    Note: The 'length' parameter is also irrelevant here
#
# This pattern manually recreates SimProcedure's continuation mechanism using
# dynamic hook allocation. The continuation address is typically allocated from
# the extern segment via project.loader.extern_object.allocate() to avoid
# conflicts with existing code/data.
#
# Implementation note: When returning successor states from a hook function:
# - Return None to let execution continue naturally (default behavior)
# - Return [state] to take full control over successors
# - Each successor MUST have three attributes set:
#   * state.regs.pc (or state.regs.ip): Target instruction pointer
#   * state.scratch.guard: Branch condition (usually claripy.true())
#   * state.history.jumpkind: Jump type ('Ijk_Call', 'Ijk_Boring', etc.)
#     WARNING: Despite documentation saying "state.scratch.jumpkind", the actual
#     UserHook implementation reads from state.history.jumpkind. This is a known
#     documentation bug (verified by reading angr source code).
#
# Performance note: Although state.copy() is used when creating successors, this
# doesn't increase the number of execution paths—returning a single-element list
# [state] means only one path continues. The copy() operation uses copy-on-write
# (COW) semantics, making it lightweight. The original state passed to the hook
# is discarded after the hook returns, so memory overhead is minimal and temporary.

##############################################################################
# A much better, cleaner solution exists for this specific challenge.
##############################################################################
# Hook the comparison point where state explosion occurs.
#
# The loop compares buf[i] (in EBX) with the result of complex_function (in EAX)
# at each iteration. The conditional branch (CMP + JNZ) creates two paths per
# iteration: one where the characters match, one where they don't. This leads to
# 2^32 possible paths for a 32-character password.
#
# Our solution: Hook at the CMP instruction (0x080492a1) to:
# 1. Add a constraint forcing EBX == EAX (buf[i] must equal the mutated character)
#    via: state.solver.add(state.regs.ebx == state.regs.eax)
# 2. Skip both the CMP and JNZ instructions by jumping directly to 0x080492a5
#    (the ADD instruction that increments n_matched)
# 3. Return None from the hook to let execution continue with the modified state
#    (no need to manually create successors for this simpler approach)
#
# This eliminates the branching while preserving the loop's semantics. Angr will:
# - Execute the loop naturally for all 32 iterations
# - Call complex_function each time (maintain program semantics)
# - Accumulate 32 constraints (one per character: buf[0] == f(buf[0]), buf[1] == f(buf[1]), ...)
# - Solve for a password that satisfies all constraints simultaneously
#
# Optional optimization: If complex_function is slow, hook it separately with a
# Python implementation or symbolic formula to speed up execution.
#
# Why this approach is superior:
# - Minimal intervention: Only hooks the problematic branch point
# - Preserves program flow: Lets angr handle loop iteration and function calls
# - Single execution path: Maintains exactly 1 active state throughout (no path
#   explosion), even though the loop runs 32 times
# - Clean constraints: Each iteration adds one constraint (buf[i] == result),
#   building up to 32 constraints that the solver handles efficiently
# - No manual continuation: Simpler than the two-hook pattern described above
# - Natural state management: No need to manually manage successor states
#
# Code example:
#   @project.hook(0x080492a1, length=5)  # Hook CMP and JNZ (5 bytes total)
#   def force_match(state):
#       state.solver.add(state.regs.ebx == state.regs.eax)
#       state.regs.pc = 0x080492a5  # Skip to ADD instruction
#       # No return needed - state is modified in-place
#
# This approach is minimal, elegant, and leverages angr's natural execution flow
# rather than manually reimplementing control flow logic.


comparion_addr = 0x080492a1
matched_inc_addr = 0x080492a5

n_check_num = 0

def hook_check_logic(s:SimState)->List[SimState]:
    global n_check_num
    n_check_num += 1
    checker_i = s.regs.eax
    orig_chr = s.regs.ebx
    # Add constraint: checker_i == orig_chr
    s.add_constraints(checker_i == orig_chr)
    # Skip CMP and JNZ by setting PC to matched_inc_addr
    new_state = s.copy()
    new_state.regs.ip = matched_inc_addr # MUST use "ip" (or new_state.ip) rather than "pc" or others here according to https://docs.angr.io/en/latest/extending-angr/simprocedures.html#user-hooks
    new_state.scratch.guard = claripy.true()  # Mark that we took the "true" branch
    # The document https://docs.angr.io/en/latest/extending-angr/simprocedures.html#user-hooks is incorrect. We MUST set the "state.history.jumpkind" rather than the mentioned "state.scratch.jumpkind"!!
    new_state.history.jumpkind = 'Ijk_Boring'  # Indicate normal continuation
    # s.regs.pc = matched_inc_addr
    if n_check_num % 100 == 0:
        print(f"--- Iteration {n_check_num} ---")
        print(f"\tSymbolic feature of checker_i = {s.solver.symbolic(checker_i)}")
        print(f"\tSymbolic feature of orig_chr = {s.solver.symbolic(orig_chr)}")
        print(f"\tNumber of constraints so far: {len(s.solver.constraints)}")
        print(f"\tThe next PC will be set to: {hex(new_state.pc)}")

    return [new_state]

# Hooking helper function
def install_hooks(proj:angr.Project):
    # Note: length parameter is irrelevant here since we manually set PC
    proj.hook(addr=comparion_addr, hook=hook_check_logic)

def main(argv):
    path_to_binary = argv[1] if len(argv) > 1 else './binary/x32/12_angr_veritesting'
    project = angr.Project(path_to_binary, auto_load_libs=False)

    state = project.factory.entry_state(
        add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                     angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS}
    )

    simgr = project.factory.simgr(state, veritesting=False)

    def suc(state: SimState) -> bool:
        if state.addr == 0x080492c1:
            return True
        reached = b'Good Job.' in state.posix.dumps(1)
        return reached

    def fail(state: SimState) -> bool:
        avoid = b'Try again.' in state.posix.dumps(1)
        if avoid:
            print("Reached failure state!")
        return avoid

    install_hooks(project)
    simgr.explore(find=suc, avoid=fail)

    if simgr.found:
        found = simgr.found[0]
        solution = found.posix.dumps(sys.stdin.fileno()).decode()
        print(f'Solution: {solution}')
    else:
        print('No solution found.')

if __name__ == '__main__':
    main(sys.argv)