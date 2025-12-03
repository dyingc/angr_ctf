import angr
import claripy
from angr.storage.file import SimFile, SimPackets
from angr.sim_state import SimState
from angr import options as o
import re
import sys
from archinfo import Endness

def main():
    # Load the binary
    project = angr.Project('./binary/x32/09_angr_hooks', auto_load_libs=False)

    # Create a symbolic file to simulate input
    input_size = 32
    symbolic_input_phase_1 = claripy.BVS('symbolic_input', input_size // 2 * 8)
    symbolic_input_phase_2 = claripy.BVS('symbolic_input', input_size // 2 * 8)

    # Note, we create a single SimPackets with two parts to simulate two phases of input
    # This is a MUST because there're two "scanf" calls in the binary, and each call will read from stdin.
    simpackets = SimPackets(name="simfile",
                         write_mode=False,
                         content=[(symbolic_input_phase_1, input_size // 2), (symbolic_input_phase_2, input_size // 2)])
    # Create the initial state with the symbolic file as stdin
    state = project.factory.full_init_state(
        # args=['./binary/x32/09_angr_hooks'],
        stdin=simpackets,
        add_options={
            o.ZERO_FILL_UNCONSTRAINED_MEMORY,
            o.ZERO_FILL_UNCONSTRAINED_REGISTERS,
        }
    )

    # Create a simulation manager to explore the binary
    simgr_phase_1 = project.factory.simulation_manager(state)

    # Explore the binary until calling the "check_equals" function
    simgr_phase_1.explore(find=0x0804933e)

    if simgr_phase_1.found:
        # We add the post constraint here after reaching the check_equals function
        phase_1_state = simgr_phase_1.found[0]
        print(f"Reached check_equals function at: {hex(phase_1_state.addr)}")

        # Add constraint that the mutated input must equal the reference string
        reference_string = claripy.BVV(b"JVFWZKBIAFZNPNXN", len(b"JVFWZKBIAFZNPNXN") * 8)
        mutated_input = phase_1_state.memory.load(0x0804c02c, input_size) # "buffer" address
        for i in range(len(reference_string) // 8):
            phase_1_state.solver.add(mutated_input.get_byte(i) == reference_string.get_byte(i))

        # Output the input that satisfies the condition in this phase
        input_1 = phase_1_state.solver.eval(symbolic_input_phase_1, cast_to=bytes)
        print(f"Phase 1 input: {input_1}")

        # Start the phase 2 exploration from the phase 1 state
        phase_1_state.regs.eip = 0x08049343 # Skip the CALL `check_equals_JVFWZKBIAFZNPNXN` instruction
        phase_1_state.regs.eax = 1 # Assume the check passed

        simgr_phase_2 = project.factory.simulation_manager(phase_1_state) # IMPORTANT: start from phase_1_state

        # Explore to find the "Good Job." output
        # simgr_phase_2.explore(find=lambda s: b'Good Job.' in s.posix.dumps(sys.stdin.fileno()))
        simgr_phase_2.explore(find=0x080493f0)  # Address of the "Good Job." output

        if simgr_phase_2.found:
            found_state = simgr_phase_2.found[0]
            # Output the phase 2 input
            input_2 = found_state.solver.eval(symbolic_input_phase_2, cast_to=bytes)
            print(f"Phase 2 input: {input_2}")
            print(f"Full input to pass both phases: {input_1 + input_2}")
        else:
            print("Could not find a state that reaches the 'Good Job.' output in phase 2.")
    else:
        print("Could not reach the check_equals function in phase 1.")

if __name__ == '__main__':
    main()