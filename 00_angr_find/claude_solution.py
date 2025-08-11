#!/usr/bin/env python3
"""
Symbolic execution solution for 00_angr_find_arm using angr
This script uses symbolic execution to find the password that makes the program print "Good Job"
"""

import angr
import claripy

def solve_with_angr():
    # Load the binary
    binary_path = "/Users/yingdong/VSCode/angr/angr_ctf/00_angr_find/00_angr_find_arm"
    project = angr.Project(binary_path, auto_load_libs=False)

    # Define target addresses based on disassembly analysis
    # Success path: where "Good Job" is printed
    find_addr = 0x100000664  # Address where program branches to print "Good Job"

    # Failure paths: where "Try again" is printed
    avoid_addrs = [
        0x100000654,  # "Try again" in main function
        0x10000049c   # "Try again" in complex_function (if invalid input)
    ]

    print(f"Target binary: {binary_path}")
    print(f"Find address (Good Job): {hex(find_addr)}")
    print(f"Avoid addresses (Try again): {[hex(addr) for addr in avoid_addrs]}")

    # Create initial state at program entry
    initial_state = project.factory.entry_state()

    # Create symbolic input for the password (8 characters + null terminator)
    password_length = 8
    password = claripy.BVS("password", password_length * 8)  # 8 bytes = 64 bits

    # Constrain each character to be a uppercase letter (A-Z: 0x41-0x5A)
    for i in range(password_length):
        char = password.get_byte(i)
        initial_state.solver.add(char >= 0x41)  # >= 'A'
        initial_state.solver.add(char <= 0x5A)  # <= 'Z'

    # Store the symbolic password in stdin
    initial_state.posix.stdin.store(0, password)
    initial_state.posix.stdin.store(password_length, claripy.BVV(0x0a, 8))  # newline

    # Create simulation manager
    simulation_manager = project.factory.simulation_manager(initial_state)

    print("\nStarting symbolic execution...")

    # Explore paths to find the target and avoid failure paths
    simulation_manager.explore(find=find_addr, avoid=avoid_addrs)

    # Check if we found a solution
    if simulation_manager.found:
        print(f"Success! Found {len(simulation_manager.found)} solution(s)")

        # Get the first solution
        solution_state = simulation_manager.found[0]

        # Extract the concrete password value
        concrete_password = solution_state.solver.eval(password, cast_to=bytes)

        print(f"Password found: {concrete_password.decode('ascii')}")

        # Verify the solution by checking stdin
        try:
            stdin_content = solution_state.posix.dumps(0)
            print(f"Full stdin content: {stdin_content}")
        except:
            print("Could not extract stdin content")

        # Show stdout if available
        try:
            stdout_content = solution_state.posix.dumps(1)
            if stdout_content:
                print(f"Program output: {stdout_content}")
        except:
            print("Could not extract stdout content")

        return concrete_password.decode('ascii')

    else:
        print("No solution found!")
        print(f"Deadended states: {len(simulation_manager.deadended)}")
        print(f"Active states: {len(simulation_manager.active)}")

        # Analyze why no solution was found
        if simulation_manager.deadended:
            print("Some paths deadended - possible constraint conflicts")
        if simulation_manager.active:
            print("Some paths still active - might need more exploration")

        return None

def verify_solution(password):
    """
    Verify the solution by running the actual binary (if possible)
    or by manually checking the transformation logic
    """
    print(f"\nVerifying solution: {password}")

    # Manual verification using the reverse-engineered logic
    def complex_function(char, index):
        char_val = ord(char)
        if char_val < 0x41 or char_val > 0x5A:  # Not A-Z
            return None
        return chr((char_val - 0x41 + index * 3) % 26 + 0x41)

    transformed = ""
    for i, char in enumerate(password):
        trans_char = complex_function(char, i)
        if trans_char is None:
            print(f"Invalid character at position {i}: {char}")
            return False
        transformed += trans_char

    target = "HXUITWOA"
    print(f"Transformed: {transformed}")
    print(f"Target:      {target}")
    print(f"Match: {transformed == target}")

    return transformed == target

if __name__ == "__main__":
    print("="*60)
    print("ARM Binary Password Cracker using Symbolic Execution")
    print("="*60)

    # Solve using angr
    password = solve_with_angr()

    if password:
        # Verify the solution
        if verify_solution(password):
            print(f"\n✅ SUCCESS: The password is '{password}'")
        else:
            print(f"\n❌ VERIFICATION FAILED: '{password}' does not produce correct output")
    else:
        print("\n❌ FAILED: Could not find password using symbolic execution")