# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

angr CTF is an educational framework containing 18 progressively challenging Capture The Flag exercises (00-17) plus bonus challenges designed to teach symbolic execution and binary analysis using the angr framework. Each challenge is generated from Jinja2 templates to create unique binaries that teach specific angr concepts and techniques.

## Development Environment Setup

### Python Environment
- **Required Python**: 3.10+ (specified in pyproject.toml)
- **Virtual Environment**: Already configured in `.venv/`
- **Core Dependencies**: angr (>=9.2.162), jinja2 (>=3.1.6), ipython, pwntools
- **Package Management**: Uses modern uv.lock file for reproducible builds

### Environment Activation
```bash
source .venv/bin/activate
```

## Common Development Commands

### Building Individual Challenges
```bash
# Generate a single challenge binary with seed
cd <challenge_directory>
python generate.py <seed> <output_filename>

# Example
cd 01_angr_avoid
python generate.py 1234 01_angr_avoid
```

### Batch Building All Challenges
```bash
# Build all challenges for local development
python package.py <output_directory>

# Using Makefile for local builds
make USERS='username' local

# Using Makefile for web deployment builds
make USERS='username' web
```

### Running Solutions
```bash
# Run the generic solver (requires binary path as argument)
python solve.py <path_to_binary>

# Run challenge-specific solution
cd <challenge_directory>
python solution.py

# Run scaffold template (requires filling in placeholders)
python scaffold<XX>.py
```

### Testing Solutions
```bash
# Verify found solution against binary
echo "<solution_input>" | ./<binary_name>
```

### Running All Solutions
```bash
# Use the automated solution runner from the solutions directory
cd solutions/
./run-all.sh
```

## Architecture Overview

### Challenge Structure
Each challenge directory follows this pattern:
- **`<XX_name>.c.jinja`** - C source code template using Jinja2
- **`generate.py`** - Script to generate unique binaries from templates
- **`scaffold<XX>.py`** - Guided solution template with educational placeholders
- **`solution.py`** - Complete working solution
- **`README.md`** - Challenge explanation and learning objectives
- **`__init__.py`** - Python package marker

### Special Directories
- **`ai_agent/`** - Automated challenge solving framework with reverse engineering utilities
  - `reverse_engineering.py` - Core automated analysis capabilities
  - `r2_utils.py` - Radare2 integration utilities
  - `tests/` - Test suite for validation
- **`solutions/`** - Complete solution implementations for all challenges
  - Individual challenge solutions with `solve<XX>.py` scripts
  - `run-all.sh` - Automated batch solution runner
- **`xx_angr_segfault/`** - Bonus challenge for advanced debugging techniques
  - Uses legacy `.templite` format instead of Jinja2
  - Focuses on crash analysis and exploitation techniques

### Binary Generation Process
1. **Template Rendering**: Jinja2 templates (.c.jinja) are rendered with random values
2. **C Compilation**: Generated C code is compiled with specific GCC flags:
   - `-fno-pie -no-pie` - Disable position-independent executables
   - `-m32` - Generate 32-bit binaries for angr compatibility
3. **Unique Challenges**: Each seed creates different logic/conditions in the binary

### Learning Progression
- **Beginner (00-02)**: Basic angr concepts - project creation, path exploration, condition finding
- **Intermediate (03-06)**: Symbolic operations - registers, stack, memory, dynamic memory
- **Advanced (07-17)**: Complex techniques - file I/O, constraints, hooks, static analysis, arbitrary memory operations
- **Bonus Challenge**: `xx_angr_segfault` - Advanced segfault handling and debugging techniques

### Key angr Concepts Used
- **Project Creation**: `angr.Project(path_to_binary, auto_load_libs=False)`
- **State Management**: `project.factory.entry_state()` with configuration options
- **Symbolic Variables**: `claripy.BVS('name', size)` for symbolic inputs
- **Simulation Manager**: `project.factory.simgr(initial_state)` for path exploration
- **Path Exploration**: `simulation.explore(find=address, avoid=address)`
- **Solution Extraction**: `solution_state.posix.dumps(sys.stdin.fileno())`

## Development Workflow

### Creating New Challenges
1. Design learning objectives and target angr techniques
2. Create C source template with Jinja2 placeholders (`<XX_name>.c.jinja`)
3. Write `generate.py` script to render template with randomization
4. Create scaffold file with educational comments and placeholders
5. Write complete solution demonstrating the technique
6. Add challenge to `package.py` for batch building

### Solving Challenges
1. **Binary Analysis**: Use objdump, radare2, or IDA Pro to understand program flow
2. **Target Identification**: Find success/failure addresses in disassembly
3. **Scaffold Modification**: Fill in addresses and angr API calls in scaffold file
4. **Symbolic Execution**: Run angr to find input reaching success path
5. **Verification**: Test solution against the binary

### Debugging angr Solutions
- Enable logging: `logging.getLogger('angr').setLevel(logging.DEBUG)`
- Check simulation manager state: `len(simulation.active)`, `len(simulation.deadended)`
- Use IPython for interactive debugging: `IPython.embed()`
- Monitor exploration progress with state counts and error checking

### VSCode Debugging Configuration
The `.vscode/launch.json` file provides pre-configured debugging setups:
- **Current File**: Debug the currently active Python file
- **Current File with Arguments**: Debug with command-line arguments picker
- **CTF 00-04 Solutions**: Pre-configured launch configurations for specific challenges
- **Integrated Terminal**: Debug output appears in VSCode's integrated terminal

Python interpreter is automatically configured to use the project's virtual environment (`${workspaceFolder}/.venv/bin/python`).

## Important File Locations

- **Project Root**: `/home/edong/VSCode/angr/angr_ctf/`
- **Virtual Environment**: `.venv/` (Python 3.10)
- **Batch Build Script**: `package.py`
- **Generic Solver**: `solve.py`
- **Build System**: `Makefile` (supports local and web deployment)
- **Main Documentation**: `README.md` (comprehensive Chinese installation and usage guide)
- **VSCode Configuration**: `.vscode/settings.json`, `.vscode/launch.json`
- **Dependency Lock File**: `uv.lock` (reproducible builds)
- **Automated Solutions**: `solutions/run-all.sh` (batch solution runner)
- **AI Agent Framework**: `ai_agent/` (automated challenge solving)

## Current Branch Status

- **Branch**: `review_before_ch05`
- **Recent Work**: README updates with corrected memory interaction links, Chinese translation of solution comments, assembly syntax conversion from AT&T to Intel format

## Performance Considerations

- Use `auto_load_libs=False` to reduce analysis complexity
- Enable Unicorn engine for faster execution: `add_options=angr.options.unicorn`
- Set memory limits for complex challenges: `export ANGR_MAX_MEMORY=2G`
- Use Veritesting technique for state space reduction: `simulation.use_technique(angr.exploration_techniques.Veritesting())`