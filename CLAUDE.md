# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Architecture

This is an angr CTF repository with two main components:

1. **CTF Challenges (00-17)**: Progressive angr tutorials teaching binary analysis through practical examples
2. **AI Agent System**: A reverse engineering MCP (Model Context Protocol) server with specialized tools

### Core Structure

- **Challenge Directories** (`00_angr_find/` to `17_angr_arbitrary_jump/`): Each contains:
  - `*.c.jinja`: C source template for binary generation
  - `generate.py`: Script to create challenge binaries
  - `scaffold*.py`: Solution templates with detailed instructions
  - `solution.py`: Complete solutions (where available)

- **AI Agent** (`ai_agent/`): Reverse engineering toolkit featuring:
  - **Backends**: Radare2 and Rizin binary analysis engines (`backends/`)
  - **Core Tools**: Call graphs, CFG analysis, string extraction, emulation (`core/`)
  - **MCP Server**: Exposes RE tools via Model Context Protocol (`mcp_server.py`)
  - **Libraries**: Specialized utilities for r2/rizin integration (`libs/`)

- **Solutions** (`solutions/`): Pre-built binaries and working solutions for all challenges

## Development Commands

### Environment Setup
```bash
# Install dependencies with uv (recommended)
uv sync

# Alternative: traditional pip install
pip install -e .
# or
pip install -r requirements.txt
```

### Building Challenges
```bash
# Generate all challenge binaries
python package.py output_directory

# Generate single challenge (example for challenge 00)
cd 00_angr_find
python generate.py seed_value binary_name

# Using Makefile (requires USERS variable)
make USERS='username' local
```

### Running Solutions
```bash
# Run scaffold template (learning mode)
cd 00_angr_find
python scaffold00.py

# Run complete solution
python solution.py

# Test solution against binary
echo "solution_string" | ./00_angr_find
```

### Testing
```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_rz_utils.py

# Run single test
pytest tests/test_rz_utils.py::TestClassName::test_method_name
```

### AI Agent Operations
```bash
# Start MCP server
python ai_agent/mcp_server.py

# Run reverse engineering analysis
python ai_agent/reverse_engineering.py

# Test backend functionality
python -c "from ai_agent.backends.dispatcher import call_backend; print(call_backend('get_function_list', './binary_path'))"
```

## Key Architecture Concepts

### Challenge Progression
The CTF follows a structured learning path:
- **00-02**: Basic symbolic execution (find, avoid, conditions)
- **03-06**: Memory symbolization (registers, stack, heap, files)
- **07-10**: Advanced techniques (constraints, hooks, SimProcedures)
- **11-17**: Complex scenarios (scanf simulation, static binaries, shared libraries, arbitrary memory operations)

### Backend Dispatcher Pattern
The AI agent uses a unified dispatcher (`ai_agent/backends/dispatcher.py`) that:
- Automatically selects between Radare2 and Rizin backends
- Provides consistent API across different analysis engines
- Falls back gracefully when tools are unavailable
- Caches results for performance

### Configuration System
- Main config: `ai_agent/config.yaml` - Controls AI agent behavior, tool selection, and prompts
- Dependencies: `pyproject.toml` - Modern Python packaging with angr ~9.2, rizin, MCP tools
- Legacy: `requirements.txt` - Minimal dependencies (jinja2, angr ~6.7)

### MCP Integration
The repository exposes reverse engineering capabilities through MCP (Model Context Protocol):
- Tools for binary analysis, disassembly, pseudo-code generation
- Emulation capabilities with ESIL (Evaluable Strings Intermediate Language)
- Integration with AI models for automated analysis

## Important Development Notes

- **Binary Generation**: All challenges use Jinja2 templates, not the older .templite format
- **Python Path**: AI agent modules require project root in Python path (handled automatically in main scripts)
- **Backend Requirements**: Install either `radare2` or `rizin` system packages for binary analysis
- **Testing Framework**: Uses pytest with mocking for backend interactions
- **Logging**: AI agent logs to `/tmp/re_ai_agent.log` by default

## Working with CTF Challenges

Each challenge directory is self-contained. To work on a challenge:
1. Generate the binary: `python generate.py <seed> <output_name>`
2. Study the scaffold file for objectives and hints
3. Analyze the binary with angr following the progression pattern
4. Test your solution against the generated binary

The scaffold files contain detailed comments explaining the angr concepts being taught and provide working code templates.