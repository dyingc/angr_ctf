
import unittest
import os
import sys
import re
from typing import Dict, Any

# Add the project root to the Python path to resolve module imports
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from ai_agent.reverse_engineering import (
    get_function_list,
    get_disassembly,
    get_pseudo_code,
    execute_python_code,
    execute_os_command,
    do_internal_inference,
    InternalInferenceToolInput
)
from ai_agent.r2_utils import (
    get_call_graph,
    get_cfg_basic_blocks,
    get_strings,
    search_string_refs,
    emulate_function
)

class TestReverseEngineeringTools(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """Set up the test class with the binary path."""
        cls.binary_path = os.path.join(project_root, '00_angr_find', '00_angr_find')
        # cls.binary_path = os.path.join(project_root, 'crackme100')
        cls.function_name = 'main'

        # Check if the binary exists before running tests
        if not os.path.exists(cls.binary_path):
            raise FileNotFoundError(f"Test binary not found at: {cls.binary_path}")

    def test_get_function_list(self):
        """Test get_function_list to ensure it finds the main function."""
        result = get_function_list(self.binary_path)
        self.assertIsInstance(result, dict)
        self.assertIn('result', result)

        functions = result['result']
        self.assertIsInstance(functions, list)

        # Check if 'main' is in the list of function names
        main_found = any(re.match(f'^.*\\.{self.function_name}$', f['name']) or f['name'] == self.function_name for f in functions)
        # main_found = any(f['name'] for f in functions)
        self.assertTrue(main_found, f"Function '{self.function_name}' not found in the binary.")

    def test_get_disassembly(self):
        """Test get_disassembly for the main function."""
        result = get_disassembly(self.binary_path, self.function_name)
        self.assertIsInstance(result, dict)
        self.assertIn('result', result)
        self.assertIsInstance(result['result'], str)
        self.assertIn('main', result['result']) # Check if the function name is in the disassembly

    def test_get_pseudo_code(self):
        """Test get_pseudo_code for the main function."""
        result = get_pseudo_code(self.binary_path, self.function_name)
        self.assertIsInstance(result, dict)
        self.assertIn('result', result)
        self.assertIsInstance(result['result'], str)
        # Check for C-like syntax
        self.assertIn('(', result['result'])
        self.assertIn(')', result['result'])
        self.assertIn('{', result['result'])

    def test_get_call_graph(self):
        """Test get_call_graph for the main function."""
        result = get_call_graph(self.binary_path, self.function_name)
        self.assertIsInstance(result, dict)
        self.assertIn('nodes', result)
        self.assertIn('edges', result)
        self.assertIsInstance(result['nodes'], list)
        self.assertIsInstance(result['edges'], list)

    def test_get_cfg_basic_blocks(self):
        """Test get_cfg_basic_blocks for the main function."""
        result = get_cfg_basic_blocks(self.binary_path, self.function_name)
        self.assertIsInstance(result, list)
        self.assertGreater(len(result), 0, "CFG should have at least one basic block.")
        block = result[0]
        self.assertIn('offset', block)
        self.assertIn('size', block)
        self.assertIn('succ', block)

    def test_get_strings(self):
        """Test get_strings to find known strings in the binary."""
        result = get_strings(self.binary_path)
        self.assertIsInstance(result, list)
        self.assertGreater(len(result), 0, "Should find at least one string.")

        # Check for a known string from the 00_angr_find challenge
        found_string = any("Good job." in s['string'] for s in result)
        self.assertTrue(found_string, "Expected string 'Good job.' not found.")

    def test_search_string_refs(self):
        """Test search_string_refs for a known string."""
        query = "Good job."
        result = search_string_refs(self.binary_path, query)
        self.assertIsInstance(result, list)
        self.assertGreater(len(result), 0, f"No references found for query: '{query}'")
        ref = result[0]
        self.assertIn('string', ref)
        self.assertIn('refs', ref)
        self.assertEqual(ref['string'], query)
        self.assertGreater(len(ref['refs']), 0, "Should have at least one reference.")

    def test_emulate_function(self):
        """Test emulate_function for the main function."""
        result = emulate_function(self.binary_path, self.function_name, max_steps=10)
        self.assertIsInstance(result, dict)
        self.assertIn('trace', result)
        self.assertIn('final_regs', result)
        self.assertIsInstance(result['trace'], list)
        self.assertGreater(len(result['trace']), 0, "Emulation trace should not be empty.")

    def test_execute_python_code(self):
        """Test execute_python_code with a simple command."""
        code = "print('Hello from test')"
        result = execute_python_code(code)
        self.assertIsInstance(result, dict)
        self.assertIn('result', result)
        self.assertEqual(result['result'], 'Hello from test')

    def test_execute_os_command(self):
        """Test execute_os_command with a simple command."""
        command = "echo 'Hello from OS'"
        result = execute_os_command(command)
        self.assertIsInstance(result, dict)
        self.assertIn('result', result)
        self.assertTrue(result['result']['success'])
        self.assertEqual(result['result']['stdout'].strip(), 'Hello from OS')

    def test_do_internal_inference(self):
        """Test do_internal_inference to ensure it structures data correctly."""
        input_data = {
            "known_facts": ["fact1", "fact2"],
            "reasoning_method": "deduction",
            "arguments": ["arg1", "arg2"],
            "inferred_insights": ["insight1"],
            "validation_check": "check"
        }
        result = do_internal_inference(**input_data)
        self.assertIsInstance(result, InternalInferenceToolInput)
        self.assertEqual(result.known_facts, input_data['known_facts'])
        self.assertEqual(result.reasoning_method, input_data['reasoning_method'])
        self.assertEqual(result.arguments, input_data['arguments'])
        self.assertEqual(result.inferred_insights, input_data['inferred_insights'])
        self.assertEqual(result.validation_check, input_data['validation_check'])

if __name__ == '__main__':
    unittest.main()
