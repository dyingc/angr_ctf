import sys
import os
import json

# Add the project root to the Python path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from ai_agent.r2_utils import get_cfg_basic_blocks

binary_path = os.path.join(project_root, 'crackme100')
function_name = 'main'

# Temporarily modify r2_utils.py to print edges_json
# This is a hack for debugging, will revert later
with open(os.path.join(project_root, 'ai_agent', 'r2_utils.py'), 'r+') as f:
    content = f.read()
    f.seek(0)
    f.truncate()
    new_content = content.replace(
        "            edges_data = json.loads(edges_json) if edges_json else []",
        "            edges_data = json.loads(edges_json) if edges_json else []\n            print(f\"DEBUG: edges_json = {edges_json}\") # Temporary print for debugging"
    )
    f.write(new_content)


try:
    result = get_cfg_basic_blocks(binary_path, function_name)
    print("Function returned:", result)
except Exception as e:
    print(f"An error occurred: {e}")
finally:
    # Revert the temporary modification to r2_utils.py
    with open(os.path.join(project_root, 'ai_agent', 'r2_utils.py'), 'r+') as f:
        content = f.read()
        f.seek(0)
        f.truncate()
        original_content = content.replace(
            "            print(f\"DEBUG: edges_json = {edges_json}\") # Temporary print for debugging\n",
            ""
        )
        f.write(original_content)
