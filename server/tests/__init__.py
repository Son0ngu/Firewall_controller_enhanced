"""Server test package isolation.

When pytest runs ``agent/tests`` and ``server/tests`` in one process, agent
tests can cache top-level packages named ``services``/``utils``/``controllers``.
Server tests use the same top-level names for the Flask app, so clear any
agent-owned modules right before importing server test modules.
"""

import os
import sys
from pathlib import Path


SERVER_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = SERVER_DIR.parent
AGENT_DIR = REPO_ROOT / "agent"

server_path = str(SERVER_DIR)
if server_path in sys.path:
    sys.path.remove(server_path)
sys.path.insert(0, server_path)


def _module_paths(module) -> list[str]:
    paths = []
    file_path = getattr(module, "__file__", None)
    if file_path:
        paths.append(os.path.abspath(file_path))
    package_paths = getattr(module, "__path__", None)
    if package_paths:
        paths.extend(os.path.abspath(path) for path in package_paths)
    return paths


for root_name in (
    "bootstrap",
    "config",
    "controllers",
    "database",
    "middleware",
    "models",
    "routes",
    "services",
    "utils",
):
    module = sys.modules.get(root_name)
    if module and any(path.startswith(str(AGENT_DIR)) for path in _module_paths(module)):
        for module_name in list(sys.modules):
            if module_name == root_name or module_name.startswith(root_name + "."):
                sys.modules.pop(module_name, None)
