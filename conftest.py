"""Test import isolation for mixed agent/server pytest runs.

The repository has two Python apps that both use top-level package names such
as ``services``, ``utils``, and ``controllers``. Running the suites separately
works, but ``pytest agent/tests server/tests`` can cache the agent packages
first and then break server collection. This hook switches the import cache to
the server tree before each server test file is collected.
"""

import os
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent
AGENT_DIR = REPO_ROOT / "agent"
SERVER_DIR = REPO_ROOT / "server"
SERVER_TESTS_DIR = SERVER_DIR / "tests"
TOP_LEVEL_NAMES = (
    "bootstrap",
    "config",
    "controllers",
    "database",
    "middleware",
    "models",
    "routes",
    "services",
    "utils",
)


def _module_paths(module) -> list[str]:
    paths = []
    file_path = getattr(module, "__file__", None)
    if file_path:
        paths.append(os.path.abspath(file_path))
    package_paths = getattr(module, "__path__", None)
    if package_paths:
        paths.extend(os.path.abspath(path) for path in package_paths)
    return paths


def _activate_server_imports() -> None:
    server_path = str(SERVER_DIR)
    if server_path in sys.path:
        sys.path.remove(server_path)
    sys.path.insert(0, server_path)

    for root_name in TOP_LEVEL_NAMES:
        for module_name in list(sys.modules):
            if module_name == root_name or module_name.startswith(root_name + "."):
                sys.modules.pop(module_name, None)


def _maybe_activate_server_imports(path_value) -> None:
    try:
        file_resolved = Path(path_value).resolve()
        normalized = str(file_resolved).replace("/", "\\").lower()
        marker = str(SERVER_TESTS_DIR).replace("/", "\\").lower() + "\\"
        if normalized.startswith(marker):
            _activate_server_imports()
    except Exception:
        # Never let import isolation interfere with pytest's own collection.
        pass


def pytest_collect_file(file_path: Path, parent):
    _maybe_activate_server_imports(file_path)
    return None


def pytest_pycollect_makemodule(module_path: Path, parent):
    _maybe_activate_server_imports(module_path)
    return None


def pytest_collectreport(report):
    nodeid = str(getattr(report, "nodeid", "")).replace("\\", "/")
    if nodeid.startswith("agent/tests/"):
        for root_name in TOP_LEVEL_NAMES:
            for module_name in list(sys.modules):
                if module_name == root_name or module_name.startswith(root_name + "."):
                    sys.modules.pop(module_name, None)
