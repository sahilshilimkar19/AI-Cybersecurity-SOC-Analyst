"""Bootstrap smoke tests — every monorepo package imports cleanly."""

import importlib

import pytest

PACKAGES = [
    "config",
    "backend",
    "agents",
    "graph",
    "memory",
    "rag",
    "tools",
    "services",
    "models",
    "integrations",
]


@pytest.mark.parametrize("module", PACKAGES)
def test_package_imports(module: str) -> None:
    assert importlib.import_module(module) is not None
