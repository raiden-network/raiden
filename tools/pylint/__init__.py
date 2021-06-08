from functools import lru_cache, wraps
from typing import Any, Callable, Optional, TypeVar

from astroid import Module
from astroid.node_classes import NodeNG

RAIDEN_TESTS_MODULE = "raiden.tests"

T_NODE = TypeVar("T_NODE", bound=NodeNG)


@lru_cache(maxsize=None)
def find_parent(node: NodeNG, scope_type: T_NODE) -> Optional[T_NODE]:
    current_node = node
    while current_node is not None and not isinstance(current_node, scope_type):
        current_node = current_node.parent
    return current_node


def ignore_tests(func: Callable) -> Callable:
    """Decorator that ignores nodes below the raiden.tests module."""

    @wraps(func)
    def decorator(self, node: NodeNG) -> Any:
        module_node = find_parent(node, Module)
        if module_node is None or module_node.name.startswith(RAIDEN_TESTS_MODULE):
            return None
        return func(self, node)

    return decorator
