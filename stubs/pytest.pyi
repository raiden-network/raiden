from typing import Any, Callable, List, Tuple, TypeVar, Union, overload

from typing_extensions import Literal

FuncType = Callable[..., Any]
F = TypeVar("F", bound=FuncType)

Scopes = Union[
    Literal["function"],
    Literal["class"],
    Literal["module"],
    Literal["package"],
    Literal["session"],
]

GenerativeParams = List[Tuple[Any, ...]]
@overload
def fixture(scope: F) -> F: ...
@overload
def fixture(
    scope: Scopes = "function",
    params: GenerativeParams = None,
    autouse: bool = False,
    ids: List[str] = None,
    name: str = None,
): ...
