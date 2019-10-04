from typing import Generic, TypeVar

T = TypeVar("T")

class AsyncResult(Generic[T]):
    def get(self, block: bool = True, timeout: float = None) -> T: ...
    def set(self, value: T = None) -> None: ...
