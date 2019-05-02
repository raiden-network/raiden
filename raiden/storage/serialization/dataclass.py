# pylint: disable=unused-import
from dataclasses import dataclass as stdlib_dataclass, field, fields, replace  # noqa

from dataclasses_json import dataclass_json

# pylint: disable=unused-import
import raiden.storage.serialization.types  # noqa # isort:skip


def dataclass(
        _cls: type = None,
        *,
        init: bool = True,
        repr: bool = True,  # pylint: disable=redefined-builtin
        eq: bool = True,
        order: bool = False,
        unsafe_hash: bool = False,
        frozen: bool = False,
) -> type:
    def wrapper(cls):
        cls = stdlib_dataclass(  # type: ignore
            cls,
            init=init,
            repr=repr,
            eq=eq,
            order=order,
            unsafe_hash=unsafe_hash,
            frozen=frozen,
        )
        return dataclass_json(cls)

    if _cls is None:
        return wrapper

    return wrapper(_cls)
