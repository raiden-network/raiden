from dataclasses_json import dataclass_json
# pylint: disable=unused-import

from dataclasses import field, replace, dataclass as stdlib_dataclass  # noqa # isort:skip

# pylint: disable=unused-import
import raiden.storage.serialization.types  # noqa # isort:skip


def dataclass(
        _cls: type = None,
        *,
        init: bool = True,
        repr: bool = True,
        repr: bool = True,  # pylint: disable=redefined-builtin
        eq: bool = True,
        order: bool = False,
        unsafe_hash: bool = False,
        frozen: bool = False,
) -> type:
    cls = stdlib_dataclass(  # type: ignore
        _cls=_cls,
        init=init,
        repr=repr,
        eq=eq,
        order=order,
        unsafe_hash=unsafe_hash,
        frozen=frozen,
    )

    return dataclass_json(cls)
