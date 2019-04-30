import dataclasses

from dataclasses_json import dataclass_json


def dataclass(
        _cls: type = None,
        *,
        repr=True,
        eq=True,
        order=False,
        unsafe_hash=False,
        frozen=False,
) -> type:
    cls = dataclasses.dataclass(
        _cls,
        repr=repr,
        eq=eq,
        order=order,
        unsafe_hash=unsafe_hash,
        frozen=frozen,
    )

    return dataclass_json(cls)
