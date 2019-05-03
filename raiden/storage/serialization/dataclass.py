# pylint: disable=unused-import
from dataclasses import (  # noqa
    _FIELD,
    MISSING,
    Field,
    dataclass as stdlib_dataclass,
    field,
    fields,
    replace,
)

from dataclasses_json import dataclass_json

# pylint: disable=unused-import
import raiden.storage.serialization.types  # noqa # isort:skip


def class_type(cls):
    return f'{cls.__module__}.{cls.__name__}'


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
        #
        type_field = Field(
            default=MISSING,
            default_factory=MISSING,
            init=False,
            hash=None,
            repr=False,
            compare=False,
            metadata=None,
        )
        type_field.name = 'type_'
        type_field._field_type = _FIELD
        cls.__dataclass_fields__['type_'] = type_field
        cls.type_ = class_type(cls)
        cls = dataclass_json(cls)

        return cls

    if _cls is None:
        return wrapper

    return wrapper(_cls)
