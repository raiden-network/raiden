import inspect
from enum import Enum

import pytoml

from raiden.utils.serialization import serialize_bytes

builtin_types = (int, str, bool, tuple)


def _clean_non_serializables(data):
    copy = {}
    for key, value in data.items():
        if callable(value):
            continue

        if hasattr(value, 'to_dict'):
            value = value.to_dict()

        if isinstance(value, dict):
            value = _clean_non_serializables(value)

        if isinstance(value, bytes):
            value = serialize_bytes(value)

        if isinstance(value, tuple):
            value = list(value)

        if isinstance(key, Enum):
            key = key.name

        if isinstance(value, Enum):
            value = value.value

        if value and not isinstance(value, builtin_types):
            try:
                pytoml.dumps({key: value})
            except RuntimeError:
                continue

        copy[key] = value
    return copy


def dump_config(config):
    print(pytoml.dumps({'configs': _clean_non_serializables(config)}))
    print()


def dump_cmd_options(options):
    print(pytoml.dumps({
        'options': _clean_non_serializables(options),
    }))
    print()


def dump_module(header, module):
    attribs = dict()
    for name, value in inspect.getmembers(module):
        if name.isupper():
            attribs[name] = value

    attribs = _clean_non_serializables(attribs)

    print(pytoml.dumps({header: attribs}))
    print()
