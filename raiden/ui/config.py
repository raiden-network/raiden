import inspect
from enum import Enum

import toml

from raiden.utils.serialization import serialize_bytes

HEADER_PREFIX = ' ' * 2
CONFIG_PREFIX = HEADER_PREFIX * 2


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

        copy[key] = value
    return copy


def dump_config(config):
    print(toml.dumps({'configs': config}))
    print()


def dump_cmd_options(options):
    print(toml.dumps({
        'options': _clean_non_serializables(options),
    }))
    print()


def dump_module(header, module):
    attribs = dict()
    for name, value in inspect.getmembers(module):
        if name.isupper():
            attribs[name] = value

    attribs = _clean_non_serializables(attribs)

    print(toml.dumps({header: attribs}))
    print()
