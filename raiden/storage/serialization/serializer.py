""" This module contains logic for automatically importing modules/objects,
this means that arbitrary modules are imported and potentially arbitrary code
can be executed (altough, the code which can be executed is limited to our
internal interfaces). Nevertheless, because of this, this must only be used
with sanitized input, to avoid the risk of exploits.
"""
import importlib
import json
from copy import deepcopy
from dataclasses import is_dataclass

# pylint: disable=unused-import
from raiden.storage.serialization.types import SchemaCache
from raiden.utils.typing import Any


def _import_type(type_name):
    module_name, _, klass_name = type_name.rpartition(".")

    try:
        module = importlib.import_module(module_name, None)
    except ModuleNotFoundError:
        raise TypeError(f"Module {module_name} does not exist")

    if not hasattr(module, klass_name):
        raise TypeError(f"Could not find {module_name}.{klass_name}")
    klass = getattr(module, klass_name)
    return klass


class SerializationBase:
    @staticmethod
    def serialize(obj: Any):
        raise NotImplementedError

    @staticmethod
    def deserialize(data: str):
        raise NotImplementedError


class DictSerializer(SerializationBase):
    @staticmethod
    def serialize(obj):
        # Default, in case this is not a dataclass
        data = obj
        if is_dataclass(obj):
            schema = SchemaCache.get_or_create_schema(obj.__class__)
            data = schema.dump(obj)
        return data

    @staticmethod
    def deserialize(data):
        if "_type" in data:
            klass = _import_type(data["_type"])
            schema = SchemaCache.get_or_create_schema(klass)
            return schema.load(deepcopy(data))
        return data


class JSONSerializer(SerializationBase):
    @staticmethod
    def serialize(obj):
        data = DictSerializer.serialize(obj)
        return json.dumps(data)

    @staticmethod
    def deserialize(data):
        data = DictSerializer.deserialize(json.loads(data))
        return data
