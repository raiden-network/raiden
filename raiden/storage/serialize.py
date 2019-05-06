""" This module contains logic for automatically importing modules/objects,
this means that arbitrary modules are imported and potentially arbitrary code
can be executed (altough, the code which can be executed is limited to our
internal interfaces). Nevertheless, because of this, this must only be used
with sanitized input, to avoid the risk of exploits.
"""
import importlib
import json

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


class JSONSerializer(SerializationBase):
    @staticmethod
    def serialize(obj):
        if hasattr(obj, "schema"):
            return obj.schema().dumps(obj)

        return json.dumps(obj)

    @staticmethod
    def deserialize(data):
        obj_data = json.loads(data)
        type_ = _import_type(obj_data["type_"])
        return type_.schema().loads(data)
