""" This module contains logic for automatically importing modules/objects,
this means that arbitrary modules are imported and potentially arbitrary code
can be executed (altough, the code which can be executed is limited to our
internal interfaces). Nevertheless, because of this, this must only be used
with sanitized input, to avoid the risk of exploits.
"""
import importlib
import json
from dataclasses import is_dataclass

from marshmallow import Schema
from marshmallow_dataclass import class_schema

from raiden.utils.typing import Any, Dict

# pylint: disable=unused-import
import raiden.storage.serialization.types  # noqa # isort:skip


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


def class_type(clazz: type) -> str:
    return f"{clazz.__module__}.{clazz.__name__}"


def set_class_type(self, data, many):
    data["_type"] = self.schema_parent_class_name
    return data


def remove_class_type(self, data, many):
    if "_type" in data:
        del data["_type"]
    return data


def inject_type_resolver_hook(schema: Schema, clazz: type):
    key = ("post_dump", False)
    schema._hooks[key].append("attach_type")
    schema.attach_type = set_class_type
    setattr(schema.attach_type, "__marshmallow_hook__", {key: {"pass_original": True}})
    schema.schema_parent_class_name = class_type(clazz)


def inject_remove_type_field_hook(schema: Schema):
    key = ("pre_load", False)
    schema._hooks[key].append("remove_type")
    schema.remove_type = remove_class_type
    setattr(schema.remove_type, "__marshmallow_hook__", {key: {"pass_original": True}})


class SerializationBase:
    @staticmethod
    def serialize(obj: Any):
        raise NotImplementedError

    @staticmethod
    def deserialize(data: str):
        raise NotImplementedError


class DictSerializer(SerializationBase):
    SCHEMA_CACHE: Dict[str, Schema] = {}

    @staticmethod
    def get_or_create_schema(clazz: type) -> Schema:
        class_name = clazz.__name__
        if class_name not in DictSerializer.SCHEMA_CACHE:
            schema = class_schema(clazz)
            inject_type_resolver_hook(schema, clazz)
            inject_remove_type_field_hook(schema)

            DictSerializer.SCHEMA_CACHE[class_name] = schema
        return DictSerializer.SCHEMA_CACHE[class_name]

    @staticmethod
    def serialize(obj):
        # Default, in case this is not a dataclass
        data = obj
        if is_dataclass(obj):
            schema = DictSerializer.get_or_create_schema(obj.__class__)
            data = schema().dump(obj)
        return data

    @staticmethod
    def deserialize(data):
        if "_type" in data:
            klass = _import_type(data["_type"])
            schema = DictSerializer.get_or_create_schema(klass)
            return schema().load(data)
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
