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
from json import JSONDecodeError
from typing import Mapping

from marshmallow import ValidationError

from raiden.exceptions import SerializationError
from raiden.storage.serialization.types import MESSAGE_NAME_TO_QUALIFIED_NAME, SchemaCache
from raiden.utils.typing import Any, Dict


def _import_type(type_name: str) -> type:
    module_name, _, klass_name = type_name.rpartition(".")

    try:
        module = importlib.import_module(module_name, None)
    except ModuleNotFoundError as ex:
        raise TypeError(f"Module {module_name} does not exist") from ex

    if not hasattr(module, klass_name):
        raise TypeError(f"Could not find {module_name}.{klass_name}")
    klass = getattr(module, klass_name)
    return klass


class SerializationBase:
    @staticmethod
    def serialize(obj):
        raise NotImplementedError

    @staticmethod
    def deserialize(data):
        raise NotImplementedError


class DictSerializer(SerializationBase):
    # TODO: Fix the type annotation bellow.
    # Any is too broad of a type, the real signature is `Union[Dict,
    # Dataclass]`, however, there is no base class available from the
    # dataclasses module that allows for such type annotation.
    @staticmethod
    def serialize(obj: Any, include_module: bool = True) -> Dict:
        # Default, in case this is not a dataclass
        data = obj
        if is_dataclass(obj):
            try:
                schema = SchemaCache.get_or_create_schema(obj.__class__)
                data = schema.dump(obj)
            except (TypeError, ValidationError) as ex:
                raise SerializationError(f"Can't serialize: {data}") from ex
        elif not isinstance(obj, Mapping):
            raise SerializationError(f"Can only serialize dataclasses or dict-like objects: {obj}")

        if not include_module:
            # Only use 'Message' instead of `raiden.messages.Message` as _type.
            # Used for Raiden protocol messages.
            data["_type"] = data["_type"].split(".")[-1]

        return data

    @staticmethod
    def deserialize(data: Dict) -> Any:
        """ Deserialize a dict-like object.

        If the key ``_type`` is present, import the target and deserialize via Marshmallow.
        Raises ``SerializationError`` for invalid inputs.
        """
        if not isinstance(data, Mapping):
            raise SerializationError(f"Can't deserialize non dict-like objects: {data}")
        if "_type" in data:
            if "." not in data["_type"]:
                # When serializing Messages for external communication, we
                # strip the module part of the name to not leak implementation
                # details. We need to reconstruct them when loading a message.
                try:
                    data["_type"] = MESSAGE_NAME_TO_QUALIFIED_NAME[data["_type"]]
                except KeyError as ex:
                    raise SerializationError(f"Unknown type: {data['_type']}") from ex
            try:
                klass = _import_type(data["_type"])
                schema = SchemaCache.get_or_create_schema(klass)
                return schema.load(deepcopy(data))
            except (ValueError, TypeError, ValidationError) as ex:
                raise SerializationError(f"Can't deserialize: {data}") from ex
        return data


class JSONSerializer(SerializationBase):
    @staticmethod
    def serialize(obj: Any, include_module: bool = True) -> str:
        data = DictSerializer.serialize(obj, include_module=include_module)
        return json.dumps(data)

    @staticmethod
    def deserialize(data: str) -> Any:
        """ Deserialize a JSON object.

        Raises ``SerializationError`` for invalid inputs.
        """
        try:
            decoded_json = json.loads(data)
        except (UnicodeDecodeError, JSONDecodeError) as ex:
            raise SerializationError(f"Can't decode invalid JSON: {data}") from ex
        data = DictSerializer.deserialize(decoded_json)
        return data
