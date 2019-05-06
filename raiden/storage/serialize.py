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


def from_dict_hook(data):
    """Decode internal objects encoded using `to_dict_hook`.

    This automatically imports the class defined in the `_type` metadata field,
    and calls the `from_dict` method hook to instantiate an object of that
    class.

    Note:
        Because this function will do automatic module loading it's really
        important to only use this with sanitized or trusted input, otherwise
        arbitrary modules can be imported and potentially arbitrary code can be
        executed.
    """
    type_ = data.get("_type", None)
    if type_ is not None:
        klass = _import_type(type_)

        msg = "_type must point to a class with `from_dict` static method"
        assert hasattr(klass, "from_dict"), msg

        return klass.from_dict(data)
    return data


def to_dict_hook(obj):
    """Convert internal objects to a serializable representation.

    During serialization if the object has the hook method `to_dict` it will be
    automatically called and metadata for decoding will be added. This allows
    for the translation of objects trees of arbitrary depth. E.g.:

    >>> class Root:
    >>>     def __init__(self, left, right):
    >>>         self.left = left
    >>>         self.right = right
    >>>     def to_dict(self):
    >>>         return {
    >>>           'left': left,
    >>>           'right': right,
    >>>         }
    >>> class Node:
    >>>     def to_dict(self):
    >>>         return {'value': 'node'}
    >>> root = Root(left=None(), right=None())
    >>> json.dumps(root, default=to_dict_hook)
    '{
        "_type": "Root",
        "left": {"_type": "Node", "value": "node"},
        "right": {"_type": "Node", "value": "node"}
    }'
    """
    if hasattr(obj, "to_dict"):
        result = obj.to_dict()
        assert isinstance(result, dict), "to_dict must return a dictionary"
        result["_type"] = f"{obj.__module__}.{obj.__class__.__name__}"
        result["_version"] = 0
        return result

    raise TypeError(f"Object of type {obj.__class__.__name__} is not JSON serializable")


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
        return json.dumps(obj, default=to_dict_hook)

    @staticmethod
    def deserialize(data):
        return json.loads(data, object_hook=from_dict_hook)
