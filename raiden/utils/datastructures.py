import collections
from itertools import zip_longest
from typing import Any, Callable, Iterable, Tuple


def merge_dict(to_update: dict, other_dict: dict) -> None:
    """ merges b into a """
    for key, value in other_dict.items():
        has_map = isinstance(value, collections.Mapping) and isinstance(
            to_update.get(key, None), collections.Mapping
        )

        if has_map:
            merge_dict(to_update[key], value)
        else:
            to_update[key] = value


def split_in_pairs(arg: Iterable) -> Iterable[Tuple]:
    """ Split given iterable in pairs [a, b, c, d, e] -> [(a, b), (c, d), (e, None)]"""
    # We are using zip_longest with one clever hack:
    # https://docs.python.org/3/library/itertools.html#itertools.zip_longest
    # We create an iterator out of the list and then pass the same iterator to
    # the function two times. Thus the function consumes a different element
    # from the iterator each time and produces the desired result.
    iterator = iter(arg)
    return zip_longest(iterator, iterator)


class cached_property:
    """ Same as functools.cached_property in python 3.8

    See https://docs.python.org/3/library/functools.html#functools.cached_property.
    Remove after upgrading to python3.8
    """

    def __init__(self, func: Callable) -> None:
        self.func = func
        self.__doc__ = func.__doc__

    def __get__(self, instance: Any, cls: Any = None) -> Any:
        if instance is None:
            return self
        attrname = self.func.__name__
        try:
            cache = instance.__dict__
        except AttributeError:  # objects with __slots__ have no __dict__
            msg = (
                f"No '__dict__' attribute on {type(instance).__name__!r} "
                f"instance to cache {attrname!r} property."
            )
            raise TypeError(msg) from None
        if attrname not in cache:
            cache[attrname] = self.func(instance)
        return cache[attrname]
