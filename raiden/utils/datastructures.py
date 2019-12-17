import collections
from itertools import zip_longest
from typing import Iterable, Tuple


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
