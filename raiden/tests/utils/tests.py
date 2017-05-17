# -*- coding: utf-8 -*-
import gc
import os
from itertools import chain, combinations, product

import gevent

from raiden.utils import get_project_root

__all__ = (
    'cleanup_tasks',
)


def get_test_contract_path(contract_name):
    contract_path = os.path.join(
        get_project_root(),
        'tests',
        'smart_contracts',
        contract_name
    )
    return os.path.realpath(contract_path)


def get_relative_contract(relative_to, contract_name):
    contract_path = os.path.join(
        os.path.dirname(os.path.realpath(relative_to)),
        contract_name
    )
    return contract_path


def cleanup_tasks():
    tasks = [
        running_task
        for running_task in gc.get_objects()
        if isinstance(running_task, gevent.Greenlet)
    ]
    gevent.killall(tasks)
    gevent.hub.reinit()


def all_combinations(values):
    """ Returns all possible combinations, from length 1 up to full-length of
    values.
    """
    all_generators = (
        combinations(values, r)
        for r in range(1, len(values))
    )
    flat = chain.from_iterable(all_generators)
    return flat


def fixture_all_combinations(invalid_values):
    """ Generate all combinations for testing invalid values.

    `pytest.mark.parametrize` will generate the combination of the full-length
    values, this is not sufficient for an exhaustive failing test with default
    values, example::

        @pytest.mark.parametrize("x", [0, 1])
        @pytest.mark.parametrize("y", [2, 3])
        def test_foo(x, y):
            with pytest.raises(Exception):
                # failing computation with x and y

    The above test will generate 4 tests {x:0,y:2}, {x:0,y:3}, {x:1,y:2}, and
    {x:1,y:3}, but it will not generate a scenario for x and y alone {x:0},
    {x:1}, {y:2}, {y:3}.
    """
    # all_combinations needs an object with length
    invalid_values_items = list(invalid_values.iteritems())

    # Generate all possible test combinations. E.g. `{a: [..], b: [..]}` will
    # produce tests for:
    # - `{a: [..]}`
    # - `{b: [..]}`
    # - `{a: [..], b: [..]}`
    all_invalid_values = all_combinations(invalid_values_items)

    # Expand the generate test. E.g. {a: [1,2], b:[3,4]} will produce:
    # - {a: 1, b:3}
    # - {a: 1, b:4}
    # - {a: 2, b:3}
    # - {a: 2, b:4}
    for invalid_values in all_invalid_values:
        # expand the value list `(key, [v1,v2])` to `((key, v1), (key, v2))`
        keys_values = (
            product((key,), values)
            for key, values in invalid_values
        )

        # now make the cartesian product of all possible invalid keys and values
        invalid_instances = product(*keys_values)

        for instance in invalid_instances:
            yield dict(instance)
