import gc
import os
from itertools import chain, combinations, count, product

import gevent


def unique_path(initial_path: str) -> str:
    """Creates a new path name based on `initial_path`.

    This is necessary to separate the logs of consecutive runs done by
    pytest-flaky.

    Because we use `tmpdir` to generate the `initial_path` on local runs, and
    that fixture automatically creates the directories. We have to use a marker
    inside the folder instead of the folder itself as a way of detecting if a
    new path should be generated.
    """
    proposed_path = initial_path
    marker_path = os.path.join(proposed_path, "used")

    counter = count()
    while os.path.exists(marker_path):
        # Adding ## before the number to differenciate from the tests
        # parametrized arguments
        number = f"##{next(counter)}"
        proposed_path = f"{initial_path[:-len(number)]}{number}"
        marker_path = os.path.join(proposed_path, "used")

    # The folder may exist if it is the first run locally, so it is okay if the
    # directory exists, otherwise create it.
    os.makedirs(proposed_path, exist_ok=True)

    # Create the empty marker file, this will force a new path on the next run.
    with open(marker_path, "w"):
        pass

    return proposed_path


def cleanup_tasks():
    tasks = [
        running_task
        for running_task in gc.get_objects()
        if isinstance(running_task, gevent.Greenlet)
    ]
    gevent.killall(tasks)
    gevent.hub.reinit()


def shutdown_apps_and_cleanup_tasks(raiden_apps):
    for app in raiden_apps:
        app.stop()

    # Two tests in sequence could run a server on the same port, a hanging
    # greenlet from the previous tests could send packet to the new server and
    # mess things up. Kill all greenlets to make sure that no left-over state
    # from a previous test interferes with a new one.
    cleanup_tasks()


def all_combinations(values):
    """Returns all possible combinations, from length 1 up to full-length of
    values.
    """
    all_generators = (combinations(values, r) for r in range(1, len(values)))
    flat = chain.from_iterable(all_generators)
    return flat


def fixture_all_combinations(invalid_values):
    """Generate all combinations for testing invalid values.

    `pytest.mark.parametrize` will generate the combination of the full-length
    values, this is not sufficient for an exhaustive failing test with default
    values, example::

        @pytest.mark.parametrize('x', [0, 1])
        @pytest.mark.parametrize('y', [2, 3])
        def test_foo(x, y):
            with pytest.raises(Exception):
                # failing computation with x and y

    The above test will generate 4 tests {x:0,y:2}, {x:0,y:3}, {x:1,y:2}, and
    {x:1,y:3}, but it will not generate a scenario for x and y alone {x:0},
    {x:1}, {y:2}, {y:3}.
    """
    # all_combinations needs an object with length
    invalid_values_items = list(invalid_values.items())

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
    for invalid_combinations in all_invalid_values:
        # expand the value list `(key, [v1,v2])` to `((key, v1), (key, v2))`
        keys_values = (product((key,), values) for key, values in invalid_combinations)

        # now make the cartesian product of all possible invalid keys and values
        invalid_instances = product(*keys_values)

        for instance in invalid_instances:
            yield dict(instance)
