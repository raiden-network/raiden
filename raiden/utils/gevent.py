from typing import Any, Callable

from gevent import Greenlet


def spawn_named(name: str, task: Callable, *args: Any, **kwargs: Any) -> Greenlet:
    """ Helper function to spawn a greenlet with a name. """

    greenlet = Greenlet(task, *args, **kwargs)
    greenlet.name = name

    greenlet.start()

    return greenlet
