from signal import _HANDLER, _SIGNUM
from typing import Any

from gevent.greenlet import Greenlet as Greenlet, joinall as joinall
from gevent.hub import GreenletExit as GreenletExit, sleep as sleep

spawn = Greenlet.spawn

class signal(object):
    def __init__(
        self, signalnum: _SIGNUM, handler: _HANDLER, *args: Any, **kwargs: Any
    ) -> _HANDLER: ...
