from typing import Sequence

import structlog
from gevent import Greenlet

log = structlog.get_logger(__name__)


class Runnable:
    """Greenlet-like class, __run() inside one, but can be stopped and restarted

    Allows subtasks to crash self, and bubble up the exception in the greenlet
    In the future, when proper restart is implemented, may be replaced by actual greenlet
    """
    greenlet: Greenlet = None
    args: Sequence = tuple()  # args for _run()
    kwargs: dict = dict()  # kwargs for _run()

    def __init__(self, run=None, *args, **kwargs):
        if run is not None:
            self._run = run
        self.args = args
        self.kwargs = kwargs

        self.greenlet = Greenlet(self._run, *self.args, **self.kwargs)
        self.greenlet.name = f'{self.__class__.__name__}|{self.greenlet.name}'

    def start(self):
        """ Synchronously start task

        Reimplements in children an call super().start() at end to start _run()
        Start-time exceptions may be raised
        """
        if self.greenlet:
            raise RuntimeError(f'Greenlet {self.greenlet!r} already started')
        pristine = (
            not self.greenlet.dead and
            tuple(self.greenlet.args) == tuple(self.args) and
            self.greenlet.kwargs == self.kwargs
        )
        if not pristine:
            self.greenlet = Greenlet(self._run, *self.args, **self.kwargs)
            self.greenlet.name = f'{self.__class__.__name__}|{self.greenlet.name}'
        self.greenlet.start()

    def _run(self, *args, **kwargs):
        """ Reimplements in children to busy wait here

        This busy wait should be finished gracefully after stop(),
        or be killed and re-raise on subtasks exception """
        raise NotImplementedError

    def stop(self):
        """ Synchronous stop, gracefully tells _run() to exit

        Should wait subtasks to finish.
        Stop-time exceptions may be raised, run exceptions should not (accessible via get())
        """
        raise NotImplementedError

    def on_error(self, subtask: Greenlet):
        """ Default callback for substasks link_exception

        Default callback re-raises the exception inside _run() """
        log.error(
            'Runnable subtask died!',
            this=self,
            running=bool(self),
            subtask=subtask,
            exc=subtask.exception,
        )
        if not self.greenlet:
            return
        self.greenlet.kill(subtask.exception)

    # redirect missing members to underlying greenlet for compatibility
    # but better use greenlet directly for now, to make use of the c extension optimizations
    def __getattribute__(self, name):
        try:
            return super().__getattribute__(name)
        except AttributeError as ex:
            try:
                return getattr(self.greenlet, name)
            except AttributeError:
                raise ex from None

    def __bool__(self):
        return bool(self.greenlet)
