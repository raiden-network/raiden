from gevent import Greenlet
from typing import Sequence


class Runnable:
    """Greenlet-like class, run() inside one, but can be stopped and restarted

    Allows subtasks to crash self, and bubble up the exception in the greenlet
    In the future, when proper restart is implemented, may be replaced by actual greenlet
    """
    greenlet: Greenlet = None
    args: Sequence = tuple()  # args for run()
    kwargs: dict = dict()  # kwargs for run()

    def __init__(self, run=None, *args, **kwargs):
        if run is not None:
            self.run = run
        self.args = tuple(args)
        self.kwargs = kwargs

        self.greenlet = Greenlet(self.run, *self.args, **self.kwargs)
        self.greenlet.name = f'{self.__class__.__name__}|{self.greenlet.name}'

    def start(self):
        """ Synchronously start task

        Reimplements in children an call super().start() at end to start run()
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
            self.greenlet = Greenlet(self.run, *self.args, **self.kwargs)
            self.greenlet.name = f'{self.__class__.__name__}|{self.greenlet.name}'
        self.greenlet.start()

    def run(self, *args, **kwargs):
        """ Reimplements in children to busy wait here

        This busy wait should be finished gracefully after stop(),
        or be killed and re-raise on subtasks exception """
        raise NotImplementedError

    def stop(self):
        """ Synchronous stop, gracefully tells run() to exit

        May wait subtasks to finish.
        Stop-time exceptions may be raised, run exceptions should not (accessible via get())
        """
        raise NotImplementedError

    def on_error(self, subtask: Greenlet):
        """ Default callback for substasks link_exception

        Default callback re-raises the exception inside run() """
        if not self.greenlet:
            return
        self.greenlet.kill(subtask.exception)

    # redirect missing members to underlying greenlet for compatibility
    # but better use greenlet directly for now, to make use of the c extension optimizations
    def __getattr__(self, name):
        return getattr(self.greenlet, name)

    def __bool__(self):
        return bool(self.greenlet)
