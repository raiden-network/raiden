# -*- coding: utf-8 -*-
import signal

from .constants import INTERVAL_SECONDS

# TIMER_SIGNAL = signal.SIGALRM
# TIMER =  signal.ITIMER_REAL
# TIMER_SIGNAL = signal.SIGVTALRM
# TIMER =  signal.ITIMER_VIRTUAL
TIMER = signal.ITIMER_PROF
TIMER_SIGNAL = signal.SIGPROF


class Timer:
    def __init__(
            self,
            callback,
            timer=TIMER,
            interval=INTERVAL_SECONDS,
            timer_signal=TIMER_SIGNAL):

        assert callable(callback), 'callback must be callable'

        signal.signal(timer_signal, self.callback)
        signal.setitimer(timer, interval, interval)

        oldtimer, oldaction = None, None  # cheating for now
        self.oldaction = oldaction
        self.oldtimer = oldtimer
        self._callback = callback

    def callback(self, signum, stack):
        self._callback(signum, stack)

        if self.oldaction and callable(self.oldaction):
            self.oldaction(signum, stack)  # pylint: disable=not-callable

    def stop(self):
        self._callback = None

        if self.oldaction and callable(self.oldaction):
            signal.signal(TIMER_SIGNAL, self.oldaction)
            signal.setitimer(
                TIMER_SIGNAL,
                self.oldtimer[0],
                self.oldtimer[1],
            )
        else:
            signal.signal(TIMER_SIGNAL, signal.SIG_IGN)

    def __del__(self):
        self.stop()

    def __bool__(self):
        # we're always truthy
        return True
