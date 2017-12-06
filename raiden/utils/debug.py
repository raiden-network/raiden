# -*- coding: utf-8 -*-
import os
import signal

import gevent
from IPython.core import ultratb


def enable_greenlet_debugger():
    def _print_exception(self, context, type_, value, traceback):
        ultratb.VerboseTB(call_pdb=True)(type_, value, traceback)
        resp = input('Debugger exited. Do you want to quit raiden? [Y/n] ').strip().lower()

        if not resp or resp.startswith('y'):
            os.kill(os.getpid(), signal.SIGTERM)

    gevent.get_hub().__class__.print_exception = _print_exception
