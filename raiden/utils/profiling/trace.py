# -*- coding: utf-8 -*-
import gc
import os
import pickle
import time
from datetime import datetime
import tracemalloc

from .timer import Timer
from .constants import MINUTE


def _serialize_statistics(statistics):
    traceback = [
        frame._frame  # pylint: disable=protected-access
        for frame in statistics.traceback
    ]
    return (statistics.count, statistics.size, traceback)


class TraceProfiler:
    def __init__(self, datadir):
        self.datadir = datadir
        self.profiling = False
        self.trace_stream = None
        self.timer = None

    def trace(self, signum, frame):  # pylint: disable=unused-argument
        """ Signal handler used to take snapshots of the running process. """

        # the last pending signal after trace_stop
        if not self.profiling:
            return

        gc.collect()

        snapshot = tracemalloc.take_snapshot()
        timestamp = time.time()
        sample_data = (timestamp, snapshot)

        # *Must* use the HIGHEST_PROTOCOL, otherwise the serialization will
        # use GBs of memory
        pickle.dump(sample_data, self.trace_stream, protocol=pickle.HIGHEST_PROTOCOL)
        self.trace_stream.flush()

    def toggle(self):
        if not self.profiling:
            self.start()
        else:
            self.stop()

    def start(self):
        if self.profiling:
            return

        self.profiling = True

        now = datetime.now()
        trace_file = '{:%Y%m%d_%H%M}_trace.pickle'.format(now)
        trace_path = os.path.join(self.datadir, trace_file)
        self.trace_stream = open(trace_path, 'w')
        tracemalloc.start(15)

        # Take snapshots at slower pace because the size of the samples is not
        # negligible, the de/serialization is slow and uses lots of memory.
        self.timer = Timer(self.trace, interval=MINUTE * 5)

    def stop(self):
        if not self.profiling:
            return

        self.profiling = False

        tracemalloc.stop()
        self.timer.stop()
        self.trace_stream.close()
        self.trace_stream = None
        self.timer = None
