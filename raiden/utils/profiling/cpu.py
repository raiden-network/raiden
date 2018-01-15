# -*- coding: utf-8 -*-
import os
from datetime import datetime

import gevent_profiler
import GreenletProfiler


class CpuProfiler:
    def __init__(self, datadir):
        self.profiling = False
        self.datadir = datadir

    def start(self):
        if self.profiling:
            return

        # create a new file every time instead of overwritting the latest profiling
        summary_file = '{:%Y%m%d_%H%M}_profile_summary'.format(datetime.now())
        stats_file = '{:%Y%m%d_%H%M}_profile_stats'.format(datetime.now())

        summary_path = os.path.join(self.datadir, summary_file)
        stats_path = os.path.join(self.datadir, stats_file)

        gevent_profiler.set_trace_output(None)
        gevent_profiler.set_summary_output(summary_path)
        gevent_profiler.set_stats_output(stats_path)

        GreenletProfiler.set_clock_type('cpu')
        GreenletProfiler.start()
        # gevent_profiler.attach()

        self.profiling = True

    def stop(self):
        if not self.profiling:
            return

        GreenletProfiler.stop()
        # gevent_profiler.detach()

        greenlet_file = '{:%Y%m%d_%H%M}_profile_greenlet.callgrind'.format(datetime.now())
        greenlet_path = os.path.join(self.datadir, greenlet_file)

        stats = GreenletProfiler.get_func_stats()
        stats.print_all()
        stats.save(greenlet_path, type='callgrind')

        self.profiling = False

    def toogle(self):
        if self.profiling:
            self.stop()
        else:
            self.start()
