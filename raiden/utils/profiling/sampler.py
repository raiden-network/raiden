# -*- coding: utf-8 -*-
import collections
from datetime import datetime
import os
import pickle
import time

import psutil
import objgraph

from .timer import Timer
from .constants import MEGA, SECOND, INTERVAL_SECONDS

# Improvements:
# - The objcount itself is not that useful, add the _sys.getsizeof_ to know the
#   amount of memory used by the type (heapy is a good alternative for this)
# - Experiment with heapy or PySizer for memory profiling / leak hunting


def frame_format(frame):
    block_name = frame.f_code.co_name
    module_name = frame.f_globals.get('__name__')
    return '{}({})'.format(block_name, module_name)


def flamegraph_format(stack_count):
    return '\n'.join('%s %d' % (key, value) for key, value in sorted(stack_count.items()))


def process_memory_mb(pid):
    process = psutil.Process(pid)
    memory = process.memory_info()[0]
    for child in process.children(recursive=True):
        memory += child.memory_info()[0]
    return memory / MEGA


def sample_stack(stack_count, frame):
    callstack = []
    while frame is not None:
        callstack.append(frame_format(frame))
        frame = frame.f_back

    formatted_stack = ';'.join(reversed(callstack))
    stack_count[formatted_stack] += 1


def sample_memory(timestamp, pid, stream):
    memory = process_memory_mb(pid)
    stream.write('{timestamp:.6f} {memory:.4f}\n'.format(
        timestamp=timestamp,
        memory=memory,
    ))


def sample_objects(timestamp, stream):
    # instead of keeping the count_per_type in memory, stream the data to a file
    # to save memory
    count_per_type = objgraph.typestats()

    # add the timestamp for plotting
    data = [timestamp, count_per_type]

    data_pickled = pickle.dumps(data)
    stream.write(data_pickled)


class SampleProfiler:
    def __init__(self, datadir):
        self.datadir = datadir

        self.profiling = False
        self.stack_count = None
        # this value will force the first call of sample() to do a sample_objects
        self.last_sample = 0
        self.profiling_start = None

        self.stack_stream = None
        self.memory_stream = None
        self.objects_stream = None
        self.memory100_stream = None
        self.timer = None

    def sample(self, signum, frame):  # pylint: disable=unused-argument
        """ Signal handler used to sample the running process. """

        # sample can be called one last time after sample_stop
        if not self.profiling:
            return

        timestamp = time.time()

        sample_stack(self.stack_count, frame)
        sample_memory(timestamp, os.getpid(), self.memory_stream)

        # a minute is to coarse for a single session
        if timestamp - self.last_sample > 1 * SECOND:
            sample_objects(timestamp, self.objects_stream)
            self.objects_stream.flush()

        # waiting for the cache to fill takes too long, just flush the data
        self.memory_stream.flush()

        self.last_sample = timestamp

    def sample_memory(self):
        if not self.memory100_stream:
            memory100_file = '{:%Y%m%d_%H%M}_memory_at_1000.data'.format(self.profiling_start)
            self.memory100_stream = open(memory100_file, 'w')

        now = time.time()
        memory = process_memory_mb(os.getpid())

        self.memory100_stream.write('{} {}\n'.format(now, memory))
        self.memory100_stream.flush()

    def toogle_sample(self):
        if not self.profiling:
            self.start()
        else:
            self.stop()

    def start(self, interval=INTERVAL_SECONDS):
        if self.profiling:
            return

        self.stack_count = collections.defaultdict(int)

        now = datetime.now()
        stack_file = '{:%Y%m%d_%H%M}_stack.data'.format(now)
        memory_file = '{:%Y%m%d_%H%M}_memory.data'.format(now)
        objects_file = '{:%Y%m%d_%H%M}_objects.pickle'.format(now)

        stack_path = os.path.join(self.datadir, stack_file)
        memory_path = os.path.join(self.datadir, memory_file)
        objects_path = os.path.join(self.datadir, objects_file)

        self.stack_stream = open(stack_path, 'w')
        self.memory_stream = open(memory_path, 'w')
        self.objects_stream = open(objects_path, 'w')

        # only start the Timer after opening the files
        self.timer = Timer(self.sample, interval=interval)
        self.profiling_start = now

        self.profiling = True

    def stop(self):
        if not self.profiling:
            return

        # Disable the Timer before tear down
        self.timer.stop()

        stack_data = flamegraph_format(self.stack_count)
        self.stack_stream.write(stack_data)

        self.memory_stream.close()
        self.stack_stream.close()

        self.timer = None
        self.memory_stream = None
        self.stack_stream = None
        self.stack_count = None

        self.profiling = False
