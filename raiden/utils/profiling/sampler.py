import collections
import os
import pickle
import sys
import threading
import time

import greenlet
import objgraph
import psutil

from .constants import INTERVAL_SECONDS, MEGA
from .timer import TIMER, TIMER_SIGNAL, Timer

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


def sample_stack(stack_count, frame):
    callstack = []
    while frame is not None:
        callstack.append(frame_format(frame))
        frame = frame.f_back

    formatted_stack = ';'.join(reversed(callstack))
    stack_count[formatted_stack] += 1


def process_memory_mb(pid):
    process = psutil.Process(pid)
    memory = process.memory_info()[0]
    for child in process.children(recursive=True):
        memory += child.memory_info()[0]
    return memory / MEGA


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


class FlameGraphCollector:
    def __init__(self, stack_stream):
        self.stack_stream = stack_stream
        self.stack_count = collections.defaultdict(int)

    def collect(self, frame, _ts):
        sample_stack(self.stack_count, frame)

    def stop(self):
        stack_data = flamegraph_format(self.stack_count)

        self.stack_stream.write(stack_data)
        self.stack_stream.close()
        self.stack_stream = None


class MemoryCollector:
    def __init__(self, memory_stream):
        self.memory_stream = memory_stream

    def collect(self, _frame, timestamp):
        # waiting for the cache to fill takes too long, just flush the data
        sample_memory(timestamp, os.getpid(), self.memory_stream)
        self.memory_stream.flush()

    def stop(self):
        self.memory_stream.close()
        self.memory_stream = None


class ObjectCollector:
    def __init__(self, objects_stream):
        self.objects_stream = objects_stream

    def collect(self, _frame, timestamp):
        sample_objects(timestamp, self.objects_stream)
        self.objects_stream.flush()

    def stop(self):
        self.objects_stream.close()
        self.objects_stream = None


class TraceSampler:
    def __init__(self, collector, sample_interval=0.1):
        self.collector = collector
        self.sample_interval = sample_interval
        self.last_timestamp = time.time()

        greenlet.settrace(self._greenlet_profiler)  # pylint: disable=c-extension-no-member
        sys.setprofile(self._thread_profiler)
        # threading.setprofile(self._thread_profiler)

    def _should_sample(self, timestamp):
        if timestamp - self.last_timestamp >= self.sample_interval:
            self.last_timestamp = timestamp
            return True
        return False

    def _greenlet_profiler(self, _event, _args):
        timestamp = time.time()
        if self._should_sample(timestamp):
            try:
                # we need to account the time for the user function
                frame = sys._getframe(1)  # pylint:disable=protected-access
            except ValueError:
                # the first greenlet.switch() and when the greenlet is being
                # destroied there is nothing more in the stack, so this function is
                # the first function called
                frame = sys._getframe(0)  # pylint:disable=protected-access

            self.collector.collect(frame, timestamp)

    def _thread_profiler(self, frame, _event, _arg):
        timestamp = time.time()
        if self._should_sample(timestamp):
            self.collector.collect(frame, timestamp)

    def stop(self):
        # Unregister the profiler in this order, otherwise we will have extra
        # measurements in the end
        sys.setprofile(None)
        threading.setprofile(None)
        greenlet.settrace(None)  # pylint: disable=c-extension-no-member

        self.collector.stop()
        self.collector = None


class SignalSampler:
    """ Signal based sampler. """

    def __init__(
            self,
            collector,
            timer=TIMER,
            interval=INTERVAL_SECONDS,
            timer_signal=TIMER_SIGNAL,
    ):

        self.collector = collector
        # The timer must be started after collector is set
        self.timer = Timer(
            callback=self._timer_callback,
            timer=timer,
            interval=interval,
            timer_signal=timer_signal,
        )

    def _timer_callback(self, signum, frame):  # pylint: disable=unused-argument
        # Sample can be called one last time after sample_stop
        if self.collector is not None:
            self.collector.collect(frame, time.time())

    def stop(self):
        timer = self.timer
        collector = self.collector

        self.timer = None
        self.collector = None

        # The timer must be stoped before sampler
        timer.stop()
        collector.stop()
