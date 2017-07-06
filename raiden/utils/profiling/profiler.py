# -*- coding: utf-8 -*-
from __future__ import print_function

import contextlib
import sys
import threading
import time
from collections import OrderedDict, namedtuple
from itertools import chain, izip_longest

import greenlet

from raiden.utils.profiling.stack import get_trace_info, get_trace_from_frame


# TODO:
#  - sys.callstats()
#  - calibration
#  - at least write good docs about clocks, problems:
#     - clock precision
#     - clock sckew between cores (if the proccess is not bound to a core this can be a problem)
#     - syscalls and linux's vdso
#     - wall time vs. cpu time
#     - monotonic clock
#     - https://www.python.org/dev/peps/pep-0418/

# this variable holds the global state of the profiler, while it is running
_state = None

# about the measurements:
# - GreenletProfiler/YAPPI uses a configurable clock to get the time (wall or cpu)
# - gevent_profiler uses time.time()

# The stdlib profile.py has the following comment about clock
#       Using getrusage(3) is better than clock(3) if available [...] getrusage has a
#       higher resolution
# But throught testing I found the precision of getrusage to be terrible, using
# time.clock() instead

# "this is the function to use for benchmarking Python or timing algorithms"
#       https://docs.python.org/2/library/time.html#time.clock

# PEP-0418
#        perf_counter = It does include time elapsed during sleep and is system-wide.
try:
    clock = time.perf_counter  # pylint: disable=no-member
except:
    clock = time.clock

# info is used to store the function name/module/lineno
# children is an OrderedDict with function id -> CallNode
# parent is the node that resulted in this call
CallNode = namedtuple('CallNode', ('info', 'children', 'parent'))
MergeNode = namedtuple('MergeNode', ('info', 'children'))


def _copy_call(call):
    call = dict(call)

    call.setdefault('calls', 0)
    # wall time
    call.setdefault('wall_enter_time', list())
    call.setdefault('wall_exit_time', list())
    # wall time (when a switch happened)
    call.setdefault('sleep_start_time', list())
    call.setdefault('sleep_end_time', list())
    # wall time (when a subcall is made)
    call.setdefault('subcall_enter_time', list())
    call.setdefault('subcall_exit_time', list())

    return call


def ensure_call(curr, call):
    ''' Returns an existing entry of call or create a new one. '''
    id_ = call['runtime_id']

    if id_ not in curr.children:
        # XXX: do we have a leak with curr?
        curr.children[id_] = CallNode(_copy_call(call), OrderedDict(), curr)

    return curr.children[id_]


def ensure_thread_state(target, frame):
    if target not in _state:
        frame = frame
        trace = get_trace_from_frame(frame)
        _state[target] = ThreadState(target.__class__.__name__, trace)

    return _state[target]


def zip_both(first, second):
    data = []
    for one, two in zip(first, second):
        if one and two:
            data.append((one, two))
    return data


def calculate_metrics(info):
    info = dict(info)

    wall_data = zip_both(info['wall_enter_time'], info['wall_exit_time'])
    sleep_data = zip_both(info['sleep_start_time'], info['sleep_end_time'])
    subcall_data = zip_both(info['subcall_enter_time'], info['subcall_exit_time'])

    accumulated, min_, max_ = 0, float('inf'), 0
    avg, count = None, None

    if wall_data:
        for start, exit in wall_data:
            run_time = exit - start
            accumulated += run_time
            min_ = min(min_, run_time)
            max_ = max(max_, run_time)

        if accumulated:
            count = len(wall_data)
            avg = accumulated / count

    sleep = 0
    if sleep_data:
        for start, exit in sleep_data:
            sleep += exit - start

    subcall_time = 0
    if subcall_data:
        for start, exit in subcall_data:
            subcall_time += exit - start

    inline = 0
    if accumulated:
        inline = accumulated - subcall_time - sleep

    info['sleep'] = sleep
    info['accumulated'] = accumulated
    info['subcall_time'] = subcall_time
    info['inline'] = inline
    info['min'] = min_
    info['max'] = max_
    info['avg'] = avg
    info['profiled_calls'] = count

    return info


class GlobalState(dict):
    ''' This class is responsable to store the state of a profiling session '''
    def __init__(self, *args, **kwargs):
        super(GlobalState, self).__init__(*args, **kwargs)
        self.last = None


class ThreadState(object):
    ''' This class is responsable to store the state of an execution thread,
    that can be a native thread, with a 1-to-1 mapping between userland and
    kernel space, or a light thread with a n-to-1, be it cooperative or not.

    This will store not trace every single line but the call's and return's in
    the code.
    '''
    def __init__(self, name, trace):
        self.root = CallNode({}, OrderedDict(), None)  # the root node is empty
        self.calltree = self.root
        self.curr = self.calltree
        self.context_switch = 0
        self.name = name

        if trace:
            self.depth = len(trace) - 1

            for call in trace:
                self.curr = ensure_call(self.curr, call)

    @property
    def total_accumulated(self):
        ''' Returns the top most stack that has a wall time measurement '''

        accumulated, top_depth = 0.0, None
        for depth, node in self.depthorder():
            if accumulated and top_depth != depth:
                return accumulated

            if node['accumulated']:
                top_depth = depth
                accumulated += node['accumulated']

    def call_enter(self, call, now):
        node = ensure_call(self.curr, call)

        node.info['calls'] += 1
        node.info['wall_enter_time'].append(now)

        # this could be the root node, but that is not a problem
        self.curr.info['subcall_enter_time'].append(now)

        self.curr = node

    def call_exit(self, call, now):
        info = self.curr.info

        info['wall_exit_time'].append(now)
        if len(info['wall_exit_time']) > len(info['wall_enter_time']):
            info['wall_enter_time'].append(None)

        parent_info = self.curr.parent.info
        parent_info['subcall_exit_time'].append(now)
        if len(parent_info['subcall_exit_time']) > len(parent_info['subcall_enter_time']):
            parent_info['subcall_enter_time'].append(None)

        self.curr = self.curr.parent

    def switch_enter(self, now):
        assert self.root != self.curr, 'switch_enter must be called on a initialized ThreadState'

        info = self.curr.info
        info['sleep_start_time'].append(now)

    def switch_exit(self, now):
        assert self.root != self.curr, 'switch_enter must be called on a initialized ThreadState'

        info = self.curr.info
        info['sleep_end_time'].append(now)
        if len(info['sleep_end_time']) > len(info['sleep_start_time']):
            info['sleep_start_time'].append(None)

    def depthorder(self):
        ''' Returns a generator that does stack traversal stepping in the depth order. '''
        iterators = [
            (1, self.root.children[key])
            for key in self.root.children  # the root node doesnt have data
        ]

        while iterators:
            depth, node = iterators.pop(0)

            info = calculate_metrics(node.info)
            yield depth, info

            if node.children:
                children = [
                    (depth + 1, node.children[key])
                    for key in node.children
                ]

                # this is one level deeper, to the children need to go to the
                # end of the iterators, also the order should be from newest to
                # oldest
                iterators.extend(children)

    def traverse(self):
        ''' Returns a generator that does stack travesal using order of appearance (inorder). '''
        iterators = [
            (1, self.root.children[key])
            for key in self.root.children
        ]

        while iterators:
            depth, node = iterators.pop()

            info = calculate_metrics(node.info)
            yield depth, info

            if node.children:
                children = [
                    (depth + 1, node.children[key])
                    for key in node.children
                ]

                # the newest need to be in the end because we use pop()
                iterators.extend(children[::-1])


def thread_profiler(frame, event, arg):
    global _state

    now = clock()  # measure once and reuse it

    current_greenlet = greenlet.getcurrent()  # pylint: disable=no-member
    current_state = ensure_thread_state(current_greenlet, frame)

    if _state.last != current_state:
        current_state.context_switch += 1
        _state.last = current_state

    if event in ('c_call', 'c_return', 'c_exception'):
        # The frame is of the python callee
        call = {
            'function': arg.__name__,
            'module': arg.__module__ or '__builtin__',
            'lineno': '',
            'abs_path': '',
            'filename': '',
            'runtime_id': id(arg),
        }
    else:
        call = get_trace_info(frame)

    if event in ('call', 'c_call'):
        current_state.call_enter(call, now)
    elif event in ('return', 'c_return', 'c_exception'):
        current_state.call_exit(call, now)

    return thread_profiler


def greenlet_profiler(event, args):
    if event in ('switch', 'throw'):  # both events are in the target context
        now = clock()

        try:
            # we need to account the time for the user function
            frame = sys._getframe(1)
        except ValueError:
            # the first greenlet.switch() and when the greenlet is being
            # destroied there is nothing more in the stack, so this function is
            # the first function called
            frame = sys._getframe(0)

        origin, target = args

        origin_state = _state[origin]
        target_state = ensure_thread_state(target, frame)

        origin_state.switch_enter(now)  # origin is entering the "sleep" state
        target_state.switch_exit(now)   # target might be leaving the "sleep"


def start_profiler():
    global _state

    _state = GlobalState()

    frame = sys._getframe(0)
    current_greenlet = greenlet.getcurrent()  # pylint: disable=no-member

    thread_state = ensure_thread_state(current_greenlet, frame)
    _state.last = thread_state

    # this needs to be instantiate before the handler is installed
    greenlet.settrace(greenlet_profiler)  # pylint: disable=no-member
    sys.setprofile(thread_profiler)
    threading.setprofile(thread_profiler)


def stop_profiler():
    # we keep the _state around for the user until the next session

    # Unregister the profiler in this order, otherwise we will have extra
    # measurements in the end
    sys.setprofile(None)
    threading.setprofile(None)
    greenlet.settrace(None)  # pylint: disable=no-member


@contextlib.contextmanager
def profile():
    start_profiler()
    yield
    stop_profiler()


def zip_outter_join(equal, *element_list):
    ''' Returns a list with equal elements grouped, were elements considered
    equal will be in the same tuple '''

    if not callable(equal):
        raise ValueError('equal must be a callable')

    length = len(element_list)
    result = [list() for __ in range(length)]

    # do it all in one swipe
    for iteration in izip_longest(*element_list):
        # the done flag is set when the element is used, this can happen either
        # because the element was equal to another one or because it is the
        # element turn in the search
        done = [False] * length

        while not all(done):
            # get the next element, index() will return the first index from
            # left to right, so we are keeping this order
            base_pos = done.index(False)
            done[base_pos] = True
            base = iteration[base_pos]
            equals = [None] * length
            equals[base_pos] = base

            if base is None:
                continue

            for pos, (element_done, element) in enumerate(zip(done, iteration)):
                if element is None:
                    continue

                if not element_done and equal(base, element):
                    equals[pos] = element
                    done[pos] = True

            result[base_pos].append(equals)

    return list(chain.from_iterable(result))


def merge_info(*allinfo):
    def _info_to_list(infodata, field):
        iterable = chain.from_iterable(info[field] for info in allinfo)
        return list(iterable)

    allinfo = list(allinfo)
    # guarantee that the metrics are calculated
    for pos, info in enumerate(allinfo):
        allinfo[pos] = calculate_metrics(info)

    result = dict(allinfo[0])

    # keep this data in case we need to call calculate_metrics again, preserve the order
    result['calls'] = sum(info['calls'] for info in allinfo)

    result['wall_enter_time'] = _info_to_list(allinfo, 'wall_enter_time')
    result['wall_exit_time'] = _info_to_list(allinfo, 'wall_exit_time')
    result['sleep_start_time'] = _info_to_list(allinfo, 'sleep_start_time')
    result['sleep_end_time'] = _info_to_list(allinfo, 'sleep_end_time')
    result['subcall_enter_time'] = _info_to_list(allinfo, 'subcall_enter_time')
    result['subcall_exit_time'] = _info_to_list(allinfo, 'subcall_exit_time')

    result['sleep'] = sum(info['sleep'] for info in allinfo)
    result['accumulated'] = sum(info['accumulated'] for info in allinfo)
    result['subcall_time'] = sum(info['subcall_time'] for info in allinfo)
    result['inline'] = sum(info['inline'] for info in allinfo)
    result['min'] = min(info['min'] for info in allinfo)
    result['max'] = max(info['max'] for info in allinfo)

    # if one element is None convert the result to None
    if all(info['profiled_calls'] for info in allinfo):
        result['profiled_calls'] = sum(info['profiled_calls'] for info in allinfo)
    else:
        result['profiled_calls'] = None

    if all(info['avg'] for info in allinfo):
        result['avg'] = sum(info['avg'] for info in allinfo) / len(allinfo)
    else:
        result['avg'] = None

    return result


def merge_threadstates(*threadstates):
    ''' Merge the profile data from first and second, the result will _not_ be
    a ThreadState
    '''

    def equal(first_node, second_node):
        runtime_id = first_node.info['runtime_id'] == second_node.info['runtime_id']
        module = first_node.info['module'] == second_node.info['module']
        function = first_node.info['function'] == second_node.info['function']

        return (module and function) or runtime_id

    tree = [
        (1, {}, [state.calltree for state in threadstates])
    ]

    while tree:
        depth, curr, callnodes = tree.pop()

        yield depth, curr

        # CallNode.children is an OrderedDict
        children = [
            node.children.values()
            for node in callnodes
        ]

        # XXX: create a version of outter_join were the order is not essential,
        # so the first element is compared with all others and if there are any
        # equal it is merged

        extend_search = []
        for nodes_joined in zip_outter_join(equal, *children):
            nodes_joined = filter(None, nodes_joined)
            info_merged = merge_info(*(node.info for node in nodes_joined))
            extend_search.append((depth + 1, info_merged, nodes_joined))

        # do the search inorder
        tree.extend(extend_search[::-1])


def print_info(depth, info):
    def _line(recursion):
        line = list(' ' * (recursion + 1))
        line[7::7] = len(line[7::7]) * '.'
        return ''.join(line)

    inline = ' ' * 8
    accumulated = ' ' * 8
    sleep = ' ' * 8

    if 'accumulated' in info:
        accumulated = '{:>8.6f}'.format(info['accumulated'])

        if 'inline' in info:
            inline = '{:>8.6f}'.format(info['inline'])

    if 'sleep' in info:
        sleep = '{:>8.6f}'.format(info['sleep'])

    align = _line(depth)
    line = '{accumulated} {inline} {sleep} {align}{module}.{function}:{line} [{calls}x]'.format(
        align=align,
        inline=inline,
        accumulated=accumulated,
        sleep=sleep,
        module=info.get('module', ''),
        function=info.get('function', ''),
        line=info.get('lineno', ''),
        calls=info.get('calls', ''),
    )
    print(line)


def print_info_tree(depth_info):
    print('   total   inline    sleep')

    # the calltree is ordered by stack height and the by call order
    for depth, info in depth_info:
        print_info(depth, info)


def filter_fast(depth_info):
    depth_info = list(depth_info)

    # filters
    acc_max, acc_min = 0, float('inf')
    inline_max, inline_min = 0, float('inf')

    for depth, info in depth_info:
        acc_max = max(info.get('accumulated', 0), acc_max)
        acc_min = min(info.get('accumulated', float('inf')), acc_min)
        inline_max = max(info.get('inline', 0), inline_max)
        inline_min = min(info.get('inline', float('inf')), inline_min)

    for depth, info in depth_info:
        yield depth, info


def print_thread_profile(thread_state):
    header = '{} [context_switches: {}, total time: {:>8.6f}]'.format(
        thread_state.name,
        thread_state.context_switch,
        thread_state.total_accumulated,
    )
    print(header)
    print_info_tree(thread_state.traverse())


def print_merged():
    global _state

    merged = merge_threadstates(*_state.values())
    print_info_tree(filter_fast(merged))


def print_all_threads():
    global _state

    for thread_state in _state.values():
        print_thread_profile(thread_state)

    print()
    print('total - time spent to execute the function')
    print('inline - time spent in the function itself')
    print('sleep - time waiting in a greenlet.switch')
    print()
    print('total and inline do not include sleep')
    print('total include subcalls while inline does not')
