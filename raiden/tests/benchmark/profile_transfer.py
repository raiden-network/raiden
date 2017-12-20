# -*- coding: utf-8 -*-


from collections import namedtuple

from ethereum import slogging

from raiden.settings import DEFAULT_SETTLE_TIMEOUT
from raiden.utils import sha3, profiling
from raiden.network.transport import UDPTransport
from raiden.network.discovery import Discovery
from raiden.tests.utils.network import (
    create_apps,
)
from raiden.tests.utils.tester_client import (
    BlockChainServiceTesterMock,
)
from raiden.tests.fixtures.tester import (
    tester_blockgas_limit,
    tester_channelmanager_library_address,
    tester_nettingchannel_library_address,
    tester_registry_address,
    tester_chain,
)

try:
    from termcolor import colored
except ImportError:
    def colored(text, color=None, on_color=None, attrs=None):
        return text


slogging.configure(':CRITICAL')

ProfileLine = namedtuple(
    'ProfileLine',
    (
        'recursion',
        'name',
        'calls',
        'cumulative',
        'total',
        'average',
    )
)

FORMAT_LINE = '{total:>6.4f} {cumulative:>6.4f} {avg:>6.4f} {align}{name} [{calls} calls]'


def print_stats(stat_list, total_time):
    # The GreenletProfiler is based on YAPPI, the YAPPI implementation does
    # quite a bit of calling back and forth from C to Python, the overall
    # result is as follows:
    #
    # [GreenletProfiler:start]  Registers YAPPI to profile all threads
    #                           (threading.setprofile and _yapp.start)
    # [_yappi.c:profile_event]  at each event a callback is called
    #   [_yappi.c:_call_enter/_call_leve] and the callstack is traced
    #
    # The yappi implementation can use three different clocks, cpu, rusage or
    # wall [timing.c:tickcount], there a couple of things that needs to be kept
    # track of:
    #
    # - context switches, the clock needs to be paused and restore.
    #  - If the GreenletProfiler is running for cpu time it will take care of
    #  _not_ accounting for the cpu time of other threads (it will compensate
    #  by artificially increasing the start time by the time the thread was
    #  sleeping)
    #
    # The traced data can be extract in two ways, through the enum_func_stats
    # [_yappi.c:_pitenumstat] or enum_thread_stats [_yappi.c:_ctxenumstat], each
    # will enumerate through the traced data and run a callback from C to
    # Python

    # we are trying to reconstruct the call-stack, this is used to track if
    # there are rootless calls
    call_count = {}

    nameline_stat = {}
    for stat in stat_list:
        # we cant use just name because labmda's are named "<lambda>" and will conflict
        key = (stat.name, stat.lineno)

        if key in nameline_stat:
            raise Exception('the code assumes that (name, lineno) are unique, they are not')

        nameline_stat[key] = stat

    # index is a counter increment by one every time a new function is called,
    # so it is _somewhat_ in order
    ordered_stats = sorted(stat_list, key=lambda item: item.index)

    # we need to recursivelly format the call-stack, this function is also
    # closing over variables and changing state
    def _stack(stat, recursion=0):
        key = (stat.name, stat.lineno)
        accumulated_count = call_count.get(key, 0)

        if accumulated_count >= stat.ncall:
            return []

        call_count[key] = accumulated_count + stat.ncall

        line = ProfileLine(
            recursion=recursion,
            name=stat.name,
            calls=stat.ncall,
            cumulative=stat.tsub,
            total=stat.ttot,
            average=stat.tavg,
        )

        stack = [line]

        if stat.children is not None:
            for child in stat.children:
                if child.name.endswith('switch'):
                    continue

                child_key = (child.name, child.lineno)
                child_line = _stack(nameline_stat[child_key], recursion + 1)
                stack.extend(child_line)

        return stack

    def _line(recursion):
        line = list(' ' * (recursion + 1))
        line[7::7] = len(line[7::7]) * '.'
        return ''.join(line)

    highest_time = 0
    full_stack = []
    for stat in ordered_stats:
        for line in _stack(stat):
            highest_time = max(highest_time, line.average)
            full_stack.append(line)

    cumulative_depth = float('inf')
    formated_stack = []

    print(' total   cumm single')
    for line in full_stack:

        formated_line = FORMAT_LINE.format(
            align=_line(line.recursion),
            name=line.name,
            calls=line.calls,
            total=line.total,
            cumulative=line.cumulative,
            avg=line.average,
        )

        # highlight slowest blocks
        if line.cumulative > total_time * 0.1:
            cumulative_depth = line.recursion

        if cumulative_depth >= line.recursion:
            cumulative_depth = float('inf')

        # highlight the slowest functions
        if highest_time * 0.85 <= line.average:
            formated_line = colored(formated_line, 'red')
        elif cumulative_depth <= line.recursion:
            formated_line = colored(formated_line, 'blue')

        # hide functions that wont save time after optimizing ...
        # if line.cumulative < 0.0001:
        #     continue

        formated_stack.append(formated_line)

    print('\n'.join(formated_stack))
    print('''
    total  - total wall time to run the function call (including subcalls)
    cumm   - total wall time for the function itself (removing subcalls)
    single - time spent on a _single_ execution (average time, really)
    ''')
    print('Total time: {:6.4f}s'.format(total_time))


def profile_transfer(num_nodes=10, channels_per_node=2):
    num_tokens = 1
    deposit = 10000

    tokens = [
        sha3('token:{}'.format(number).encode())[:20]
        for number in range(num_tokens)
    ]

    private_keys = [
        sha3('speed:{}'.format(position).encode())
        for position in range(num_nodes)
    ]

    blockchain_services = list()
    tester = tester_chain(
        private_keys[0],
        private_keys,
        tester_blockgas_limit(),
    )
    nettingchannel_library_address = tester_nettingchannel_library_address(
        tester_chain,
    )
    channelmanager_library_address = tester_channelmanager_library_address(
        tester_chain,
        nettingchannel_library_address,
    )
    registry_address = tester_registry_address(
        tester_chain,
        channelmanager_library_address,
    )
    for privkey in private_keys:
        blockchain = BlockChainServiceTesterMock(
            privkey,
            tester,
        )
        blockchain_services.append(blockchain)

    registry = blockchain_services[0].registry(registry_address)
    for token in tokens:
        registry.add_token(token)

    discovery_mock = Discovery()
    endpoint_discovery_services = [discovery_mock for _ in private_keys]

    apps = create_apps(
        blockchain_services,
        endpoint_discovery_services,
        registry_address,
        tokens,
        channels_per_node,
        deposit,
        DEFAULT_SETTLE_TIMEOUT,
        UDPTransport,
    )

    main_app = apps[0]

    # channels
    main_graph = main_app.raiden.token_to_channelgraph[tokens[0]]

    # search for a path of length=2 A > B > C
    num_hops = 2
    source = main_app.raiden.address
    paths = main_graph.get_paths_of_length(source, num_hops)

    # sanity check
    assert paths

    path = paths[0]
    target = path[-1]

    # addresses
    token_address = main_graph.token_address

    amount = 10

    # measure the hot path
    with profiling.profile():
        result = main_app.raiden.mediated_transfer_async(
            token_address,
            amount,
            target,
            1,
        )
        result.wait()

    profiling.print_all_threads()
    # profiling.print_merged()


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('--nodes', default=10, type=int)
    parser.add_argument('--channels-per-node', default=2, type=int)
    parser.add_argument('--pdb', action='store_true', default=False)

    args = parser.parse_args()

    if args.pdb:
        try:
            profile_transfer(
                num_nodes=args.nodes,
                channels_per_node=args.channels_per_node,
            )
        except: # noqa
            import pdb
            pdb.xpm()
    else:
        profile_transfer(
            num_nodes=args.nodes,
            channels_per_node=args.channels_per_node,
        )
