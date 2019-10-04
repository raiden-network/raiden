#!/usr/bin/env python
import fcntl
import os
import select
import signal
import subprocess
import sys
from typing import Any, List


def make_async(fd: int) -> None:
    fcntl.fcntl(fd, fcntl.F_SETFL, fcntl.fcntl(fd, fcntl.F_GETFL) | os.O_NONBLOCK)


def kill_child(process, dormant_signal: int, kill_after: float, kill_signal: int) -> None:
    os.kill(process.pid, dormant_signal)

    try:
        # process.wait handles timeouts and captures the exit status
        process.wait(timeout=kill_after)
    except subprocess.TimeoutExpired:
        os.kill(process.pid, kill_signal)


def read_until_exhaustion(fd: int) -> None:
    try:
        data = os.read(fd, 1024)
    except BlockingIOError:
        data = b""

    while data:
        sys.stdout.buffer.write(data)
        sys.stdout.flush()
        try:
            data = os.read(fd, 1024)
        except BlockingIOError:
            data = b""


def monitor(
    subcommand, dormant_after: float, dormant_signal: int, kill_after: float, kill_signal: int
) -> int:
    # Using a single pipe for both stderr and stdout because it allows the
    # parent process to read the child output in the correct order.
    parent_read, child_stdout_write = os.pipe()
    child_stderr_write = os.dup(child_stdout_write)

    process = subprocess.Popen(
        subcommand, stdin=subprocess.DEVNULL, stdout=child_stdout_write, stderr=child_stderr_write
    )

    # These are used by the child process only
    os.close(child_stderr_write)
    os.close(child_stdout_write)

    make_async(parent_read)

    read_targets = [parent_read]
    empty_targets: List[Any] = []

    while process.poll() is None:
        # using select because it works both on Linux and MacOS, otherwise
        # epoll and kqueue would have to be handled separtly.
        (read_list, _, _) = select.select(
            read_targets, empty_targets, empty_targets, dormant_after
        )

        # The process timedout, kill it. After the proess is killed the loop
        # will exit and the left over in the stdout will be consumed
        if not read_list:
            kill_child(process, dormant_signal, kill_after, kill_signal)

        for fd in read_list:
            read_until_exhaustion(fd)

    # Read the last bit of data after the process exited.
    for fd in read_targets:
        read_until_exhaustion(fd)

    os.close(parent_read)

    return process.poll()


def main() -> None:
    from argparse import ArgumentParser

    parser = ArgumentParser()

    Signals = signal.Signals  # pylint: disable=no-member
    signal_names = [sig.name for sig in Signals]

    parser.add_argument("--dormant-timeout", required=True, type=float)
    parser.add_argument("--dormant-signal", required=True, choices=signal_names)
    parser.add_argument("--kill-timeout", required=True, type=float)
    parser.add_argument("--kill-signal", required=True, choices=signal_names)

    args, subcommand = parser.parse_known_args()

    dormant_signal_number = getattr(Signals, args.dormant_signal)
    kill_signal_number = getattr(Signals, args.kill_signal)

    exit_status = monitor(
        subcommand=subcommand,
        dormant_after=args.dormant_timeout,
        dormant_signal=dormant_signal_number,
        kill_after=args.kill_timeout,
        kill_signal=kill_signal_number,
    )
    sys.exit(exit_status)


if __name__ == "__main__":
    main()
