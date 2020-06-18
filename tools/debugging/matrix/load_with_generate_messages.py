#!/usr/bin/env python
from gevent import monkey  # isort:skip

monkey.patch_all()  # isort:skip

import asyncio  # isort:skip # noqa
from raiden.network.transport.matrix.rtc import aiogevent  # isort:skip # noqa

asyncio.set_event_loop_policy(aiogevent.EventLoopPolicy())  # isort:skip # noqa

import argparse
import os
import time
from dataclasses import dataclass
from typing import Iterator, List

from raiden.utils.nursery import Janitor, Nursery

CWD = os.path.dirname(os.path.abspath(__file__))
GENERATE_MESSAGES_SCRIPT = os.path.join(CWD, "generate_messages.py")


@dataclass
class Config:
    logdir: str
    sender_matrix_server_url: str
    receiver_matrix_server_url: str
    target_qty_of_chat_rooms: int
    qty_of_new_rooms_per_iteration: int
    concurrent_messages_per_room: int
    wait_before_next_iteration: float


def batch_size(target: int, step: int) -> Iterator[int]:
    iterations = target // step

    for _ in range(iterations):
        yield step

    rest = target % step
    if rest:
        yield rest


def run(config: Config, nursery: Nursery) -> None:
    for i, qty_of_rooms in enumerate(
        batch_size(config.target_qty_of_chat_rooms, config.qty_of_new_rooms_per_iteration)
    ):
        log_file = os.path.join(config.logdir, str(i))
        script_args: List[str] = [
            GENERATE_MESSAGES_SCRIPT,
            "--concurrent-messages",
            str(config.concurrent_messages_per_room),
            "--chat-rooms",
            str(qty_of_rooms),
            log_file,
            config.sender_matrix_server_url,
            config.receiver_matrix_server_url,
        ]

        nursery.exec_under_watch(script_args)

        time.sleep(config.wait_before_next_iteration)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--wait-before-next-iteration", type=int, default=60)
    parser.add_argument("target_qty_of_chat_rooms", type=int, default=500)
    parser.add_argument("qty_of_new_rooms_per_iteration", type=int, default=10)
    parser.add_argument("concurrent_messages_per_room", type=int, default=50)
    parser.add_argument("logdir", help="Directory used to save the script logs.")
    parser.add_argument("server", help="Matrix server used by the sender user.")
    parser.add_argument(
        "server2",
        help=(
            "If provided, the server used by the receiever, otherwise the same "
            "server as the sender is used."
        ),
        default=None,
        nargs="?",
    )
    args = parser.parse_args()
    logdir = args.logdir

    os.makedirs(logdir, exist_ok=True)

    sender_matrix_server_url = args.server
    receiver_matrix_server_url = args.server2 or args.server

    config = Config(
        logdir=logdir,
        sender_matrix_server_url=sender_matrix_server_url,
        receiver_matrix_server_url=receiver_matrix_server_url,
        target_qty_of_chat_rooms=args.target_qty_of_chat_rooms,
        qty_of_new_rooms_per_iteration=args.qty_of_new_rooms_per_iteration,
        concurrent_messages_per_room=args.concurrent_messages_per_room,
        wait_before_next_iteration=args.wait_before_next_iteration,
    )

    with Janitor() as nursery:
        nursery.spawn_under_watch(run, config, nursery)
        nursery.wait(timeout=None)


if __name__ == "__main__":
    main()
