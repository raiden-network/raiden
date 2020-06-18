#!/usr/bin/env python
import gevent.monkey  # isort:skip # noqa

gevent.monkey.patch_all()  # isort:skip # noqa

import asyncio  # isort:skip # noqa
from raiden.network.transport.matrix.rtc import aiogevent  # isort:skip # noqa

asyncio.set_event_loop_policy(aiogevent.EventLoopPolicy())  # isort:skip # noqa

import argparse
import json
import logging.config
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from itertools import repeat

import structlog
from gevent.pool import Pool

from raiden.network.transport.matrix.client import GMatrixClient, MatrixSyncMessages, Room, User
from raiden.network.transport.matrix.utils import login
from raiden.settings import (
    DEFAULT_TRANSPORT_MATRIX_SYNC_LATENCY,
    DEFAULT_TRANSPORT_MATRIX_SYNC_TIMEOUT,
)
from raiden.tests.utils import factories
from raiden.utils.signer import Signer
from raiden.utils.typing import Any, Dict, Iterator, RoomID

log = structlog.get_logger(__name__)

STARTED = "started: "
FINISHED = "finished: "
RECEIVED = "received: "

INVITE = "invite"
MESSAGE = "message"
USER = "user"
ROOM = "room"


def configure_logging(log_path: str) -> None:
    processors = [
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="%Y-%m-%d %H:%M:%S.%f"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
    ]
    structlog.reset_defaults()
    logging.config.dictConfig(
        {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "colorized-formatter": {
                    "()": structlog.stdlib.ProcessorFormatter,
                    "processor": structlog.dev.ConsoleRenderer(colors=True),
                    "foreign_pre_chain": processors,
                },
                "json": {
                    "()": structlog.stdlib.ProcessorFormatter,
                    "processor": structlog.processors.JSONRenderer(),
                    "foreign_pre_chain": processors,
                },
            },
            "handlers": {
                "colorized-handler": {
                    "class": "logging.StreamHandler",
                    "level": "DEBUG",
                    "formatter": "colorized-formatter",
                },
                "debug-info": {
                    "class": "logging.FileHandler",
                    "filename": log_path,
                    "level": "DEBUG",
                    "formatter": "json",
                },
            },
            "loggers": {"": {"handlers": ["colorized-handler", "debug-info"], "propagate": True}},
        }
    )
    structlog.configure(
        processors=processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        logger_factory=structlog.stdlib.LoggerFactory(),
    )
    log.setLevel("DEBUG")


@dataclass
class LoggedUser:
    client: GMatrixClient
    signer: Signer
    user: User


@dataclass
class Config:
    sender_matrix_server_url: str
    receiver_matrix_server_url: str
    number_of_concurrent_chat_rooms: int
    number_of_concurrent_messages: int
    number_of_users: int = field(init=False)
    number_of_parallel_messages: int = field(init=False)

    def __post_init__(self) -> None:
        self.number_of_users = self.number_of_concurrent_chat_rooms * 2
        self.number_of_parallel_messages = (
            self.number_of_concurrent_chat_rooms * self.number_of_concurrent_messages
        )


@contextmanager
def logtime(msg: str, *args: Any, **kwargs: Any) -> Iterator[Dict[str, Any]]:
    start = time.monotonic()
    details: Dict[str, Any] = {}

    log.info(STARTED + msg, *args, **kwargs, **details)

    yield details

    elapsed = time.monotonic() - start
    log.info(FINISHED + msg, elapsed=elapsed, *args, **kwargs, **details)


def time_messages(sync_messages: MatrixSyncMessages) -> bool:
    for _, room_messages in sync_messages:
        for message in room_messages:
            is_valid_type = (
                message["type"] == "m.room.message" and message["content"]["msgtype"] == "m.text"
            )
            if is_valid_type:
                data_encoded = message["content"]["body"]
                data = json.loads(data_encoded)
                elapsed = time.monotonic() - data["monotonic_start"]
                log.debug(RECEIVED + MESSAGE, elapsed=elapsed)

    return True


def ignore_messages(sync_messages: MatrixSyncMessages) -> bool:  # pylint: disable=unused-argument
    pass


def ignore_member_join(room: Room) -> None:  # pylint: disable=unused-argument
    pass


def handle_and_time_invite(
    invite_start: float,
    client: GMatrixClient,
    room_id: RoomID,
    state: Dict,  # pylint: disable=unused-argument
) -> None:
    invite_elapsed = time.monotonic() - invite_start
    log.debug(RECEIVED + INVITE, invite_elapsed=invite_elapsed)

    with logtime(ROOM, room_id=room_id):
        client.join_room(room_id_or_alias=room_id)


def send(room: Room) -> None:
    while True:
        data = {"monotonic_start": time.monotonic()}
        data_encoded = json.dumps(data)

        with logtime(MESSAGE, room_id=room.room_id):
            room.send_text(data_encoded)


def new_user(matrix_server_url: str) -> LoggedUser:
    client = GMatrixClient(time_messages, ignore_member_join, matrix_server_url)
    signer = factories.make_signer()

    with logtime(USER) as details:
        user = login(client, signer)
        details["user_id"] = user.user_id

    return LoggedUser(client, signer, user)


def init_clients_and_rooms(sender: LoggedUser, receiver: LoggedUser) -> Room:
    invite_start = time.monotonic()

    with logtime(ROOM, sender=sender.user.user_id, receiver=receiver.user.user_id) as details:
        sender_room = sender.client.create_room(
            None, invitees=[receiver.user.user_id], is_public=False
        )
        details["room_id"] = sender_room.room_id

    # The sender doesn't need to process the messages, so skip the listener
    # thread
    receiver.client.add_invite_listener(
        lambda r, s: handle_and_time_invite(invite_start, receiver.client, r, s)
    )
    receiver.client.start_listener_thread(
        timeout_ms=DEFAULT_TRANSPORT_MATRIX_SYNC_TIMEOUT,
        latency_ms=DEFAULT_TRANSPORT_MATRIX_SYNC_LATENCY,
    )

    return sender_room


def messages_p2p(config: Config) -> None:
    login_pool = Pool(size=config.number_of_users)
    number_of_senders = config.number_of_users // 2
    number_of_receivers = config.number_of_users // 2

    # login senders and receivers concurrently
    senders_users_results = login_pool.imap(
        new_user, repeat(config.sender_matrix_server_url, times=number_of_senders)
    )
    receivers_users_results = login_pool.imap(
        new_user, repeat(config.receiver_matrix_server_url, times=number_of_receivers)
    )
    senders = list(senders_users_results)
    receivers = list(receivers_users_results)

    invite_pool = Pool(size=config.number_of_concurrent_chat_rooms)
    rooms = list(login_pool.imap(init_clients_and_rooms, senders, receivers))
    invite_pool.join()

    message_pool = Pool(size=config.number_of_parallel_messages)
    for room in rooms:
        message_pool.spawn(send, room)
    message_pool.join()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--concurrent-messages", type=int, default=50)
    parser.add_argument("--chat-rooms", type=int, default=10)
    parser.add_argument("logfile", help="File used to save the script logs.")
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
    sender_matrix_server_url = args.server
    receiver_matrix_server_url = args.server2 or args.server
    number_of_concurrent_chat_rooms = args.chat_rooms
    number_of_concurrent_messages = args.concurrent_messages

    config = Config(
        sender_matrix_server_url=sender_matrix_server_url,
        receiver_matrix_server_url=receiver_matrix_server_url,
        number_of_concurrent_chat_rooms=number_of_concurrent_chat_rooms,
        number_of_concurrent_messages=number_of_concurrent_messages,
    )

    configure_logging(args.logfile)
    messages_p2p(config)


if __name__ == "__main__":
    main()
