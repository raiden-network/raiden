import logging
import os
import re
import sys
from binascii import unhexlify
from collections import defaultdict
from contextlib import ExitStack, contextmanager
from datetime import datetime
from itertools import chain
from pathlib import Path
from subprocess import DEVNULL, STDOUT
from tempfile import mkdtemp
from typing import Any, Callable, DefaultDict, Dict, Iterator, List, Tuple
from urllib.parse import urljoin, urlsplit

import requests
from eth_utils import encode_hex, to_normalized_address
from gevent import subprocess
from requests.packages import urllib3
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from synapse.handlers.auth import AuthHandler
from twisted.internet import defer

from raiden.constants import Environment
from raiden.messages.abstract import Message
from raiden.network.transport.matrix.client import GMatrixClient, MatrixSyncMessages, Room
from raiden.network.transport.matrix.transport import MatrixTransport, MessagesQueue
from raiden.settings import MatrixTransportConfig
from raiden.tests.utils.factories import make_signer
from raiden.transfer.identifiers import QueueIdentifier
from raiden.utils.http import EXECUTOR_IO, HTTPExecutor
from raiden.utils.signer import recover
from raiden.utils.typing import Iterable, Port, Signature

_SYNAPSE_BASE_DIR_VAR_NAME = "RAIDEN_TESTS_SYNAPSE_BASE_DIR"
_SYNAPSE_LOGS_PATH = os.environ.get("RAIDEN_TESTS_SYNAPSE_LOGS_DIR")
_SYNAPSE_CONFIG_TEMPLATE = Path(__file__).parent.joinpath("synapse_config.yaml.template")

SynapseConfig = Tuple[str, Path]
SynapseConfigGenerator = Callable[[int], SynapseConfig]


def get_admin_credentials(server_name):
    username = f"admin-{server_name}".replace(":", "-")
    credentials = {"username": username, "password": "securepassword"}

    return credentials


def new_client(
    handle_messages_callback: Callable[[MatrixSyncMessages], bool],
    handle_member_join_callback: Callable[[Room], None],
    server: "ParsedURL",
) -> GMatrixClient:
    server_name = server.netloc
    signer = make_signer()
    username = str(to_normalized_address(signer.address))
    password = encode_hex(signer.sign(server_name.encode()))

    client = GMatrixClient(
        handle_messages_callback=handle_messages_callback,
        handle_member_join_callback=handle_member_join_callback,
        base_url=server,
    )
    client.login(username, password, sync=False)

    return client


def ignore_member_join(_room: Room) -> None:
    return None


def ignore_messages(_matrix_messages: MatrixSyncMessages) -> bool:
    return True


def setup_broadcast_room(servers: List["ParsedURL"], broadcast_room_name: str) -> None:
    client = new_client(ignore_messages, ignore_member_join, servers[0])
    admin_power_level = {"users": {client.user_id: 100}}
    for server in servers:
        admin_username = get_admin_credentials(server.netloc)["username"]
        admin_user_id = f"@{admin_username}:{servers[0].netloc}"
        admin_power_level["users"][admin_user_id] = 50

    room = client.create_room(
        alias=broadcast_room_name, is_public=True, power_level_content_override=admin_power_level
    )

    for server in servers[1:]:
        client = new_client(ignore_messages, ignore_member_join, server)

        # A user must join the room to create the room in the federated server
        room = client.join_room(room.aliases[0])

        # Since #5892 `join_room()` only populates server-local aliases but we need all here
        room.update_aliases()
        server_name = server.netloc
        alias = f"#{broadcast_room_name}:{server_name}"

        msg = "Setting up the room alias must not fail, otherwise the test can not run."
        assert room.add_room_alias(alias), msg

        room_state = client.api.get_room_state(room.room_id)
        all_aliases = chain.from_iterable(
            event["content"]["aliases"]
            for event in room_state
            if event["type"] == "m.room.aliases"
        )

        msg = "The new alias must be added, otherwise the Raiden node won't be able to find it."
        assert alias in all_aliases, msg

        msg = (
            "Leaving the room failed. This is done otherwise there would be "
            "a ghost user in the broadcast room"
        )
        assert room.leave() is None, msg


class ParsedURL(str):
    """ A string subclass that allows direct access to the split components of a URL """

    def __new__(cls, *args, **kwargs):
        new = str.__new__(cls, *args, **kwargs)  # type: ignore
        new._parsed = urlsplit(new)
        return new

    def __dir__(self):
        return dir("") + dir(self._parsed)

    def __repr__(self):
        return f"<{self.__class__.__name__}('{self}')>"

    def __getattr__(self, item):
        try:
            return getattr(self._parsed, item)
        except AttributeError:
            raise AttributeError(f"'{self.__class__.__name__}' object has no attribute '{item}'")


class AdminUserAuthProvider:
    __version__ = "0.1"

    def __init__(self, config, account_handler):
        self.account_handler = account_handler
        self.log = logging.getLogger(__name__)
        self.credentials = config["admin_credentials"]

        msg = "Keys 'username' and 'password' expected in credentials."
        assert "username" in self.credentials, msg
        assert "password" in self.credentials, msg

    @defer.inlineCallbacks
    def check_password(self, user_id: str, password: str):
        if not password:
            self.log.error("No password provided, user=%r", user_id)
            defer.returnValue(False)

        username = user_id.partition(":")[0].strip("@")
        if username == self.credentials["username"] and password == self.credentials["password"]:
            self.log.info("Logging in well known admin user")
            user_exists = yield self.account_handler.check_user_exists(user_id)
            if not user_exists:
                self.log.info("First well known admin user login, registering: user=%r", user_id)
                user_id = yield self.account_handler._hs.get_registration_handler().register_user(
                    localpart=username, admin=True
                )
                _, access_token = yield self.account_handler.register_device(user_id)
                yield user_id, access_token
            defer.returnValue(True)

        self.log.error("Unknown user '%s', ignoring.", user_id)
        defer.returnValue(False)

    @staticmethod
    def parse_config(config):
        return config


# Used from within synapse during tests
class EthAuthProvider:
    __version__ = "0.1"
    _user_re = re.compile(r"^@(0x[0-9a-f]{40}):(.+)$")
    _password_re = re.compile(r"^0x[0-9a-f]{130}$")

    def __init__(self, config, account_handler):
        self.account_handler = account_handler
        self.config = config
        self.hs_hostname = self.account_handler._hs.hostname
        self.log = logging.getLogger(__name__)

    @defer.inlineCallbacks
    def check_password(self, user_id, password):
        if not password:
            self.log.error("no password provided, user=%r", user_id)
            defer.returnValue(False)

        if not self._password_re.match(password):
            self.log.error(
                "invalid password format, must be 0x-prefixed hex, "
                "lowercase, 65-bytes hash. user=%r",
                user_id,
            )
            defer.returnValue(False)

        signature = Signature(unhexlify(password[2:]))

        user_match = self._user_re.match(user_id)
        if not user_match or user_match.group(2) != self.hs_hostname:
            self.log.error(
                "invalid user format, must start with 0x-prefixed hex, "
                "lowercase address. user=%r",
                user_id,
            )
            defer.returnValue(False)

        user_addr_hex = user_match.group(1)
        user_addr = unhexlify(user_addr_hex[2:])

        rec_addr = recover(data=self.hs_hostname.encode(), signature=signature)
        if not rec_addr or rec_addr != user_addr:
            self.log.error(
                "invalid account password/signature. user=%r, signer=%r", user_id, rec_addr
            )
            defer.returnValue(False)

        localpart = user_id.split(":", 1)[0][1:]
        self.log.info("eth login! valid signature. user=%r", user_id)

        if not (yield self.account_handler.check_user_exists(user_id)):
            self.log.info("first user login, registering: user=%r", user_id)
            yield self.account_handler.register(localpart=localpart)

        defer.returnValue(True)

    @staticmethod
    def parse_config(config):
        return config


# Used from within synapse during tests
class NoTLSFederationMonkeyPatchProvider:
    """ Dummy auth provider that disables TLS on S2S federation.

    This is used by the integration tests to avoid the need for tls certificates.
    It's implemented as an auth provider since that's a handy way to inject code into the
    synapse process.

    It works by replacing ``synapse.crypto.context_factory.ClientTLSOptionsFactory`` with an
    object that returns ``None`` when instantiated.
    """

    __version__ = "0.1"

    class NoTLSFactory:
        def __new__(
            cls, *args: List[Any], **kwargs: Dict[str, Any]  # pylint: disable=unused-argument
        ):
            return None

    def __init__(  # pylint: disable=unused-argument
        self, config: Dict[str, Any], account_handler: AuthHandler
    ) -> None:
        pass

    def check_password(  # pylint: disable=unused-argument,no-self-use
        self, user_id: str, password: str
    ) -> bool:
        return False

    @staticmethod
    def parse_config(config: Dict[str, Any]) -> Dict[str, Any]:
        from synapse.crypto import context_factory

        context_factory.ClientTLSOptionsFactory = NoTLSFederationMonkeyPatchProvider.NoTLSFactory
        return config


def make_requests_insecure():
    """
    Prevent `requests` from performing TLS verification.

    **THIS MUST ONLY BE USED FOR TESTING PURPOSES!**
    """
    # Disable verification in requests by replacing the 'verify'
    # attribute with non-writable property that always returns `False`
    requests.Session.verify = property(lambda self: False, lambda self, val: None)  # type: ignore
    urllib3.disable_warnings(InsecureRequestWarning)


@contextmanager
def generate_synapse_config() -> Iterator[SynapseConfigGenerator]:
    # Allows caching of self signed synapse certificates on CI systems
    if _SYNAPSE_BASE_DIR_VAR_NAME in os.environ:
        synapse_base_dir = Path(os.environ[_SYNAPSE_BASE_DIR_VAR_NAME])
        synapse_base_dir.mkdir(parents=True, exist_ok=True)
    else:
        synapse_base_dir = Path(mkdtemp(prefix="pytest-synapse-"))

    def generate_config(port: int) -> SynapseConfig:
        server_dir = synapse_base_dir.joinpath(f"localhost-{port}")
        server_dir.mkdir(parents=True, exist_ok=True)

        server_name = f"localhost:{port}"
        admin_credentials = get_admin_credentials(server_name)
        # Always overwrite config file to ensure we're not using a stale version
        config_file = server_dir.joinpath("synapse_config.yaml").resolve()
        config_template = _SYNAPSE_CONFIG_TEMPLATE.read_text()
        config_file.write_text(
            config_template.format(
                server_dir=server_dir, port=port, admin_credentials=admin_credentials
            )
        )

        tls_key_file = server_dir.joinpath(f"{server_name}.tls.crt")

        if not tls_key_file.exists():
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "synapse.app.homeserver",
                    f"--server-name={server_name}",
                    f"--config-path={config_file!s}",
                    "--generate-keys",
                ],
                cwd=server_dir,
                timeout=30,
                check=True,
                stderr=DEVNULL,
                stdout=DEVNULL,
            )
        return server_name, config_file

    yield generate_config


@contextmanager
def matrix_server_starter(
    free_port_generator: Iterable[Port],
    broadcast_rooms_aliases: Iterable[str],
    *,
    count: int = 1,
    config_generator: SynapseConfigGenerator = None,
    log_context: str = None,
) -> Iterator[List[Tuple[ParsedURL, HTTPExecutor]]]:
    with ExitStack() as exit_stack:

        if config_generator is None:
            config_generator = exit_stack.enter_context(generate_synapse_config())

        servers: List[Tuple[ParsedURL, HTTPExecutor]] = []
        for _, port in zip(range(count), free_port_generator):
            server_name, config_file = config_generator(port)
            server_url = ParsedURL(f"http://{server_name}")

            synapse_cmd = [
                sys.executable,
                "-m",
                "synapse.app.homeserver",
                f"--server-name={server_name}",
                f"--config-path={config_file!s}",
            ]

            synapse_io: EXECUTOR_IO = DEVNULL
            # Used in CI to capture the logs for failure analysis
            if _SYNAPSE_LOGS_PATH is not None:
                log_file_path = Path(_SYNAPSE_LOGS_PATH).joinpath(f"{server_name}.log")
                log_file_path.parent.mkdir(parents=True, exist_ok=True)
                log_file = exit_stack.enter_context(log_file_path.open("at"))

                # Preface log with header
                header = datetime.utcnow().isoformat()
                if log_context:
                    header = f"{header}: {log_context}"
                header = f" {header} "
                log_file.write(f"{header:=^100}\n")
                log_file.write(f"Cmd: `{' '.join(synapse_cmd)}`\n")
                log_file.flush()

                synapse_io = DEVNULL, log_file, STDOUT

            startup_timeout = 10
            sleep = 0.1

            executor = HTTPExecutor(
                synapse_cmd,
                url=urljoin(server_url, "/_matrix/client/versions"),
                method="GET",
                timeout=startup_timeout,
                sleep=sleep,
                cwd=config_file.parent,
                verify_tls=False,
                io=synapse_io,
            )
            exit_stack.enter_context(executor)

            # The timeout_limit_teardown is necessary to prevent the build
            # being killed because of the lack of output, at the same time the
            # timeout must never happen, because if it does, not all finalizers
            # are executed, leaving dirty state behind and resulting in test
            # flakiness.
            #
            # Because of this, this value is arbitrarily smaller than the
            # teardown timeout, forcing the subprocess to be killed on a timely
            # manner, which should allow the teardown to proceed and finish
            # before the timeout elapses.
            teardown_timeout = 0.5

            # The timeout values for the startup and teardown must be
            # different, however the library doesn't support it. So here we
            # must poke at the private member and overwrite it.
            executor._timeout = teardown_timeout

            servers.append((server_url, executor))

        for broadcast_room_alias in broadcast_rooms_aliases:
            setup_broadcast_room([url for url, _ in servers], broadcast_room_alias)

        yield servers


class TestMatrixTransport(MatrixTransport):
    __test__ = False  # pytest should ignore this

    def __init__(self, config: MatrixTransportConfig, environment: Environment) -> None:
        super().__init__(config, environment)

        self.broadcast_messages: DefaultDict[str, List[Message]] = defaultdict(list)
        self.send_messages: DefaultDict[QueueIdentifier, List[Message]] = defaultdict(list)

    def broadcast(self, room: str, message: Message) -> None:
        self.broadcast_messages[room].append(message)

        super().broadcast(room, message)

    def send_async(self, message_queues: List[MessagesQueue]) -> None:
        for queue in message_queues:
            self.send_messages[queue.queue_identifier].extend(queue.messages)

        super().send_async(message_queues)
