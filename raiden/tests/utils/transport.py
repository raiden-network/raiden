import json
import logging
import os
import re
import sys
from binascii import unhexlify
from collections import defaultdict
from contextlib import ExitStack, contextmanager
from datetime import datetime
from json.decoder import JSONDecodeError
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
from structlog import get_logger
from synapse.handlers.auth import AuthHandler

from raiden.constants import DeviceIDs, Environment
from raiden.messages.abstract import Message
from raiden.network.transport.matrix.client import GMatrixClient, MatrixMessage
from raiden.network.transport.matrix.transport import MatrixTransport, MessagesQueue
from raiden.settings import MatrixTransportConfig
from raiden.tests.utils.factories import make_signer
from raiden.transfer.identifiers import QueueIdentifier
from raiden.utils.http import EXECUTOR_IO, HTTPExecutor
from raiden.utils.signer import recover
from raiden.utils.typing import Iterable, Port
from raiden_contracts.utils.type_aliases import Signature

log = get_logger(__name__)

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
    handle_messages_callback: Callable[[List[MatrixMessage]], bool],
    server: "ParsedURL",
) -> GMatrixClient:
    server_name = server.netloc
    signer = make_signer()
    username = str(to_normalized_address(signer.address))
    password = encode_hex(signer.sign(server_name.encode()))

    client = GMatrixClient(
        handle_messages_callback=handle_messages_callback,
        base_url=server,
    )
    client.login(username, password, sync=False)

    return client


def ignore_messages(_matrix_messages: List[MatrixMessage]) -> bool:
    return True


class ParsedURL(str):
    """A string subclass that allows direct access to the split components of a URL"""

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

    def __init__(self, config, account_handler) -> None:  # type: ignore
        self.account_handler = account_handler
        self.log = logging.getLogger(__name__)
        if "credentials_file" in config:
            credentials_file = Path(config["credentials_file"])
            if not credentials_file.exists():
                raise AssertionError(f"Credentials file '{credentials_file}' is missing.")
            try:
                self.credentials = json.loads(credentials_file.read_text())
            except (JSONDecodeError, UnicodeDecodeError, OSError) as ex:
                raise AssertionError(
                    f"Could not read credentials file '{credentials_file}': {ex}"
                ) from ex
        elif "admin_credentials" in config:
            self.credentials = config["admin_credentials"]
        else:
            raise AssertionError(
                "Either 'credentials_file' or 'admin_credentials' must be specified in "
                "auth provider config."
            )

        msg = "Keys 'username' and 'password' expected in credentials."
        assert "username" in self.credentials, msg
        assert "password" in self.credentials, msg

    async def check_password(self, user_id: str, password: str) -> bool:
        if not password:
            self.log.error("No password provided, user=%r", user_id)
            return False

        username = user_id.partition(":")[0].strip("@")
        if username == self.credentials["username"] and password == self.credentials["password"]:
            self.log.info("Logging in well known admin user")
            user_exists = await self.account_handler.check_user_exists(user_id)
            if not user_exists:
                self.log.info("First well known admin user login, registering: user=%r", user_id)
                await self.account_handler._hs.get_registration_handler().register_user(
                    localpart=username, admin=True
                )
            return True
        return False

    @staticmethod
    def parse_config(config: Any) -> Any:
        return config


class EthAuthProvider:
    __version__ = "0.1"
    _user_re = re.compile(r"^@(0x[0-9a-f]{40}):(.+)$")
    _password_re = re.compile(r"^0x[0-9a-f]{130}$")

    def __init__(self, config, account_handler) -> None:  # type: ignore
        self.account_handler = account_handler
        self.config = config
        self.hs_hostname = self.account_handler._hs.hostname
        self.log = logging.getLogger(__name__)

    async def check_password(self, user_id: str, password: str) -> bool:
        if not password:
            self.log.error("no password provided, user=%r", user_id)
            return False

        if not self._password_re.match(password):
            self.log.error(
                "invalid password format, must be 0x-prefixed hex, "
                "lowercase, 65-bytes hash. user=%r",
                user_id,
            )
            return False

        signature = Signature(unhexlify(password[2:]))

        user_match = self._user_re.match(user_id)
        if not user_match or user_match.group(2) != self.hs_hostname:
            self.log.error(
                "invalid user format, must start with 0x-prefixed hex, "
                "lowercase address. user=%r",
                user_id,
            )
            return False

        user_addr_hex = user_match.group(1)
        user_addr = unhexlify(user_addr_hex[2:])

        rec_addr = recover(data=self.hs_hostname.encode(), signature=signature)
        if not rec_addr or rec_addr != user_addr:
            self.log.error(
                "invalid account password/signature. user=%r, signer=%r", user_id, rec_addr
            )
            return False

        localpart = user_id.split(":", 1)[0][1:]
        self.log.info("eth login! valid signature. user=%r", user_id)

        if not (await self.account_handler.check_user_exists(user_id)):
            self.log.info("First login, creating new user: user=%r", user_id)
            registered_user_id = await self.account_handler.register_user(localpart=localpart)
            await self.account_handler.register_device(registered_user_id, device_id="RAIDEN")

        return True

    @staticmethod
    def parse_config(config: Any) -> Any:
        return config


# Used from within synapse during tests
class NoTLSFederationMonkeyPatchProvider:
    """Dummy auth provider that disables TLS on S2S federation.

    This is used by the integration tests to avoid the need for tls certificates.
    It's implemented as an auth provider since that's a handy way to inject code into the
    Synapse process.

    It works by replacing ``synapse.crypto.context_factory.FederationPolicyForHTTPS`` with an
    object that returns ``None`` when instantiated which causes a non-TLS socket to be used
    inside the Synapse federation machinery.
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

    async def check_password(  # pylint: disable=unused-argument,no-self-use
        self, user_id: str, password: str
    ) -> bool:
        return False

    @staticmethod
    def parse_config(config: Dict[str, Any]) -> Dict[str, Any]:
        from synapse.crypto import context_factory

        context_factory.FederationPolicyForHTTPS = NoTLSFederationMonkeyPatchProvider.NoTLSFactory
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

            log.debug("Synapse command", command=synapse_cmd)

            startup_timeout = 30
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

        yield servers


class TestMatrixTransport(MatrixTransport):
    __test__ = False  # pytest should ignore this

    def __init__(self, config: MatrixTransportConfig, environment: Environment) -> None:
        super().__init__(config, environment)

        self.broadcast_messages: DefaultDict[str, List[Message]] = defaultdict(list)
        self.send_messages: DefaultDict[QueueIdentifier, List[Message]] = defaultdict(list)

    def broadcast(self, message: Message, device_id: DeviceIDs) -> None:
        self.broadcast_messages[device_id.value].append(message)

        super().broadcast(message, device_id=device_id)

    def send_async(self, message_queues: List[MessagesQueue]) -> None:
        for queue in message_queues:
            self.send_messages[queue.queue_identifier].extend(queue.messages)

        super().send_async(message_queues)
