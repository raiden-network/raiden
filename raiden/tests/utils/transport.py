import logging
import os
import re
import shutil
import subprocess
import sys
from binascii import unhexlify
from contextlib import ExitStack, contextmanager
from datetime import datetime
from pathlib import Path
from tempfile import mkdtemp
from typing import ContextManager
from urllib.parse import urljoin, urlsplit

import requests
from twisted.internet import defer

from raiden.network.utils import get_free_port
from raiden.utils.http import HTTPExecutor
from raiden.utils.signer import recover

_SYNAPSE_BASE_DIR_VAR_NAME = 'RAIDEN_TESTS_SYNAPSE_BASE_DIR'
_SYNAPSE_LOGS_PATH = os.environ.get('RAIDEN_TESTS_SYNAPSE_LOGS_DIR', False)
_SYNAPSE_CONFIG_TEMPLATE = Path(__file__).parent.joinpath('synapse_config.yaml.template')


class MockDiscovery(object):
    @staticmethod
    def get(node_address: bytes):
        return '127.0.0.1:5252'


class ParsedURL(str):
    """ A string subclass that allows direct access to the split components of a URL """
    def __new__(cls, *args, **kwargs):
        new = str.__new__(cls, *args, **kwargs)
        new._parsed = urlsplit(new)
        return new

    def __dir__(self):
        return dir('') + dir(self._parsed)

    def __repr__(self):
        return f"<{self.__class__.__name__}('{self}')>"

    def __getattr__(self, item):
        try:
            return getattr(self._parsed, item)
        except AttributeError:
            raise AttributeError(
                f"'{self.__class__.__name__}' object has no attribute '{item}'",
            )


# Used from within synapse during tests
class EthAuthProvider(object):
    __version__ = '0.1'
    _user_re = re.compile(r'^@(0x[0-9a-f]{40}):(.+)$')
    _password_re = re.compile(r'^0x[0-9a-f]{130}$')

    def __init__(self, config, account_handler):
        self.account_handler = account_handler
        self.config = config
        self.hs_hostname = self.account_handler.hs.hostname
        self.log = logging.getLogger(__name__)

    @defer.inlineCallbacks
    def check_password(self, user_id, password):
        if not password:
            self.log.error('no password provided, user=%r', user_id)
            defer.returnValue(False)

        if not self._password_re.match(password):
            self.log.error(
                'invalid password format, must be 0x-prefixed hex, '
                'lowercase, 65-bytes hash. user=%r',
                user_id,
            )
            defer.returnValue(False)

        signature = unhexlify(password[2:])

        user_match = self._user_re.match(user_id)
        if not user_match or user_match.group(2) != self.hs_hostname:
            self.log.error(
                'invalid user format, must start with 0x-prefixed hex, '
                'lowercase address. user=%r',
                user_id,
            )
            defer.returnValue(False)

        user_addr_hex = user_match.group(1)
        user_addr = unhexlify(user_addr_hex[2:])

        rec_addr = recover(data=self.hs_hostname.encode(), signature=signature)
        if not rec_addr or rec_addr != user_addr:
            self.log.error(
                'invalid account password/signature. user=%r, signer=%r',
                user_id,
                rec_addr,
            )
            defer.returnValue(False)

        localpart = user_id.split(":", 1)[0][1:]
        self.log.info('eth login! valid signature. user=%r', user_id)

        if not (yield self.account_handler.check_user_exists(user_id)):
            self.log.info('first user login, registering: user=%r', user_id)
            yield self.account_handler.register(localpart=localpart)

        defer.returnValue(True)

    @staticmethod
    def parse_config(config):
        return config


def make_requests_insecure():
    """
    Prevent `requests` from performing TLS verification.

    **THIS MUST ONLY BE USED FOR TESTING PURPOSES!**
    """
    # Disable verification in requests by replacing the 'verify'
    # attribute with non-writable property that always returns `False`
    requests.Session.verify = property(lambda self: False, lambda self, val: None)


@contextmanager
def generate_synapse_config() -> ContextManager:
    # Allows caching of self signed synapse certificates on CI systems
    if _SYNAPSE_BASE_DIR_VAR_NAME in os.environ:
        synapse_base_dir = Path(os.environ[_SYNAPSE_BASE_DIR_VAR_NAME])
        synapse_base_dir.mkdir(parents=True, exist_ok=True)
        delete_base_dir = False
    else:
        synapse_base_dir = Path(mkdtemp(prefix='pytest-synapse-'))
        delete_base_dir = True

    def generate_config(port: int):
        server_dir = synapse_base_dir.joinpath(f'localhost-{port}')
        server_dir.mkdir(parents=True, exist_ok=True)

        server_name = f'localhost:{port}'

        # Always overwrite config file to ensure we're not using a stale version
        config_file = server_dir.joinpath('synapse_config.yaml').resolve()
        config_template = _SYNAPSE_CONFIG_TEMPLATE.read_text()
        config_file.write_text(config_template.format(server_dir=server_dir, port=port))

        tls_key_file = server_dir.joinpath(f'{server_name}.tls.crt')

        if not tls_key_file.exists():
            subprocess.run(
                [
                    sys.executable,
                    '-m',
                    'synapse.app.homeserver',
                    f'--server-name={server_name}',
                    f'--config-path={config_file!s}',
                    '--generate-keys',
                ],
                cwd=server_dir,
                timeout=30,
                check=True,
                stderr=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
            )
        return server_name, config_file

    try:
        yield generate_config
    finally:
        if delete_base_dir:
            shutil.rmtree(synapse_base_dir)


@contextmanager
def matrix_server_starter(
        *,
        count: int = 1,
        config_generator: ContextManager = None,
        log_context: str = None,
) -> ContextManager:
    with ExitStack() as exit_stack:
        if config_generator is None:
            config_generator = exit_stack.enter_context(generate_synapse_config())
        server_urls = []
        for _, port in zip(range(count), get_free_port(initial_port=8500)):
            server_name, config_file = config_generator(port)
            server_url = ParsedURL(f'https://{server_name}')
            server_urls.append(server_url)

            synapse_io = subprocess.DEVNULL
            # Used in CI to capture the logs for failure analysis
            if _SYNAPSE_LOGS_PATH:
                log_file_path = Path(_SYNAPSE_LOGS_PATH).joinpath(f'{server_name}.log')
                log_file_path.parent.mkdir(parents=True, exist_ok=True)
                log_file = exit_stack.enter_context(log_file_path.open('at'))

                # Preface log with header
                header = datetime.utcnow().isoformat()
                if log_context:
                    header = f'{header}: {log_context}'
                header = f' {header} '
                log_file.write(f'{header:=^100}\n')
                log_file.flush()

                synapse_io = subprocess.DEVNULL, log_file, subprocess.STDOUT

            exit_stack.enter_context(
                HTTPExecutor(
                    [
                        sys.executable,
                        '-m',
                        'synapse.app.homeserver',
                        f'--server-name={server_name}',
                        f'--config-path={config_file.name}',
                    ],
                    url=urljoin(server_url, '/_matrix/client/versions'),
                    method='GET',
                    timeout=30,
                    cwd=config_file.parent,
                    io=synapse_io,
                ),
            )
        yield server_urls
