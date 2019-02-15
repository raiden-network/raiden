import hashlib
import json
import os
import random
import shutil
import socket
import stat
import sys
import time
from datetime import timedelta
from enum import Enum
from pathlib import Path
from tarfile import TarFile
from typing import Any, Dict
from zipfile import ZipFile

import gevent
import requests
import structlog
from cachetools.func import ttl_cache
from eth_keyfile import create_keyfile_json
from eth_utils import to_checksum_address
from gevent import Greenlet
from gevent.pool import Group, Pool
from mirakuru import ProcessExitedWithError

from raiden.ui.cli import run as cli_run
from scenario_player.exceptions import ScenarioError
from scenario_player.runner import ScenarioRunner
from scenario_player.utils import HTTPExecutor

log = structlog.get_logger(__name__)


RAIDEN_RELEASES_URL = 'https://raiden-nightlies.ams3.digitaloceanspaces.com/'
if sys.platform == 'darwin':
    RAIDEN_RELEASES_LATEST_FILE = '_LATEST-macOS.txt'
    RAIDEN_RELEASE_VERSIONED_NAME_TEMPLATE = 'raiden-v{version}-macOS.zip'
else:
    RAIDEN_RELEASES_LATEST_FILE = '_LATEST-linux.txt'
    RAIDEN_RELEASE_VERSIONED_NAME_TEMPLATE = 'raiden-v{version}-linux.tar.gz'


MANAGED_CONFIG_OPTIONS = {
    'accept-disclaimer',
    'address',
    'config-file',
    'datadir',
    'disable-debug-logfile',
    'eth-rpc-endpoint',
    'log-config',
    'log-file',
    'log-json',
    'network-id',
    'password-file',
    'rpc',
    'sync-check',
    'transport'
    'web-ui',
}

MANAGED_CONFIG_OPTIONS_OVERRIDABLE = {
    'api-address',
    'endpoint-registry-contract-address',
    'tokennetwork-registry-contract-address',
    'secret-registry-contract-address',
}


KNOWN_OPTIONS = {param.name.replace('_', '-') for param in cli_run.params}
FLAG_OPTIONS = {param.name.replace('_', '-') for param in cli_run.params if param.is_flag}


class NodeState(Enum):
    STOPPED = 1
    STARTED = 2


class RaidenReleaseKeeper:
    def __init__(self, release_cache_dir: Path):
        self._releases = {}
        self._downloads_path = release_cache_dir.joinpath('downloads')
        self._bin_path = release_cache_dir.joinpath('bin')

        self._downloads_path.mkdir(exist_ok=True, parents=True)
        self._bin_path.mkdir(exist_ok=True, parents=True)

    def get_release(self, version: str = 'LATEST'):
        # `version` can also be a path
        bin_path = Path(version)
        if bin_path.exists() and bin_path.stat().st_mode & stat.S_IXUSR == stat.S_IXUSR:
            # File exists and is executable
            return bin_path

        if version.lower() == 'latest':
            release_file_name = self._latest_release_name
        else:
            if version.startswith('v'):
                version = version.lstrip('v')
            release_file_name = RAIDEN_RELEASE_VERSIONED_NAME_TEMPLATE.format(version=version)

        release_file_path = self._get_release_file(release_file_name)
        return self._get_bin_for_release(release_file_path)

    def _get_bin_for_release(self, release_file_path: Path):
        if not release_file_path.exists():
            raise ValueError(f'Release file {release_file_path} not found')

        if release_file_path.suffix == '.gz':
            opener = TarFile.open(release_file_path, 'r:*')
        else:
            opener = ZipFile(release_file_path, 'r')

        with opener as archive:
            if release_file_path.suffix == '.gz':
                contents = archive.getnames()
            else:
                contents = archive.namelist()
            if len(contents) != 1:
                raise ValueError(
                    f'Release archive has unexpected content. '
                    f'Expected 1 file, found {len(contents)}: {", ".join(contents)}',
                )
            bin_file_path = self._bin_path.joinpath(contents[0])
            if not bin_file_path.exists():
                log.debug(
                    'Extracting Raiden binary',
                    release_file_name=release_file_path.name,
                    bin_file_name=bin_file_path.name,
                )
                archive.extract(contents[0], self._bin_path)
                bin_file_path.chmod(0o770)
            return bin_file_path

    def _get_release_file(self, release_file_name: str):
        release_file_path = self._downloads_path.joinpath(release_file_name)
        if release_file_path.exists():
            return release_file_path

        url = RAIDEN_RELEASES_URL + release_file_name
        with requests.get(url, stream=True) as resp, release_file_path.open('wb') as release_file:
            log.debug('Downloading Raiden release', release_file_name=release_file_name)
            if not 199 < resp.status_code < 300:
                raise ValueError(
                    f"Can't download release file {release_file_name}: "
                    f"{resp.status_code} {resp.text}",
                )
            shutil.copyfileobj(resp.raw, release_file)
        return release_file_path

    @property
    @ttl_cache(maxsize=1, ttl=600)
    def _latest_release_name(self):
        url = RAIDEN_RELEASES_URL + RAIDEN_RELEASES_LATEST_FILE
        log.debug('Fetching latest Raiden release')
        return requests.get(url).text.strip()


class NodeRunner:
    def __init__(self, runner: ScenarioRunner, index: int, raiden_version, options: dict):
        self._runner = runner
        self._index = index
        self._raiden_version = raiden_version
        self._options = options
        self._datadir = runner.data_path.joinpath(f'node_{index:03d}')

        self._address = None
        self._eth_rpc_endpoint = None
        self._executor = None
        self._api_address = None

        self.state: NodeState = NodeState.STOPPED

        self._output_files = {}

        if options.pop('_clean', False):
            shutil.rmtree(self._datadir)
        self._datadir.mkdir(parents=True, exist_ok=True)
        self._validate_options(options)

    def initialize(self):
        # Access properties to ensure they're initialized
        _ = self._keystore_file  # noqa: F841
        _ = self._raiden_bin  # noqa: F841
        _ = self.eth_rpc_endpoint  # noqa: F841

    def start(self):
        log.info(
            'Starting node',
            node=self._index,
            address=self.address,
            port=self.api_address.rpartition(':')[2],
        )
        log.debug('Node start command', command=self.executor.command)
        self._output_files['stdout'] = self._stdout_file.open('at', 1)
        self._output_files['stderr'] = self._stderr_file.open('at', 1)
        for file in self._output_files.values():
            file.write('--------- Starting ---------\n')
        self._output_files['stdout'].write(f'Command line: {self.executor.command}\n')

        begin = time.monotonic()
        try:
            ret = self.executor.start(**self._output_files)
        except ProcessExitedWithError as ex:
            raise ScenarioError(f'Failed to start Raiden node {self._index}') from ex
        self.state = NodeState.STARTED
        duration = str(timedelta(seconds=time.monotonic() - begin))
        log.info('Node started', node=self._index, duration=duration)
        return ret

    def stop(self, timeout=60):
        log.info('Stopping node', node=self._index)
        begin = time.monotonic()
        self.state = NodeState.STOPPED
        ret = self.executor.stop(timeout=timeout)
        duration = str(timedelta(seconds=time.monotonic() - begin))
        for file in self._output_files.values():
            file.write('--------- Stopped ---------\n')
            file.close()
        self._output_files = {}
        log.info('Node stopped', node=self._index, duration=duration)
        return ret

    def kill(self):
        log.info('Killing node', node=self._index)
        for file in self._output_files.values():
            file.write('--------- Killed ---------\n')
            file.close()
        self._output_files = {}
        self.state = NodeState.STOPPED
        return self.executor.kill()

    def update_options(self, new_options: Dict[str, Any]):
        if self.state is not NodeState.STOPPED:
            raise ScenarioError("Can't update node options while node is running.")
        self._validate_options(new_options)
        self._options.update(new_options)
        self._executor = None

    @property
    def address(self):
        if not self._address:
            with self._keystore_file.open('r') as keystore_file:
                keystore_contents = json.load(keystore_file)
            self._address = to_checksum_address(keystore_contents['address'])
        return self._address

    @property
    def base_url(self):
        return self.api_address

    @property
    def eth_rpc_endpoint(self):
        if not self._eth_rpc_endpoint:
            self._eth_rpc_endpoint = random.choice(self._runner.eth_rpc_urls)
            log.debug(
                'Using endpoint for node',
                node=self._index,
                rpc_endpoint=self._eth_rpc_endpoint,
            )
        return self._eth_rpc_endpoint

    @property
    def executor(self):
        if not self._executor:
            self._executor = HTTPExecutor(self._command, f'http://{self.base_url}/api/v1/address')
        return self._executor

    @property
    def _command(self):
        cmd = [
            self._raiden_bin,
            '--accept-disclaimer',
            '--datadir',
            self._datadir,
            '--keystore-path',
            self._keystore_file.parent,
            '--address',
            self.address,
            '--password-file',
            self._password_file,
            '--network-id',
            self._runner.chain_id,
            '--sync-check',  # FIXME: Disable sync check for private chains
            '--gas-price',
            self._options.get('gas-price', 'normal'),
            '--eth-rpc-endpoint',
            self.eth_rpc_endpoint,
            '--log-config',
            (
                ':info,'
                'raiden:debug,'
                'raiden_contracts:debug,'
                'raiden.api.rest.pywsgi:warning'
            ),
            '--log-json',
            '--log-file',
            self._log_file,
            '--disable-debug-logfile',
            '--matrix-server',
            self._options.get('matrix-server', 'auto'),
            '--api-address',
            self.api_address,
            '--no-web-ui',
        ]
        for option_name in MANAGED_CONFIG_OPTIONS_OVERRIDABLE:
            if option_name == 'api-address':
                # already handled above
                continue
            if option_name in self._options:
                cmd.extend([f'--{option_name}', self._options[option_name]])

        remaining_option_candidates = (
            KNOWN_OPTIONS -
            MANAGED_CONFIG_OPTIONS -
            MANAGED_CONFIG_OPTIONS_OVERRIDABLE
        )
        for option_name in remaining_option_candidates:
            if option_name in self._options:
                cmd.append(f'--{option_name}')
                if option_name not in FLAG_OPTIONS:
                    cmd.append(self._options[option_name])

        # Ensure path instances are converted to strings
        cmd = [str(c) for c in cmd]
        return cmd

    @property
    def _raiden_bin(self):
        return self._runner.release_keeper.get_release(self._raiden_version)

    @property
    def _keystore_file(self):
        keystore_path = self._datadir.joinpath('keys')
        keystore_path.mkdir(exist_ok=True, parents=True)
        keystore_file = keystore_path.joinpath('UTC--1')
        if not keystore_file.exists():
            log.debug('Initializing keystore', node=self._index)
            gevent.sleep()
            privkey = hashlib.sha256(
                f'{self._runner.scenario_name}-{self._index}'.encode(),
            ).digest()
            keystore_file.write_text(json.dumps(create_keyfile_json(privkey, b'')))
        return keystore_file

    @property
    def _password_file(self):
        pw_file = self._datadir.joinpath('password.txt')
        pw_file.write_text('')
        return pw_file

    @property
    def api_address(self):
        if not self._api_address:
            self._api_address = self._options.get('api-address')
            if self._api_address is None:
                # Find a random free port
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.bind(('127.0.0.1', 0))
                self._api_address = f'127.0.0.1:{sock.getsockname()[1]}'
                sock.close()
        return self._api_address

    @property
    def _log_file(self):
        return self._datadir.joinpath(f'run-{self._runner.run_number:03d}.log')

    @property
    def _stdout_file(self):
        return self._datadir.joinpath(f'run-{self._runner.run_number:03d}.stdout')

    @property
    def _stderr_file(self):
        return self._datadir.joinpath(f'run-{self._runner.run_number:03d}.stderr')

    def _validate_options(self, options: Dict[str, Any]):
        for option_name, option_value in options.items():
            if option_name.startswith('no-'):
                option_name = option_name.replace('no-', '')
            if option_name in MANAGED_CONFIG_OPTIONS:
                raise ScenarioError(
                    f'Raiden node option "{option_name}" is managed by the scenario player '
                    f'and cannot be changed.',
                )
            if option_name in MANAGED_CONFIG_OPTIONS_OVERRIDABLE:
                log.warning(
                    'Overriding managed option',
                    option_name=option_name,
                    option_value=option_value,
                    node=self._index,
                )

            if option_name not in KNOWN_OPTIONS:
                raise ScenarioError(
                    f'Unknown option "{option_name}" supplied.',
                )


class NodeController:
    def __init__(
        self,
        runner: ScenarioRunner,
        raiden_version,
        node_count,
        global_options,
        node_options,
    ):
        self._runner = runner
        self._global_options = global_options
        self._node_options = node_options
        self._node_runners = [
            NodeRunner(
                runner,
                index,
                raiden_version,
                {**self._global_options, **self._node_options.get(index, {})},
            )
            for index in range(node_count)
        ]
        log.info('Using Raiden version', version=raiden_version)

    def __getitem__(self, item):
        return self._node_runners[item]

    def __len__(self):
        return self._node_runners.__len__()

    def start(self, wait=True):
        log.info('Starting nodes')

        # Start nodes in <number of cpus> batches
        pool = Pool(size=os.cpu_count())

        def _start():
            for runner in self._node_runners:
                pool.start(Greenlet(runner.start))
            pool.join(raise_error=True)
            log.info('All nodes started')

        starter = gevent.spawn(_start)
        if wait:
            starter.get(block=True)
        return starter

    def stop(self):
        log.info('Stopping nodes')
        stop_tasks = [gevent.spawn(runner.stop) for runner in self._node_runners]
        gevent.joinall(stop_tasks, raise_error=True)
        log.info('Nodes stopped')

    def kill(self):
        log.info('Killing nodes')
        kill_tasks = [gevent.spawn(runner.kill) for runner in self._node_runners]
        gevent.joinall(kill_tasks, raise_error=True)
        log.info('Nodes killed')

    def initialize_nodes(self):
        for runner in self._node_runners:
            runner.initialize()

    @property
    def addresses(self):
        return {runner.address for runner in self._node_runners}

    def start_node_monitor(self):
        def _monitor(runner: NodeRunner):
            while not self._runner.root_task.done:
                if runner.state is NodeState.STARTED:
                    try:
                        runner.executor.check_subprocess()
                    except ProcessExitedWithError as ex:
                        raise ScenarioError(
                            f'Raiden node {runner._index} died with non-zero exit status',
                        ) from ex
                gevent.sleep(.5)

        monitor_group = Group()
        for runner in self._node_runners:
            monitor_group.start(Greenlet(_monitor, runner))

        def _wait():
            while not monitor_group.join(.5, raise_error=True):
                pass

        return gevent.spawn(_wait)
