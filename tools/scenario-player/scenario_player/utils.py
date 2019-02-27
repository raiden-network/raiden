import json
import os
import platform
import subprocess
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime
from itertools import islice
from pathlib import Path
from typing import Dict, Union, Tuple

import click
import mirakuru
import requests
import structlog
from eth_keyfile import decode_keyfile_json
from eth_utils import encode_hex, to_checksum_address
from mirakuru import AlreadyRunning, TimeoutExpired
from mirakuru.base import ENV_UUID, IGNORED_ERROR_CODES
from requests.adapters import HTTPAdapter
from web3 import HTTPProvider, Web3
from web3.gas_strategies.time_based import fast_gas_price_strategy, medium_gas_price_strategy

from raiden.accounts import Account
from raiden.network.rpc.client import JSONRPCClient, check_address_has_code
from raiden.network.rpc.smartcontract_proxy import ContractProxy
from raiden_contracts.constants import CONTRACT_CUSTOM_TOKEN
from scenario_player.exceptions import ScenarioError, ScenarioTxError

RECLAIM_MIN_BALANCE = 10 ** 12  # 1 µEth (a.k.a. Twei, szabo)
VALUE_TX_GAS_COST = 21_000

log = structlog.get_logger(__name__)


# Seriously requests? For Humans?
class TimeOutHTTPAdapter(HTTPAdapter):
    def __init__(self, *args, **kwargs):
        self.timeout = kwargs.pop('timeout', None)
        super().__init__(*args, **kwargs)

    def send(self, *args, **kwargs):
        if 'timeout' not in kwargs or not kwargs['timeout']:
            kwargs['timeout'] = self.timeout
        return super().send(*args, **kwargs)


class LogBuffer:
    def __init__(self, capacity=1000):
        self.buffer = deque([''], maxlen=capacity)

    def write(self, content):
        lines = list(content.splitlines())
        self.buffer[0] += lines[0]
        if lines == ['']:
            # Bare newline
            self.buffer.appendleft('')
        else:
            self.buffer.extendleft(lines[1:])

    def getlines(self, start, stop=None):
        if stop:
            slice_ = islice(self.buffer, start, stop)
        else:
            slice_ = islice(self.buffer, start)
        return reversed(list(slice_))


class ConcatenableNone:
    def __radd__(self, other):
        return other


class DummyStream:
    def write(self, content):
        pass


class ChainConfigType(click.ParamType):
    name = 'chain-config'

    def get_metavar(self, param):
        return '<chain-name>:<eth-node-rpc-url>'

    def convert(self, value, param, ctx):
        name, _, rpc_url = value.partition(':')
        if name.startswith('http'):
            self.fail(f'Invalid value: {value}. Use {self.get_metavar(None)}.')
        return name, rpc_url


class HTTPExecutor(mirakuru.HTTPExecutor):
    def start(self, stdout=subprocess.PIPE, stderr=subprocess.PIPE):
        """ Merged copy paste from the inheritance chain with modified stdout/err behaviour """
        if self.pre_start_check():
            # Some other executor (or process) is running with same config:
            raise AlreadyRunning(self)

        if self.process is None:
            command = self.command
            if not self._shell:
                command = self.command_parts

            env = os.environ.copy()
            env[ENV_UUID] = self._uuid
            popen_kwargs = {
                'shell': self._shell,
                'stdin': subprocess.PIPE,
                'stdout': stdout,
                'stderr': stderr,
                'universal_newlines': True,
                'env': env,
            }
            if platform.system() != 'Windows':
                popen_kwargs['preexec_fn'] = os.setsid
            self.process = subprocess.Popen(
                command,
                **popen_kwargs,
            )

        self._set_timeout()

        self.wait_for(self.check_subprocess)
        return self

    def stop(self, sig=None, timeout=10):
        """ Copy paste job from `SimpleExecutor.stop()` to add the `timeout` parameter. """
        if self.process is None:
            return self

        if sig is None:
            sig = self._sig_stop

        try:
            os.killpg(self.process.pid, sig)
        except OSError as err:
            if err.errno in IGNORED_ERROR_CODES:
                pass
            else:
                raise

        def process_stopped():
            """Return True only only when self.process is not running."""
            return self.running() is False

        self._set_timeout(timeout)
        try:
            self.wait_for(process_stopped)
        except TimeoutExpired:
            log.warning('Timeout expired, killing process', process=self)
            pass

        self._kill_all_kids(sig)
        self._clear_process()
        return self


def wait_for_txs(client_or_web3, txhashes, timeout=360):
    if isinstance(client_or_web3, Web3):
        web3 = client_or_web3
    else:
        web3 = client_or_web3.web3
    start = time.monotonic()
    outstanding = False
    txhashes = txhashes[:]
    while txhashes and time.monotonic() - start < timeout:
        remaining_timeout = timeout - (time.monotonic() - start)
        if outstanding != len(txhashes) or int(remaining_timeout) % 10 == 0:
            outstanding = len(txhashes)
            log.debug(
                "Waiting for tx confirmations",
                outstanding=outstanding,
                timeout_remaining=int(remaining_timeout),
            )
        for txhash in txhashes[:]:
            tx = web3.eth.getTransaction(txhash)
            if tx and tx['blockNumber'] is not None:
                txhashes.remove(txhash)
            time.sleep(.1)
        time.sleep(1)
    if len(txhashes):
        txhashes_str = ', '.join(encode_hex(txhash) for txhash in txhashes)
        raise ScenarioTxError(
            f"Timeout waiting for txhashes: {txhashes_str}",
        )


def get_or_deploy_token(runner) -> Tuple[ContractProxy, int]:
    """ Deploy or reuse  """
    token_contract = runner.contract_manager.get_contract(CONTRACT_CUSTOM_TOKEN)

    token_config = runner.scenario.get('token', {})
    if not token_config:
        token_config = {}
    address = token_config.get('address')
    block = token_config.get('block', 0)
    reuse = token_config.get('reuse', False)

    token_address_file = runner.data_path.joinpath('token.infos')
    if reuse:
        if address:
            raise ScenarioError('Token settings "address" and "reuse" are mutually exclusive.')
        if token_address_file.exists():
            token_data = json.loads(token_address_file.read_text())
            address = token_data['address']
            block = token_data['block']
    if address:
        check_address_has_code(runner.client, address, 'Token')
        token_ctr = runner.client.new_contract_proxy(token_contract['abi'], address)

        log.debug(
            "Reusing token",
            address=to_checksum_address(address),
            name=token_ctr.contract.functions.name().call(),
            symbol=token_ctr.contract.functions.symbol().call(),
        )
        return token_ctr, block

    token_id = uuid.uuid4()
    now = datetime.now()
    name = token_config.get('name', f"Scenario Test Token {token_id!s} {now:%Y-%m-%dT%H:%M}")
    symbol = token_config.get('symbol', f"T{token_id!s:.3}")
    decimals = token_config.get('decimals', 0)

    log.debug("Deploying token", name=name, symbol=symbol, decimals=decimals)

    token_ctr, receipt = runner.client.deploy_solidity_contract(
        'CustomToken',
        runner.contract_manager.contracts,
        constructor_parameters=(0, decimals, name, symbol),
    )
    contract_deployment_block = receipt['blockNumber']
    contract_checksum_address = to_checksum_address(token_ctr.contract_address)
    if reuse:
        token_address_file.write_text(json.dumps({
            'address': contract_checksum_address,
            'block': contract_deployment_block,
        }))

    log.info(
        "Deployed token",
        address=contract_checksum_address,
        name=name,
        symbol=symbol,
    )
    return token_ctr, contract_deployment_block


def send_notification_mail(target_mail, subject, message, api_key):
    if not target_mail:
        return
    if not api_key:
        log.error("Can't send notification mail. No API key provided")
        return

    log.debug('Sending notification mail', subject=subject, message=message)
    res = requests.post(
        "https://api.mailgun.net/v3/notification.brainbot.com/messages",
        auth=("api", api_key),
        data={
            "from": "Raiden Scenario Player <scenario-player@notification.brainbot.com>",
            "to": [target_mail],
            "subject": subject,
            "text": message,
        },
    )
    log.debug('Notification mail result', code=res.status_code, text=res.text)


def get_gas_price_strategy(gas_price: Union[int, str]) -> callable:
    if isinstance(gas_price, int):
        def fixed_gas_price(_web3, _tx):
            return gas_price
        return fixed_gas_price
    elif gas_price == 'fast':
        return fast_gas_price_strategy
    elif gas_price == 'medium':
        return medium_gas_price_strategy
    else:
        raise ValueError(f'Invalid gas_price value: "{gas_price}"')


def reclaim_eth(account: Account, chain_rpc_urls: dict, data_path: str, min_age_hours: int):
    web3s: Dict[str, Web3] = {
        name: Web3(HTTPProvider(urls[0]))
        for name, urls in chain_rpc_urls.items()
    }

    data_path = Path(data_path)
    log.info('Starting eth reclaim', data_path=data_path)

    addresses = dict()
    for node_dir in data_path.glob('**/node_???'):
        scenario_name: Path = node_dir.parent.name
        last_run = next(
            iter(
                sorted(
                    list(node_dir.glob('run-*.log')),
                    key=lambda p: p.stat().st_mtime,
                    reverse=True,
                ),
            ),
            None,
        )
        # If there is no last run assume we can reclaim
        if last_run:
            age_hours = (time.time() - last_run.stat().st_mtime) / 3600
            if age_hours < min_age_hours:
                log.debug(
                    'Skipping too recent node',
                    scenario_name=scenario_name,
                    node=node_dir.name,
                    age_hours=age_hours,
                )
                continue
        for keyfile in node_dir.glob('keys/*'):
            keyfile_content = json.loads(keyfile.read_text())
            address = keyfile_content.get('address')
            if address:
                addresses[to_checksum_address(address)] = decode_keyfile_json(keyfile_content, b'')

    log.info('Reclaiming candidates', addresses=list(addresses.keys()))

    txs = defaultdict(list)
    reclaim_amount = defaultdict(int)
    for chain_name, web3 in web3s.items():
        log.info('Checking chain', chain=chain_name)
        for address, privkey in addresses.items():
            balance = web3.eth.getBalance(address)
            if balance > RECLAIM_MIN_BALANCE:
                drain_amount = balance - (web3.eth.gasPrice * VALUE_TX_GAS_COST)
                log.info(
                    'Reclaiming',
                    from_address=address,
                    amount=drain_amount.__format__(',d'),
                    chain=chain_name,
                )
                reclaim_amount[chain_name] += drain_amount
                client = JSONRPCClient(web3, privkey)
                txs[chain_name].append(
                    client.send_transaction(
                        to=account.address,
                        value=drain_amount,
                        startgas=VALUE_TX_GAS_COST,
                    ),
                )
    for chain_name, chain_txs in txs.items():
        wait_for_txs(web3s[chain_name], chain_txs, 1000)
    for chain_name, amount in reclaim_amount.items():
        log.info('Reclaimed', chain=chain_name, amount=amount.__format__(',d'))
