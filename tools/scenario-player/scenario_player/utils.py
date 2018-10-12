import os
import time
import uuid
from collections import deque
from datetime import datetime
from itertools import islice
from typing import Union

import click
import mirakuru
import requests
import structlog
from eth_utils import encode_hex, to_checksum_address
from mirakuru import TimeoutExpired
from mirakuru.base import IGNORED_ERROR_CODES
from requests.adapters import HTTPAdapter
from web3.gas_strategies.time_based import fast_gas_price_strategy, medium_gas_price_strategy

from raiden.network.rpc.client import check_address_has_code
from raiden.network.rpc.smartcontract_proxy import ContractProxy
from raiden_contracts.constants import CONTRACT_CUSTOM_TOKEN
from raiden_contracts.contract_manager import ContractManager, contracts_precompiled_path
from scenario_player.exceptions import ScenarioError, ScenarioTxError

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
            # at this moment, process got killed,
            pass

        self._kill_all_kids(sig)
        self._clear_process()
        return self


def wait_for_txs(client, txhashes, timeout=360):
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
            tx = client.web3.eth.getTransaction(txhash)
            if tx and tx['blockNumber'] is not None:
                txhashes.remove(txhash)
            time.sleep(.1)
        time.sleep(1)
    if len(txhashes):
        txhashes_str = ', '.join(encode_hex(txhash) for txhash in txhashes)
        raise ScenarioTxError(
            f"Timeout waiting for txhashes: {txhashes_str}",
        )


def get_or_deploy_token(runner: 'ScenarioRunner') -> ContractProxy:
    """ Deploy or reuse  """
    contract_manager = ContractManager(contracts_precompiled_path())
    token_contract = contract_manager.get_contract(CONTRACT_CUSTOM_TOKEN)

    token_config = runner.scenario.get('token', {})
    if not token_config:
        token_config = {}
    address = token_config.get('address')
    reuse = token_config.get('reuse', False)

    token_address_file = runner.data_path.joinpath('token.addr')
    if reuse:
        if address:
            raise ScenarioError('Token settings "address" and "reuse" are mutually exclusive.')
        if token_address_file.exists():
            address = token_address_file.read_text()
    if address:
        check_address_has_code(runner.client, address, 'Token')
        token_ctr = runner.client.new_contract_proxy(token_contract['abi'], address)

        log.debug(
            "Reusing token",
            address=to_checksum_address(address),
            name=token_ctr.contract.functions.name().call(),
            symbol=token_ctr.contract.functions.symbol().call(),
        )
        return token_ctr

    token_id = uuid.uuid4()
    now = datetime.now()
    name = token_config.get('name', f"Scenario Test Token {token_id!s} {now:%Y-%m-%dT%H:%M}")
    symbol = token_config.get('symbol', f"T{token_id!s:.3}")
    decimals = token_config.get('decimals', 0)

    log.debug("Deploying token", name=name, symbol=symbol, decimals=decimals)

    token_ctr = runner.client.deploy_solidity_contract(
        'CustomToken',
        contract_manager.contracts,
        constructor_parameters=(0, decimals, name, symbol),
        confirmations=1,

    )
    contract_checksum_address = to_checksum_address(token_ctr.contract_address)
    if reuse:
        token_address_file.write_text(contract_checksum_address)

    log.info(
        "Deployed token",
        address=contract_checksum_address,
        name=name,
        symbol=symbol,
    )
    return token_ctr


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
