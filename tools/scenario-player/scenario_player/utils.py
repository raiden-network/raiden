import time
import uuid
from binascii import hexlify
from collections import deque
from datetime import datetime
from itertools import islice
from typing import Union

import requests
import structlog
from eth_utils import to_checksum_address
from requests.adapters import HTTPAdapter
from web3.gas_strategies.time_based import fast_gas_price_strategy, medium_gas_price_strategy

from raiden.network.rpc.client import JSONRPCClient, check_address_has_code
from raiden.network.rpc.smartcontract_proxy import ContractProxy
from raiden_contracts.constants import CONTRACT_CUSTOM_TOKEN
from raiden_contracts.contract_manager import CONTRACT_MANAGER
from scenario_player.exceptions import ScenarioTxError

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
        time.sleep(.5)
    if len(txhashes):
        txhashes_str = ', '.join(hexlify(txhash).decode() for txhash in txhashes)
        raise ScenarioTxError(
            f"Timeout waiting for txhashes: {txhashes_str}",
        )


def get_or_deploy_token(client: JSONRPCClient, scenario: dict) -> ContractProxy:
    """ Deploy or reuse  """
    token_contract = CONTRACT_MANAGER.get_contract(CONTRACT_CUSTOM_TOKEN)

    token_config = scenario.get('token', {})
    if not token_config:
        token_config = {}
    address = token_config.get('address')
    if address:
        check_address_has_code(client, address, 'Token')
        token_ctr = client.new_contract_proxy(token_contract['abi'], address)

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

    token_ctr = client.deploy_solidity_contract(
        'CustomToken',
        CONTRACT_MANAGER._contracts,
        constructor_parameters=(0, decimals, name, symbol),
        confirmations=1,

    )
    log.info(
        "Deployed token",
        address=to_checksum_address(token_ctr.contract_address),
        name=name,
        symbol=symbol,
    )
    return token_ctr


def send_notification_mail(target_mail, subject, message, api_key):
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
