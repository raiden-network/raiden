import os
import random
from collections import defaultdict
from enum import Enum
from pathlib import Path
from typing import Dict, List

import gevent
import structlog
import yaml
from eth_utils import to_checksum_address
from raiden_contracts.contract_manager import ContractManager, contracts_precompiled_path
from requests import RequestException, Session
from web3 import HTTPProvider, Web3

from raiden.accounts import Account
from raiden.constants import GAS_LIMIT_FOR_TOKEN_CONTRACT_CALL
from raiden.network.rpc.client import JSONRPCClient
from scenario_player.exceptions import NodesUnreachableError, ScenarioError, TokenRegistrationError
from scenario_player.utils import (
    TimeOutHTTPAdapter,
    get_gas_price_strategy,
    get_or_deploy_token,
    wait_for_txs,
)

log = structlog.get_logger(__name__)


DEFAULT_TOKEN_BALANCE_MIN = 2_000
DEFAULT_TOKEN_BALANCE_FUND = 10_000
OWN_ACCOUNT_BALANCE_MIN = 5 * 10 ** 17    # := 0.5 Eth
NODE_ACCOUNT_BALANCE_MIN = 15 * 10 ** 16   # := 0.15 Eth
NODE_ACCOUNT_BALANCE_FUND = 3 * 10 ** 17  # := 0.3 Eth
TIMEOUT = 200
API_URL_ADDRESS = "{protocol}://{target_host}/api/v1/address"
API_URL_TOKENS = "{protocol}://{target_host}/api/v1/tokens"
API_URL_TOKEN_NETWORK_ADDRESS = "{protocol}://{target_host}/api/v1/tokens/{token_address}"
SUPPORTED_SCENARIO_VERSIONS = {1, 2}


class NodeMode(Enum):
    EXTERNAL = 1
    MANAGED = 2


class ScenarioRunner(object):
    def __init__(
        self,
        account: Account,
        chain_urls: Dict[str, List[str]],
        auth: str,
        data_path: Path,
        scenario_file: Path,
    ):
        from scenario_player.tasks.base import get_task_class_for_type
        from scenario_player.node_support import RaidenReleaseKeeper, NodeController

        self.task_count = 0
        self.running_task_count = 0
        self.auth = auth
        self.release_keeper = RaidenReleaseKeeper(data_path.joinpath('raiden_releases'))
        self.task_cache = {}
        self.task_storage = defaultdict(dict)

        self.scenario_name = os.path.basename(scenario_file.name).partition('.')[0]
        self.scenario = yaml.load(scenario_file)
        self.scenario_version = self.scenario.get('version', 1)
        if self.scenario_version not in SUPPORTED_SCENARIO_VERSIONS:
            raise ScenarioError(f'Unexpected scenario version {self.scenario_version}')

        self.data_path = data_path.joinpath('scenarios', self.scenario_name)
        self.data_path.mkdir(exist_ok=True, parents=True)
        log.debug('Data path', path=self.data_path)

        self.run_number = 0
        run_number_file = self.data_path.joinpath('run_number.txt')
        if run_number_file.exists():
            self.run_number = int(run_number_file.read_text()) + 1
        run_number_file.write_text(str(self.run_number))
        log.info('Run number', run_number=self.run_number)

        nodes = self.scenario['nodes']

        node_mode = NodeMode.EXTERNAL.name
        if self.is_v2:
            node_mode = nodes.get('mode', '').upper()
            if not node_mode:
                raise ScenarioError('Version 2 scenarios require a "mode" in the "nodes" section.')
        try:
            self.node_mode = NodeMode[node_mode]
        except KeyError:
            known_modes = ', '.join(mode.name.lower() for mode in NodeMode)
            raise ScenarioError(
                f'Unknown node mode "{node_mode}". Expected one of {known_modes}',
            ) from None

        if self.is_managed:
            self.node_controller = NodeController(
                self,
                nodes.get('raiden_version', 'LATEST'),
                nodes['count'],
                nodes.get('default_options', {}),
                nodes.get('node_options', {}),
            )
        else:
            if 'range' in nodes:
                range_config = nodes['range']
                template = range_config['template']
                self.raiden_nodes = [
                    template.format(i)
                    for i in range(range_config['first'], range_config['last'] + 1)
                ]
            else:
                self.raiden_nodes = nodes['list']
            self.node_commands = nodes.get('commands', {})

        settings = self.scenario.get('settings')
        if settings is None:
            settings = {}
        self.timeout = settings.get('timeout', TIMEOUT)
        if self.is_managed:
            self.protocol = 'http'
            if 'protocol' in settings:
                log.warning('The "protocol" setting is not supported in "managed" node mode.')
        else:
            self.protocol = settings.get('protocol', 'http')
        self.notification_email = settings.get('notify')
        self.chain_name = settings.get('chain', 'any')

        if self.chain_name == 'any':
            self.chain_name = random.choice(list(chain_urls.keys()))
        elif self.chain_name not in chain_urls:
            raise ScenarioError(
                f'The scenario requested chain "{self.chain_name}" for which no RPC-URL is known.',
            )
        log.info('Using chain', chain=self.chain_name)
        self.eth_rpc_urls = chain_urls[self.chain_name]

        self.client = JSONRPCClient(
            Web3(HTTPProvider(chain_urls[self.chain_name][0])),
            privkey=account.privkey,
            gas_price_strategy=get_gas_price_strategy(settings.get('gas_price', 'fast')),
        )

        self.chain_id = self.client.web3.net.version
        self.contract_manager = ContractManager(contracts_precompiled_path())

        balance = self.client.balance(account.address)
        if balance < OWN_ACCOUNT_BALANCE_MIN:
            raise ScenarioError(
                f'Insufficient balance ({balance / 10 ** 18} Eth) '
                f'in account {to_checksum_address(account.address)} on chain "{self.chain_name}"',
            )

        self.session = Session()
        # WTF? https://github.com/requests/requests/issues/2605
        if auth:
            self.session.auth = tuple(auth.split(":"))
        self.session.mount('http', TimeOutHTTPAdapter(timeout=self.timeout))
        self.session.mount('https', TimeOutHTTPAdapter(timeout=self.timeout))

        self._node_to_address = None
        self.token_address = None
        self.token_deployment_block = 0

        scenario_config = self.scenario.get('scenario')
        if not scenario_config:
            raise ScenarioError("Invalid scenario definition. Missing 'scenario' key.")

        try:
            (root_task_type, root_task_config), = scenario_config.items()
        except ValueError:
            # will be thrown if it's not a 1-element dict
            raise ScenarioError(
                "Invalid scenario definition. "
                "Exactly one root task is required below the 'scenario' key.",
            ) from None

        task_class = get_task_class_for_type(root_task_type)
        self.root_task = task_class(runner=self, config=root_task_config)

    def run_scenario(self):
        fund_tx = []
        node_starter: gevent.Greenlet = None
        if self.is_managed:
            self.node_controller.initialize_nodes()
            node_addresses = self.node_controller.addresses
            node_balances = {
                address: self.client.balance(address)
                for address in node_addresses
            }
            low_balances = {
                address: balance
                for address, balance in node_balances.items()
                if balance < NODE_ACCOUNT_BALANCE_MIN
            }
            if low_balances:
                log.info('Funding nodes', nodes=low_balances.keys())
                fund_tx = [
                    self.client.send_transaction(
                        to=address,
                        startgas=21000,
                        value=NODE_ACCOUNT_BALANCE_FUND - balance,
                    )
                    for address, balance in low_balances.items()
                ]
            node_starter = self.node_controller.start(wait=False)
        else:
            log.info("Fetching node addresses")
            unreachable_nodes = [node for node, addr in self.node_to_address.items() if not addr]
            if not self.node_to_address or unreachable_nodes:
                raise NodesUnreachableError(
                    f"Raiden nodes unreachable: {','.join(unreachable_nodes)}",
                )

        token_ctr, token_block = get_or_deploy_token(self)
        token_address = self.token_address = to_checksum_address(token_ctr.contract_address)
        self.token_deployment_block = token_block
        first_node = self.get_node_baseurl(0)

        token_settings = self.scenario.get('token') or {}
        token_balance_min = token_settings.get(
            'balance_min',
            DEFAULT_TOKEN_BALANCE_MIN,
        )
        token_balance_fund = token_settings.get(
            'balance_fund',
            DEFAULT_TOKEN_BALANCE_FUND,
        )

        mint_tx = []
        if self.is_managed:
            addresses = self.node_controller.addresses
        else:
            addresses = self.node_to_address.values()
        for address in addresses:
            balance = token_ctr.contract.functions.balanceOf(address).call()
            if balance < token_balance_min:
                mint_amount = token_balance_fund - balance
                startgas = GAS_LIMIT_FOR_TOKEN_CONTRACT_CALL
                log.debug("Minting tokens for", address=address, amount=mint_amount)
                mint_tx.append(token_ctr.transact('mintFor', startgas, mint_amount, address))
            elif balance > token_balance_min:
                log.warning("Node is overfunded", address=address, balance=balance)

        wait_for_txs(self.client, mint_tx + fund_tx)

        if node_starter is not None:
            log.debug('Waiting for nodes to finish starting')
            node_starter.get(block=True)

        registered_tokens = set(
            self.session.get(
                API_URL_TOKENS.format(protocol=self.protocol, target_host=first_node),
            ).json(),
        )
        if token_address not in registered_tokens:
            code, msg = self.register_token(token_address, first_node)
            if not 199 < code < 300:
                log.error("Couldn't register token with network", code=code, message=msg)
                raise TokenRegistrationError(msg)

        # The nodes need some time to find the token, see
        # https://github.com/raiden-network/raiden/issues/3544
        log.info('Waiting till new network is found by nodes')
        gevent.sleep(10)

        self.token_network_address = self.session.get(API_URL_TOKEN_NETWORK_ADDRESS.format(
            protocol=self.protocol,
            target_host=first_node,
            token_address=self.token_address,
        )).json()

        # Start root task
        root_task_greenlet = gevent.spawn(self.root_task)
        greenlets = [root_task_greenlet]
        if self.is_managed:
            greenlets.append(self.node_controller.start_node_monitor())
        try:
            gevent.joinall(greenlets, raise_error=True)
        except BaseException:
            if not root_task_greenlet.dead:
                # Make sure we kill the tasks if a node dies
                root_task_greenlet.kill()
            raise

    def register_token(self, token_address, node):
        try:
            base_url = API_URL_TOKENS.format(protocol=self.protocol, target_host=node)
            url = "{}/{}".format(base_url, token_address)
            log.info("Registering token with network", url=url)
            resp = self.session.put(url)
            code = resp.status_code
            msg = resp.text
        except RequestException as ex:
            code = -1
            msg = str(ex)
        return code, msg

    def _spawn_and_wait(self, objects, callback):
        tasks = {obj: gevent.spawn(callback, obj) for obj in objects}
        gevent.joinall(tasks.values())
        return {obj: task.get() for obj, task in tasks.items()}

    @property
    def is_v2(self):
        return self.scenario_version == 2

    @property
    def is_managed(self):
        return self.node_mode is NodeMode.MANAGED

    def get_node_address(self, index):
        if self.is_managed:
            return self.node_controller[index].address
        else:
            return self.node_to_address[self.raiden_nodes[index]]

    def get_node_baseurl(self, index):
        if self.is_managed:
            return self.node_controller[index].base_url
        else:
            return self.raiden_nodes[index]

    # Legacy for 'external' nodes
    def _get_node_addresses(self, nodes):
        def cb(node):
            log.debug("Getting node address", node=node)
            url = API_URL_ADDRESS.format(protocol=self.protocol, target_host=node)
            log.debug("Requesting", url=url)
            try:
                resp = self.session.get(url)
            except RequestException:
                log.error("Error fetching node address", url=url, node=node)
                return
            try:
                return resp.json().get('our_address', '')
            except ValueError:
                log.error(
                    "Error decoding response",
                    response=resp.text,
                    code=resp.status_code,
                    url=url,
                )
        ret = self._spawn_and_wait(nodes, cb)
        return ret

    @property
    def node_to_address(self):
        if not self.raiden_nodes:
            return {}
        if self._node_to_address is None:
            self._node_to_address = {
                node: address
                for node, address
                in self._get_node_addresses(self.raiden_nodes).items()
            }
        return self._node_to_address
