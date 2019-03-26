import pathlib
import random
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import gevent
import structlog
from eth_typing import ChecksumAddress
from eth_utils import to_checksum_address
from requests import RequestException, Session
from web3 import HTTPProvider, Web3

from raiden.accounts import Account
from raiden.constants import GAS_LIMIT_FOR_TOKEN_CONTRACT_CALL
from raiden.network.rpc.client import JSONRPCClient
from raiden.network.rpc.smartcontract_proxy import ContractProxy
from raiden.utils.typing import TransactionHash
from raiden_contracts.contract_manager import ContractManager, contracts_precompiled_path
from scenario_player.constants import (
    API_URL_ADDRESS,
    API_URL_TOKEN_NETWORK_ADDRESS,
    API_URL_TOKENS,
    DEFAULT_TOKEN_BALANCE_FUND,
    DEFAULT_TOKEN_BALANCE_MIN,
    NODE_ACCOUNT_BALANCE_FUND,
    NODE_ACCOUNT_BALANCE_MIN,
    OWN_ACCOUNT_BALANCE_MIN,
    NodeMode,
)
from scenario_player.exceptions import NodesUnreachableError, ScenarioError, TokenRegistrationError
from scenario_player.scenario import Scenario
from scenario_player.utils import (
    TimeOutHTTPAdapter,
    get_or_deploy_token,
    get_udc_and_token,
    mint_token_if_balance_low,
    wait_for_txs,
)

log = structlog.get_logger(__name__)


class ScenarioRunner:
    def __init__(
            self,
            account: Account,
            chain_urls: Dict[str, List[str]],
            auth: str,
            data_path: Path,
            scenario_file: Path,
    ):
        from scenario_player.node_support import RaidenReleaseKeeper, NodeController

        self.task_count = 0
        self.running_task_count = 0
        self.auth = auth
        self.release_keeper = RaidenReleaseKeeper(data_path.joinpath('raiden_releases'))
        self.task_cache = {}
        self.task_storage = defaultdict(dict)

        self.scenario = Scenario(pathlib.Path(scenario_file.name))
        self.scenario_name = self.scenario.name

        self.data_path = data_path.joinpath('scenarios', self.scenario.name)
        self.data_path.mkdir(exist_ok=True, parents=True)
        log.debug('Data path', path=self.data_path)

        self.run_number = self.determine_run_number()

        self.node_mode = self.scenario.nodes.mode

        if self.is_managed:
            self.node_controller = NodeController(
                self,
                self.scenario.nodes.raiden_version,
                self.scenario.nodes.count,
                self.scenario.nodes.default_options,
                self.scenario.nodes.node_options,
            )
        else:
            self.raiden_nodes = self.scenario.nodes
            self.node_commands = self.scenario.nodes.commands

        self.timeout = self.scenario.timeout
        self.protocol = self.scenario.protocol

        self.notification_email = self.scenario.notification_email

        self.chain_name, chain_urls = self.select_chain(chain_urls)
        self.eth_rpc_urls = chain_urls

        self.client = JSONRPCClient(
            Web3(HTTPProvider(chain_urls[0])),
            privkey=account.privkey,
            gas_price_strategy=self.scenario.gas_price_strategy,
        )

        self.chain_id = int(self.client.web3.net.version)
        self.contract_manager = ContractManager(contracts_precompiled_path())

        balance = self.client.balance(account.address)
        if balance < OWN_ACCOUNT_BALANCE_MIN:
            raise ScenarioError(
                f'Insufficient balance ({balance / 10 ** 18} Eth) '
                f'in account {to_checksum_address(account.address)} on chain "{self.chain_name}"',
            )

        self.session = Session()
        if auth:
            self.session.auth = tuple(auth.split(":"))
        self.session.mount('http', TimeOutHTTPAdapter(timeout=self.timeout))
        self.session.mount('https', TimeOutHTTPAdapter(timeout=self.timeout))

        self._node_to_address = None
        self.token_address = None
        self.token_deployment_block = 0
        self.token_network_address = None

        task_config = self.scenario.task_config
        task_class = self.scenario.task_class
        self.root_task = task_class(runner=self, config=task_config)

    def determine_run_number(self) -> int:
        """Determine the current run number.

        We check for a run number file, and use any number that is logged
        there after incrementing it.
        """
        run_number = 0
        run_number_file = self.data_path.joinpath('run_number.txt')
        if run_number_file.exists():
            run_number = int(run_number_file.read_text()) + 1
        run_number_file.write_text(str(run_number))
        log.info('Run number', run_number=run_number)
        return run_number

    def select_chain(self, chain_urls: Dict[str, List[str]]) -> Tuple[str, List[str]]:
        """Select a chain and return its name and RPC URL.

        If the currently loaded scenario's designated chain is set to 'any',
        we randomly select a chain from the given `chain_urls`.
        Otherwise, we will return `ScenarioRunner.scenario.chain_name` and whatever value
        may be associated with this key in `chain_urls`.

        :raises ScenarioError:
            if ScenarioRunner.scenario.chain_name is not one of `('any', 'Any', 'ANY')`
            and it is not a key in `chain_urls`.
        """
        chain_name = self.scenario.chain_name
        if chain_name in ('any', 'Any', 'ANY'):
            chain_name = random.choice(list(chain_urls.keys()))

        log.info('Using chain', chain=chain_name)
        try:
            return chain_name, chain_urls[chain_name]
        except KeyError:
            raise ScenarioError(
                f'The scenario requested chain "{chain_name}" for which no RPC-URL is known.',
            )

    def run_scenario(self):
        mint_gas = GAS_LIMIT_FOR_TOKEN_CONTRACT_CALL * 2

        fund_tx, node_starter, node_addresses, node_count = self._initialize_nodes()

        ud_token_tx, udc_ctr, should_deposit_ud_token = self._initialize_udc(
            gas_limit=mint_gas,
            node_count=node_count,
        )

        mint_tx = self._initialize_scenario_token(
            node_addresses=node_addresses,
            udc_ctr=udc_ctr,
            should_deposit_ud_token=should_deposit_ud_token,
            gas_limit=mint_gas,
        )

        wait_for_txs(self.client, fund_tx | ud_token_tx | mint_tx)

        if node_starter is not None:
            log.debug('Waiting for nodes to finish starting')
            node_starter.get(block=True)

        first_node = self.get_node_baseurl(0)

        registered_tokens = set(
            self.session.get(
                API_URL_TOKENS.format(protocol=self.protocol, target_host=first_node),
            ).json(),
        )
        if self.token_address not in registered_tokens:
            code, msg = self.register_token(self.token_address, first_node)
            if not 199 < code < 300:
                log.error("Couldn't register token with network", code=code, message=msg)
                raise TokenRegistrationError(msg)

        # The nodes need some time to find the token, see
        # https://github.com/raiden-network/raiden/issues/3544
        # FIXME: Add proper check via API
        log.info('Waiting till new network is found by nodes')
        while self.token_network_address is None:
            self.token_network_address = self.session.get(API_URL_TOKEN_NETWORK_ADDRESS.format(
                protocol=self.protocol,
                target_host=first_node,
                token_address=self.token_address,
            )).json()
            gevent.sleep(1)

        log.info(
            'Received token network address',
            token_network_address=self.token_network_address,
        )

        # Start root task
        root_task_greenlet = gevent.spawn(self.root_task)
        greenlets = {root_task_greenlet}
        if self.is_managed:
            greenlets.add(self.node_controller.start_node_monitor())
        try:
            gevent.joinall(greenlets, raise_error=True)
        except BaseException:
            if not root_task_greenlet.dead:
                # Make sure we kill the tasks if a node dies
                root_task_greenlet.kill()
            raise

    def _initialize_scenario_token(
            self,
            node_addresses: Set[ChecksumAddress],
            udc_ctr: Optional[ContractProxy],
            should_deposit_ud_token: bool,
            gas_limit: int,
    ) -> Set[TransactionHash]:
        token_ctr, token_block = get_or_deploy_token(self)
        self.token_address = to_checksum_address(token_ctr.contract_address)
        self.token_deployment_block = token_block
        token_settings = self.scenario.get('token') or {}
        token_balance_min = token_settings.get(
            'balance_min',
            DEFAULT_TOKEN_BALANCE_MIN,
        )
        token_balance_fund = token_settings.get(
            'balance_fund',
            DEFAULT_TOKEN_BALANCE_FUND,
        )
        mint_tx = set()
        for address in node_addresses:
            tx = mint_token_if_balance_low(
                token_contract=token_ctr,
                target_address=address,
                min_balance=token_balance_min,
                fund_amount=token_balance_fund,
                gas_limit=gas_limit,
                mint_msg="Minting tokens for",
            )
            if tx:
                mint_tx.add(tx)

            if not should_deposit_ud_token:
                continue
            ud_deposit_balance = udc_ctr.contract.functions.effectiveBalance(address).call()
            if ud_deposit_balance < DEFAULT_TOKEN_BALANCE_MIN // 2:
                deposit_amount = (DEFAULT_TOKEN_BALANCE_FUND // 2) - ud_deposit_balance
                log.debug("Depositing into UDC", address=address, amount=deposit_amount)
                mint_tx.add(
                    udc_ctr.transact(
                        'deposit',
                        gas_limit,
                        address,
                        DEFAULT_TOKEN_BALANCE_FUND // 2,
                    ),
                )
        return mint_tx

    def _initialize_udc(
            self,
            gas_limit: int,
            node_count: int,
    ) -> Tuple[Set[TransactionHash], Optional[ContractProxy], bool]:
        our_address = to_checksum_address(self.client.address)
        udc_settings = self.scenario.services.get('udc', {})
        udc_enabled = udc_settings.get('enable')

        ud_token_tx = set()

        if not udc_enabled:
            return ud_token_tx, None, False

        udc_ctr, ud_token_ctr = get_udc_and_token(self)

        ud_token_address = to_checksum_address(ud_token_ctr.contract_address)
        udc_address = to_checksum_address(udc_ctr.contract_address)

        log.info(
            'UDC enabled',
            contract_address=udc_address,
            token_address=ud_token_address,
        )

        should_deposit_ud_token = (
            udc_enabled and
            udc_settings.get('token', {}).get('deposit', False)
        )
        if should_deposit_ud_token:
            tx = mint_token_if_balance_low(
                token_contract=ud_token_ctr,
                target_address=our_address,
                min_balance=DEFAULT_TOKEN_BALANCE_FUND * node_count,
                fund_amount=DEFAULT_TOKEN_BALANCE_FUND * 10 * node_count,
                gas_limit=gas_limit,
                mint_msg="Minting UD tokens",
                no_action_msg="UD token balance sufficient",
            )
            if tx:
                ud_token_tx.add(tx)

            udt_allowance = (
                ud_token_ctr.contract.functions.allowance(our_address, udc_address).call()
            )
            if udt_allowance < DEFAULT_TOKEN_BALANCE_FUND * node_count:
                allow_amount = (DEFAULT_TOKEN_BALANCE_FUND * 10 * node_count) - udt_allowance
                log.debug('Updating UD token allowance', allowance=allow_amount)
                ud_token_tx.add(
                    ud_token_ctr.transact('approve', gas_limit, udc_address, allow_amount),
                )
            else:
                log.debug('UD token allowance sufficient', allowance=udt_allowance)
        return ud_token_tx, udc_ctr, should_deposit_ud_token

    def _initialize_nodes(self) -> Tuple[
            Set[TransactionHash],
            gevent.Greenlet,
            Set[ChecksumAddress],
            int,
    ]:
        fund_tx = set()
        node_starter: gevent.Greenlet = None
        if self.is_managed:
            self.node_controller.initialize_nodes()
            node_addresses = self.node_controller.addresses
            node_count = len(self.node_controller)
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
                fund_tx = {
                    self.client.send_transaction(
                        to=address,
                        startgas=21_000,
                        value=NODE_ACCOUNT_BALANCE_FUND - balance,
                    )
                    for address, balance in low_balances.items()
                }
            node_starter = self.node_controller.start(wait=False)

        else:
            log.info("Fetching node addresses")
            unreachable_nodes = [node for node, addr in self.node_to_address.items() if not addr]
            if not self.node_to_address or unreachable_nodes:
                raise NodesUnreachableError(
                    f"Raiden nodes unreachable: {','.join(unreachable_nodes)}",
                )
            node_addresses = set(self.node_to_address.values())
            node_count = len(self.node_to_address)
        return fund_tx, node_starter, node_addresses, node_count

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

    @staticmethod
    def _spawn_and_wait(objects, callback):
        tasks = {obj: gevent.spawn(callback, obj) for obj in objects}
        gevent.joinall(set(tasks.values()))
        return {obj: task.get() for obj, task in tasks.items()}

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
                return to_checksum_address(resp.json().get('our_address', ''))
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
    def node_to_address(self) -> Dict[str, ChecksumAddress]:
        if not self.raiden_nodes:
            return {}
        if self._node_to_address is None:
            self._node_to_address = {
                node: address
                for node, address
                in self._get_node_addresses(self.raiden_nodes).items()
            }
        return self._node_to_address
