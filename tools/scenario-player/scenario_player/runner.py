import pathlib
import random
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Tuple

import gevent
import structlog
from eth_utils import to_checksum_address
from requests import RequestException, Session
from web3 import HTTPProvider, Web3

from raiden.accounts import Account
from raiden.constants import GAS_LIMIT_FOR_TOKEN_CONTRACT_CALL
from raiden.network.rpc.client import JSONRPCClient

from raiden_contracts.contract_manager import ContractManager, contracts_precompiled_path
from scenario_player.constants import (
    API_URL_ADDRESS,
    API_URL_TOKEN_NETWORK_ADDRESS,
    API_URL_TOKENS,
    NODE_ACCOUNT_BALANCE_FUND,
    NODE_ACCOUNT_BALANCE_MIN,
    OWN_ACCOUNT_BALANCE_MIN,
    START_GAS,
    NodeMode,
)
from scenario_player.exceptions import (
    NodesUnreachableError,
    NoNodeAddressesAvailable,
    ScenarioError,
    TokenRegistrationError,
)
from scenario_player.releases import ReleaseManager
from scenario_player.scenario import Scenario
from scenario_player.utils import TimeOutHTTPAdapter, get_or_deploy_token, wait_for_txs

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
        from scenario_player.node_support import NodeController

        self.task_count = 0
        self.running_task_count = 0
        self.auth = auth
        self.release_keeper = ReleaseManager(data_path.joinpath('raiden_releases'))
        self.task_cache = {}
        # Storage for arbitrary data tasks might need to persist
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

    def fund_single_node(self, node_address: str):
        """Check the balance of a single node and fund it if necessary.

        Should the node require funding, we return the transaction's receipt:
        otherwise, we return None.

        :type node_address: str
        """
        node_balance = self.client.balance(node_address)
        if node_balance < NODE_ACCOUNT_BALANCE_MIN:
            log.info('Funding node', node=node_address)
            return self.client.send_transaction(
                to=node_address,
                startgas=START_GAS,
                value=NODE_ACCOUNT_BALANCE_FUND - node_balance,
            )
        return None

    def fund_nodes(self, node_addresses):
        """Fund the given nodes if necessary.

        Should any require funding, we attach the receipt of the funding
        transaction to the returned list.

        If no nodes required funding, we return an empty list.

        :type node_addresses: List[str]
        :rtype: List
        """
        transactions = []
        for address in node_addresses:
            receipt = self.fund_single_node(address)
            if receipt:
                transactions.append(receipt)
        return transactions

    def fetch_node_addresses(self):
        """Fetch addresses for our nodes.

        If ScenarioRunner.node_to_address returns a falsy value, we raise a
        :exc:`NoNodeAddresseAvailable` exception. Otherwise we check for unreachable
        nodes. Should ANY of them be unreachable, a :exc:`NodesUnreachableError`
        is raised.

        Otherwise, the method returns None.

        :raises NoNodeAddressesAvailable:
            if :attr"`ScenarioRunner.node_to_address` returns an empty dictionary.
        :raises NodesUnreachable:
            if ANY node has no address associated with it in the dict returned
            by :attr:`ScenarioRunner.node_to_address`.
        """
        log.info("Fetching node addresses")
        unreachable_nodes = [node for node, addr in self.node_to_address.items() if not addr]
        if not self.node_to_address or unreachable_nodes:
            raise NoNodeAddressesAvailable(
                'No node addresses were found - ScenarioRunner.node_to_address empty!',
            )
        if unreachable_nodes:
            raise NodesUnreachableError(
                f"Raiden nodes unreachable: {','.join(unreachable_nodes)}",
            )

    def mint_token_for_node(self, address, token_controller):
        """Mint an amount of tokens for node with given address.

        This does nothing if the balance of the node is adequate, logs a warning
        if it is over-funded and mints the difference of minimum required tokens
        and the current balance of the node if it is under-funded.

        Returns the transaction receipt of the mint request if tokens were
        minted.
        """
        balance = token_controller.contract.functions.balanceOf(address).call()
        if balance < self.scenario.token_balance_min:
            mint_amount = self.scenario.token_balance_fund - balance
            startgas = GAS_LIMIT_FOR_TOKEN_CONTRACT_CALL
            log.debug("Minting tokens for", address=address, amount=mint_amount)
            return token_controller.transact('mintFor', startgas, mint_amount, address)
        elif balance > self.scenario.token_balance_min:
            log.warning("Node is over-funded", address=address, balance=balance)
        return None

    def mint_token_for_nodes(self, token_controller) -> List:
        """Iterate over present nodes and mint tokens for them as necessary.

        Returns a list of receipts for each batch of minted tokens, if any.
        """
        mint_tx = []

        if self.is_managed:
            addresses = self.node_controller.addresses
        else:
            addresses = self.node_to_address.values()

        for address in addresses:
            receipt = self.mint_token_for_node(address, token_controller)
            mint_tx.append(receipt)

        return mint_tx

    def register_token(self, token_address, node) -> Tuple[int, str]:
        """Register the token at the given node.

        Returns the HTTP response status code and the response body as text.
        Should an exception occur, the code will be set to -1 and the exception
        stringified.

        :rtype: Tuple[int, str]
        """
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

    def register_token_with_network(self, node: str) -> None:
        """Register our token with the network.

        We check if our token's address is already registered - if it is,
        we do nothing. Otherwise we try to register with the network.

        Should this return a non-2xx HTTP response, we raise a
        :exc:`TokenRegistrationError` excpetion.

        :raises TokenRegistrationError:
            if the HTTP response status code of the registration request
            is not in the 2xx range.
        """
        # We need to pick a node to use as inception node; by default, we simply
        # use the first node in the list.
        registered_tokens = set(
            self.session.get(
                API_URL_TOKENS.format(protocol=self.protocol, target_host=node),
            ).json(),
        )

        if self.token_address not in registered_tokens:
            code, msg = self.register_token(self.token_address, node)
            if not 199 < code < 300:
                log.error("Couldn't register token with network", code=code, message=msg)
                raise TokenRegistrationError(msg)

    def run_scenario(self):
        fund_tx = []
        node_starter: gevent.Greenlet = None

        # Fetch our nodes and their addresses, and fund them if necessary.
        if self.is_managed:
            self.node_controller.initialize_nodes()
            fund_tx = self.fund_nodes(self.node_controller.addresses)
            node_starter = self.node_controller.start(wait=False)
        else:
            self.fetch_node_addresses()

        # Let's mint some tokens for our nodes.
        token_controller, token_block = get_or_deploy_token(self)
        mint_tx = self.mint_token_for_nodes(token_controller)

        self.token_address = to_checksum_address(token_controller.contract_address)
        self.token_deployment_block = token_block

        # We'll wait here for our transactions to complete.
        wait_for_txs(self.client, mint_tx + fund_tx)

        # If the nodes haven't fired up yet, we'll wait here again.
        if node_starter is not None:
            log.debug('Waiting for nodes to finish starting')
            node_starter.get(block=True)

        # Register our tokens
        first_node = self.get_node_baseurl(0)
        self.register_token_with_network(first_node)

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
        self.execute_task(root_task_greenlet)

    def execute_task(self, greenlet):
        """Execute the given `greenlet`.

        Ensures the greenlet is truly dead if an exception occurs, before
        re-raising the exception and propagating it upwards.
        """
        greenlets = set([greenlet])
        if self.is_managed:
            greenlets.add(self.node_controller.start_node_monitor())
        try:
            gevent.joinall(greenlets, raise_error=True)
        except BaseException:
            if not greenlet.dead:
                # Make sure we kill the tasks if a node dies
                greenlet.kill()
            raise

    @staticmethod
    def _spawn_and_wait(objects, callback):
        tasks = {obj: gevent.spawn(callback, obj) for obj in objects}
        gevent.joinall(set(tasks.values()))
        return {obj: task.get() for obj, task in tasks.items()}

    @property
    def is_v2(self) -> bool:
        return self.scenario.version == 2

    @property
    def is_managed(self) -> bool:
        return self.node_mode is NodeMode.MANAGED

    def get_node_address(self, index) -> str:
        if self.is_managed:
            return self.node_controller[index].address
        else:
            return self.node_to_address[self.raiden_nodes[index]]

    def get_node_baseurl(self, index) -> str:
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
                return None
            try:
                return to_checksum_address(resp.json().get('our_address', ''))
            except ValueError:
                log.error(
                    "Error decoding response",
                    response=resp.text,
                    code=resp.status_code,
                    url=url,
                )
            return None
        ret = self._spawn_and_wait(nodes, cb)
        return ret

    @property
    def node_to_address(self) -> Dict:
        if not self.raiden_nodes:
            return {}
        if self._node_to_address is None:
            self._node_to_address = {
                node: address
                for node, address
                in self._get_node_addresses(self.raiden_nodes).items()
            }
        return self._node_to_address
