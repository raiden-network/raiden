import pathlib
import random
from collections import defaultdict
from enum import Enum
from typing import Dict, List, Tuple, Any, Union
from pathlib import Path
from collections.abc import Mapping

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
from scenario_player.exceptions import (
    NodesUnreachableError,
    ScenarioError,
    TokenRegistrationError,
    MissingNodesConfiguration,
    MultipleTaskDefinitions,
    InvalidScenarioVersion,
)
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


class NodesConfig(Mapping):
    """Thin wrapper around a Node configuration dictionary.

    Handles exceptions handling for missing values. Additionally, enables users
    to iter directly over the internal .nodes property, while also allowing
    key-based access to the original configuration dictionary.

    :type nodes_config: Dict
    :type scenario_version: int
    """
    def __init__(self, nodes_config: Dict, scenario_version: int = 1):
        self._config = nodes_config
        self._scenario_version = scenario_version

    def __getitem__(self, item):
        return self._config.__getitem__(item)

    def __iter__(self):
        return iter(self.nodes)

    def __len__(self):
        return len(self.nodes)

    @property
    def mode(self):
        if self._scenario_version == 2:
            try:
                mode = self._config['mode'].upper()
            except KeyError:
                raise MissingNodesConfiguration(
                    'Version 2 scenarios require a "mode" in the "nodes" section.'
                )
            try:
                return NodeMode[mode]
            except KeyError:
                known_modes = ', '.join(mode.name.lower() for mode in NodeMode)
                raise ScenarioError(
                    f'Unknown node mode "{mode}". Expected one of {known_modes}',
                ) from None
        return NodeMode.EXTERNAL

    @property
    def raiden_version(self):
        return self._config.get('raiden_version', 'LATEST')

    @property
    def count(self):
        try:
            return self._config['count']
        except KeyError:
            raise MissingNodesConfiguration('Must specify a "count" setting!')

    @property
    def default_options(self):
        return self._config.get('default_options', {})

    @property
    def node_options(self):
        return self._config.get('node_options', {})

    @property
    def nodes(self) -> List[str]:
        """Return the list of nodes configured in the scenario's yaml.

        Should the scenario use version 1, we check if there is a 'setting'.
        If so, we derive the list of nodes from this dictionary, using its
        'first', 'last' and 'template' keys. Should any of these keys be
        missing, we throw an appropriate exception.

        If the scenario version is not 1, or no 'range' setting exists, we use
        the 'list' settings key and return the value. Again, should the key be
        absent, we throw an appropriate error.

        :raises MissingNodesConfiguration:
            if the scenario version is 1 and a 'range' key was detected, but any
            one of the keys 'first', 'last', 'template' are missing; *or* the
            scenario version is not 1 or the 'range' key and the 'list' are absent.
        :rtype: List
        """
        if self._scenario_version == 1 and 'range' in self._config:
            range_config = self._config['range']

            try:
                start, stop = range_config['first'], range_config['last'] + 1
            except KeyError:
                raise MissingNodesConfiguration(
                    'Setting "range" must be a dict containing keys "first" and "last",'
                    ' whose values are integers!'
                )

            try:
                template = range_config['template']
            except KeyError:
                raise MissingNodesConfiguration(
                    'Must specify "template" setting when giving "range" setting.'
                )

            return [template.format(i) for i in range(start, stop)]
        try:
            return self._config['list']
        except KeyError:
            raise MissingNodesConfiguration('Must specify nodes under "list" setting!')

    @property
    def commands(self) -> Dict:
        """Return the commands configured for the nodes.

        :rtype: Dict
        """
        return self._config.get('commands', {})


class Scenario(Mapping):
    """Thin wrapper class around a scenario .yaml file.

    Handles default values as well as exception handling on missing settings.

    :param pathlib.Path yaml_path: Path to the scenario's yaml file.
    """
    def __init__(self, yaml_path: pathlib.Path) -> None:
        self._yaml_path = yaml_path
        self._config = yaml.load(yaml_path.open())
        try:
            self._nodes = NodesConfig(self._config['nodes'], self.version)
        except KeyError:
            raise MissingNodesConfiguration('Must supply a "nodes" setting!')

    def __getitem__(self, item):
        return self._config.__getitem__(item)

    def __iter__(self):
        return iter(self._config)

    def __len__(self):
        return len(self._config)

    @property
    def version(self) -> int:
        """Return the scenario's version.

        If this is not present, we default to version 1.

        :raises InvalidScenarioVersion:
            if the supplied version is not present in :var:`SUPPORTED_SCENARIO_VERSIONS`.
        :rtype: int
        """
        version = self._config.get('version', 1)

        if version not in SUPPORTED_SCENARIO_VERSIONS:
            raise InvalidScenarioVersion(f'Unexpected scenario version {version}')
        return version

    @property
    def name(self) -> str:
        """Return the name of the scenario file, sans extension.

        :rtype: str
        """
        return self._yaml_path.stem

    @property
    def settings(self):
        """Return the 'settings' dictionary for the scenario.

        :rtype: Dict
        """
        return self._config.get('settings', {})

    @property
    def protocol(self) -> str:
        """Return the designated protocol of the scenario.

        If the node's mode is :attr:`NodeMode.MANAGED`, we always choose `http` and
        display a warning if there was a 'protocol' set explicitly in the
        scenario's yaml.

        Otherwise we simply access the 'protocol' key of the yaml, defaulting to
        'http' if it does not exist.

        :rtype: str
        """
        if self.nodes.mode is NodeMode.MANAGED:
            if 'protocol' in self._config:
                log.warning('The "protocol" setting is not supported in "managed" node mode.')
            return 'http'
        return self._config.get('protocol', 'http')

    @property
    def timeout(self) -> int:
        """Returns the scenario's set timeout in seconds.

        :rtype: int
        """
        return self.settings.get('timeout', TIMEOUT)

    @property
    def notification_email(self) -> Union[str, None]:
        """Return the email address to which notifications are to be sent.

        If this isn't set, we return None.

        :rtype: Union[str, None]
        """
        return self.settings.get('notify')

    @property
    def chain_name(self) -> str:
        """Return the name of the chain to be used for this scenario.

        :rtype: str
        """
        return self.settings.get('chain', 'any')

    @property
    def gas_price(self) -> str:
        """Return the configured gas price for this scenario.

        This defaults to 'fast'.

        :rtype: str
        """
        return self._config.get('gas_price', 'fast')

    @property
    def nodes(self) -> NodesConfig:
        """Return the configuration of nodes used in this scenario.

        :rtype: NodesConfig
        """
        return self._nodes

    @property
    def configuration(self):
        """Return the scenario's configuration.

        :raises ScenarioError: if no 'scenario' key is present in the yaml file.
        :rtype: Dict[str, Any]
        """
        try:
            return self._config['scenario']
        except KeyError:
            raise ScenarioError(
                "Invalid scenario definition. Missing 'scenario' key."
            )

    @property
    def task(self) -> Tuple[str, Any]:
        """Return the scenario's task configuration as a tuple.

        :raises MultipleTaskDefinitions:
            if there is more than one task config under the 'scenario' key.
        :rtype: Tuple[str, Any]
        """
        try:
            items, = self.configuration.items()
        except ValueError:
            raise MultipleTaskDefinitions(
                'Multiple tasks defined in scenario configuration!'
            )
        return items

    @property
    def task_config(self) -> Dict:
        """Return the task config for this scenario.

        TODO: Check this is the correct type
        :rtype: Dict
        """
        return self.task[1]

    @property
    def task_class(self):
        """Return the Task class type configured for the scenario.

        :rtype: Type[]
        """
        from scenario_player.tasks.base import get_task_class_for_type

        root_task_type, root_task_config = self.task

        task_class = get_task_class_for_type(root_task_type)
        return task_class


class ScenarioRunner(object):
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

        self.chain_name, chain_url = self.select_chain(chain_urls)
        self.eth_rpc_urls = chain_url

        self.client = JSONRPCClient(
            Web3(HTTPProvider(chain_url[0])),
            privkey=account.privkey,
            gas_price_strategy=get_gas_price_strategy(self.scenario.gas_price),
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

        task_config = self.scenario.task_config
        task_class = self.scenario.task_class
        self.root_task = task_class(runner=self, config=task_config)

    def determine_run_number(self):
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
