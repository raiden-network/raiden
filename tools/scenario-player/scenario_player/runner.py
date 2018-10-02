from pathlib import Path

import gevent
import structlog
import yaml
from eth_utils import to_checksum_address
from requests import RequestException, Session
from toolz import first
from web3 import HTTPProvider, Web3

from raiden.accounts import Account
from raiden.network.rpc.client import JSONRPCClient
from scenario_player.exceptions import NodesUnreachableError, ScenarioError, TokenRegistrationError
from scenario_player.utils import (
    TimeOutHTTPAdapter,
    get_gas_price_strategy,
    get_or_deploy_token,
    wait_for_txs,
)

log = structlog.get_logger(__name__)


DEFAULT_TOKEN_BALANCE_MIN = 5 * 10 ** 4
TIMEOUT = 200
API_URL_ADDRESS = "{protocol}://{target_host}/api/1/address"
API_URL_TOKENS = "{protocol}://{target_host}/api/1/tokens"
API_URL_CHANNELS = "{protocol}://{target_host}/api/1/channels"
API_URL_TRANSFERS = "{protocol}://{target_host}/api/1/payments/{token_address}/{partner_address}"
API_URL_CONNECT = "{protocol}://{target_host}/api/1/connection/{token_address}"


class ScenarioRunner(object):
    def __init__(
        self,
        account: Account,
        rpc_url: str,
        auth: str,
        scenario_file: Path,
    ):
        self.task_count = 0
        self.running_task_count = 0
        self.root_task = None
        self.auth = auth

        self.scenario = yaml.load(scenario_file)

        nodes = self.scenario['nodes']
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
        self.protocol = settings.get('protocol', 'http')
        self.notification_email = settings.get('notify')

        self.client = JSONRPCClient(
            Web3(HTTPProvider(rpc_url)),
            privkey=account.privkey,
            gas_price_strategy=get_gas_price_strategy(settings.get('gas_price', 'fast')),
        )

        self.session = Session()
        # WTF? https://github.com/requests/requests/issues/2605
        if auth:
            self.session.auth = tuple(auth.split(":"))
        self.session.mount('http', TimeOutHTTPAdapter(timeout=self.timeout))
        self.session.mount('https', TimeOutHTTPAdapter(timeout=self.timeout))

        self._node_to_address = None
        self.token_address = None

    def run_scenario(self):
        from scenario_player.tasks.base import get_task_class_for_type

        log.info("Fetching node addresses")
        unreachable_nodes = [node for node, addr in self.node_to_address.items() if not addr]
        if not self.node_to_address or unreachable_nodes:
            raise NodesUnreachableError(f"Raiden nodes unreachable: {','.join(unreachable_nodes)}")
        token_ctr = get_or_deploy_token(self.client, self.scenario)
        token_address = self.token_address = to_checksum_address(token_ctr.contract_address)
        first_node = first(self.raiden_nodes)

        token_settings = self.scenario.get('token') or {}
        token_balance_min = token_settings.get(
            'balance_min',
            DEFAULT_TOKEN_BALANCE_MIN,
        )

        mint_tx = []
        for node, address in self.node_to_address.items():
            balance = token_ctr.contract.functions.balanceOf(address).call()
            if balance < token_balance_min:
                mint_amount = token_balance_min - balance
                log.debug("Minting tokens for", address=address, node=node, amount=mint_amount)
                mint_tx.append(token_ctr.transact('mintFor', mint_amount, address))
            elif balance > token_balance_min:
                log.warning("Node is overfunded", address=address, node=node, balance=balance)
        wait_for_txs(self.client, mint_tx)

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
        self.root_task()

    def get_node_addresses(self, nodes):
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

    @property
    def node_to_address(self):
        if not self.raiden_nodes:
            return {}
        if self._node_to_address is None:
            self._node_to_address = {
                node: address
                for node, address
                in self.get_node_addresses(self.raiden_nodes).items()
            }
        return self._node_to_address

    def _spawn_and_wait(self, objects, callback):
        tasks = {obj: gevent.spawn(callback, obj) for obj in objects}
        gevent.joinall(tasks.values())
        return {obj: task.get() for obj, task in tasks.items()}
