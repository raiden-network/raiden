import json
import os
import shutil
import subprocess
from contextlib import ExitStack, contextmanager
from typing import ContextManager, Iterator

import gevent
import structlog
from eth_keyfile import create_keyfile_json
from eth_utils import encode_hex, remove_0x_prefix, to_normalized_address
from pkg_resources import parse_version
from web3 import Web3

from raiden.constants import BLOCK_ID_LATEST
from raiden.tests.fixtures.constants import DEFAULT_PASSPHRASE
from raiden.tests.utils.genesis import GENESIS_STUB, PARITY_CHAIN_SPEC_STUB
from raiden.utils.ethereum_clients import parse_geth_version
from raiden.utils.formatting import to_checksum_address
from raiden.utils.http import JSONRPCExecutor
from raiden.utils.keys import privatekey_to_address, privatekey_to_publickey
from raiden.utils.typing import Address, Any, ChainID, Dict, List, NamedTuple, Port, TokenAmount

log = structlog.get_logger(__name__)


Command = List[str]
_GETH_VERBOSITY_LEVEL = {"error": 1, "warn": 2, "info": 3, "debug": 4}


class EthNodeDescription(NamedTuple):
    private_key: bytes
    rpc_port: Port
    p2p_port: Port
    miner: bool
    extra_config: Dict[str, Any]
    blockchain_type: str = "geth"


class AccountDescription(NamedTuple):
    address: Address
    balance: TokenAmount


class GenesisDescription(NamedTuple):
    """ Genesis configuration for a geth PoA private chain.

    Args:
        prefunded_accounts: iterable list of privatekeys whose
            corresponding accounts will have a premined balance available.
        random_marker: A unique used to preventing interacting with the wrong
            chain.
        chain_id: The id of the private chain.
    """

    prefunded_accounts: List[AccountDescription]
    random_marker: str
    chain_id: ChainID


def geth_clique_extradata(extra_vanity: str, extra_seal: str) -> str:
    if len(extra_vanity) > 64:
        raise ValueError("extra_vanity length must be smaller-or-equal to 64")

    # Format is determined by the clique PoA:
    # https://github.com/ethereum/EIPs/issues/225
    # - First EXTRA_VANITY bytes (fixed) may contain arbitrary signer vanity data
    # - Last EXTRA_SEAL bytes (fixed) is the signer's signature sealing the header
    return f"0x{extra_vanity:0<64}{extra_seal:0<170}"


def parity_extradata(random_marker: str) -> str:
    return f"0x{random_marker:0<64}"


def geth_to_cmd(node: Dict, datadir: str, chain_id: ChainID, verbosity: str) -> Command:
    """
    Transform a node configuration into a cmd-args list for `subprocess.Popen`.

    Args:
        node: a node configuration
        datadir: the node's datadir
        verbosity: verbosity one of {'error', 'warn', 'info', 'debug'}

    Return:
        cmd-args list
    """
    node_config = [
        "nodekeyhex",
        "port",
        "rpcport",
        "bootnodes",
        "minerthreads",
        "unlock",
        "password",
    ]

    cmd = ["geth"]

    for config in node_config:
        if config in node:
            value = node[config]
            cmd.extend([f"--{config}", str(value)])

    # Add parameters that are only required in newer versions
    geth_version_string, _ = subprocess.Popen(
        ["geth", "version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE
    ).communicate()

    geth_version_parse = parse_geth_version(geth_version_string.decode())

    if geth_version_parse is None:
        raise RuntimeError(
            "Couldn't parse geth version, please double check the binary is "
            "working properly, otherwise open a bug report to update the "
            "version format."
        )

    if geth_version_parse >= parse_version("1.9.0"):
        # Geth does not normally allow running an unlocked account
        # with the http interface. But since this a test blockchain we
        # can override that.
        cmd.append("--allow-insecure-unlock")

    # Don't use the '--dev' flag
    # Don't use `--nodiscover`. This flag completely disables the peer
    # discovery, even if the peers are given through the `--bootnodes`
    # configuration flag.
    cmd.extend(
        [
            "--rpc",
            "--rpcapi",
            "eth,net,web3,personal,debug",
            "--rpcaddr",
            "127.0.0.1",
            "--networkid",
            str(chain_id),
            "--verbosity",
            str(_GETH_VERBOSITY_LEVEL[verbosity]),
            "--datadir",
            datadir,
        ]
    )

    if node.get("mine", False):
        cmd.append("--mine")

    log.debug("geth command", command=cmd)

    return cmd


def parity_to_cmd(
    node: Dict, datadir: str, chain_id: int, chain_spec: str, verbosity: str
) -> Command:

    node_config = {
        "nodekeyhex": "node-key",
        "password": "password",
        "port": "port",
        "rpcport": "jsonrpc-port",
        "pruning-history": "pruning-history",
        "pruning": "pruning",
        "pruning-memory": "pruning-memory",
        "cache-size-db": "cache-size-db",
        "cache-size-blocks": "cache-size-blocks",
        "cache-size-queue": "cache-size-queue",
        "cache-size": "cache-size",
        "bootnodes": "bootnodes",
    }

    cmd = ["parity"]

    for config, option in node_config.items():
        if config in node:
            cmd.append(f"--{option}={node[config]}")

    cmd.extend(
        [
            "--jsonrpc-apis=eth,net,web3,parity,personal,traces",
            "--jsonrpc-interface=127.0.0.1",
            "--no-discovery",
            "--no-ws",
            "--no-ipc",  # Disable IPC to prevent 'path too long' errors on macOS
            "--min-gas-price=1800000000",
            f"--base-path={datadir}",
            f"--chain={chain_spec}",
            f"--network-id={chain_id}",
            f"--logging={verbosity}",
        ]
    )

    if node.get("mine", False):
        cmd.extend([f"--engine-signer={to_checksum_address(node['address'])}", "--force-sealing"])

    log.debug("parity command", command=cmd)

    return cmd


def geth_keystore(datadir: str) -> str:
    return os.path.join(datadir, "keystore")


def geth_keyfile(datadir: str) -> str:
    keystore = geth_keystore(datadir)
    os.makedirs(keystore, exist_ok=True)
    return os.path.join(keystore, "keyfile")


def eth_create_account_file(keyfile_path: str, privkey: bytes) -> None:
    keyfile_json = create_keyfile_json(privkey, bytes(DEFAULT_PASSPHRASE, "utf-8"))

    # Parity expects a string of length 32 here, but eth_keyfile does not pad
    iv = keyfile_json["crypto"]["cipherparams"]["iv"]
    keyfile_json["crypto"]["cipherparams"]["iv"] = f"{iv:0>32}"

    with open(keyfile_path, "w") as keyfile:
        json.dump(keyfile_json, keyfile)


def parity_generate_chain_spec(
    genesis_path: str, genesis_description: GenesisDescription, seal_account: Address
) -> None:
    alloc = {
        to_checksum_address(account.address): {"balance": str(account.balance)}
        for account in genesis_description.prefunded_accounts
    }
    validators = {"list": [to_checksum_address(seal_account)]}
    extra_data = parity_extradata(genesis_description.random_marker)

    chain_spec: dict = PARITY_CHAIN_SPEC_STUB.copy()
    chain_spec["params"]["networkID"] = genesis_description.chain_id
    chain_spec["accounts"].update(alloc)
    chain_spec["engine"]["authorityRound"]["params"]["validators"] = validators
    chain_spec["genesis"]["extraData"] = extra_data
    with open(genesis_path, "w") as spec_file:
        json.dump(chain_spec, spec_file)


def geth_generate_poa_genesis(
    genesis_path: str, genesis_description: GenesisDescription, seal_account: Address
) -> None:
    """Writes a bare genesis to `genesis_path`."""

    alloc = {
        to_normalized_address(account.address): {"balance": str(account.balance)}
        for account in genesis_description.prefunded_accounts
    }
    seal_address_normalized = remove_0x_prefix(encode_hex(seal_account))
    extra_data = geth_clique_extradata(genesis_description.random_marker, seal_address_normalized)

    genesis = GENESIS_STUB.copy()
    genesis["alloc"].update(alloc)
    genesis["config"]["ChainID"] = genesis_description.chain_id
    genesis["config"]["clique"] = {"period": 1, "epoch": 30000}
    genesis["extraData"] = extra_data

    with open(genesis_path, "w") as handler:
        json.dump(genesis, handler)


def geth_init_datadir(datadir: str, genesis_path: str):
    """Initialize a clients datadir with our custom genesis block.

    Args:
        datadir: the datadir in which the blockchain is initialized.
    """
    try:
        args = ["geth", "--datadir", datadir, "init", genesis_path]
        subprocess.check_output(args, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        msg = "Initializing geth with custom genesis returned {} with error:\n {}".format(
            e.returncode, e.output
        )
        raise ValueError(msg)


def parity_keystore(datadir: str) -> str:
    return os.path.join(datadir, "keys", "RaidenTestChain")


def parity_keyfile(datadir: str) -> str:
    keystore = parity_keystore(datadir)
    os.makedirs(keystore, exist_ok=True)
    return os.path.join(keystore, "keyfile")


def eth_check_balance(web3: Web3, accounts_addresses: List[Address], retries: int = 10) -> None:
    """ Wait until the given addresses have a balance.

    Raises a ValueError if any of the addresses still have no balance after ``retries``.
    """
    addresses = {to_checksum_address(account) for account in accounts_addresses}
    for _ in range(retries):
        for address in addresses.copy():
            if web3.eth.getBalance(address, BLOCK_ID_LATEST) > 0:
                addresses.remove(address)
        gevent.sleep(1)

    if len(addresses) > 0:
        raise ValueError(f'Account(s) {", ".join(addresses)} have no balance')


def eth_node_config(
    node_pkey: bytes, p2p_port: Port, rpc_port: Port, **extra_config: Any
) -> Dict[str, Any]:
    address = privatekey_to_address(node_pkey)
    pub = privatekey_to_publickey(node_pkey).hex()

    config = extra_config.copy()
    config.update(
        {
            "nodekey": node_pkey,
            "nodekeyhex": remove_0x_prefix(encode_hex(node_pkey)),
            "pub": pub,
            "address": address,
            "port": p2p_port,
            "rpcport": rpc_port,
            "enode": f"enode://{pub}@127.0.0.1:{p2p_port}",
        }
    )

    return config


def eth_node_config_set_bootnodes(nodes_configuration: List[Dict[str, Any]]) -> None:
    bootnodes = ",".join(node["enode"] for node in nodes_configuration)

    for config in nodes_configuration:
        config["bootnodes"] = bootnodes


def eth_node_to_datadir(node_address: bytes, base_datadir: str) -> str:
    # HACK: Use only the first 8 characters to avoid golang's issue
    # https://github.com/golang/go/issues/6895 (IPC bind fails with path
    # longer than 108 characters).
    # BSD (and therefore macOS) socket path length limit is 104 chars
    nodekey_part = encode_hex(node_address)[:8]
    datadir = os.path.join(base_datadir, nodekey_part)
    return datadir


def eth_node_to_logpath(node_config: Dict[str, Any], base_logdir: str) -> str:
    # HACK: Use only the first 8 characters to avoid golang's issue
    # https://github.com/golang/go/issues/6895 (IPC bind fails with path
    # longer than 108 characters).
    # BSD (and therefore macOS) socket path length limit is 104 chars
    nodekey_part = node_config["nodekeyhex"][:8]
    logpath = os.path.join(base_logdir, f"{nodekey_part}.log")
    return logpath


def geth_prepare_datadir(datadir: str, genesis_file: str) -> None:
    node_genesis_path = os.path.join(datadir, "custom_genesis.json")
    ipc_path = datadir + "/geth.ipc"
    assert len(ipc_path) < 104, f'geth data path "{ipc_path}" is too large'

    os.makedirs(datadir, exist_ok=True)
    shutil.copy(genesis_file, node_genesis_path)
    geth_init_datadir(datadir, node_genesis_path)


def eth_nodes_to_cmds(
    nodes_configuration: List[Dict[str, Any]],
    eth_node_descs: List[EthNodeDescription],
    base_datadir: str,
    genesis_file: str,
    chain_id: ChainID,
    verbosity: str,
) -> List[Command]:
    cmds = []
    for config, node_desc in zip(nodes_configuration, eth_node_descs):
        datadir = eth_node_to_datadir(config["address"], base_datadir)

        if node_desc.blockchain_type == "geth":
            geth_prepare_datadir(datadir, genesis_file)
            commandline = geth_to_cmd(config, datadir, chain_id, verbosity)
        elif node_desc.blockchain_type == "parity":
            commandline = parity_to_cmd(config, datadir, chain_id, genesis_file, verbosity)

        else:
            assert False, f"Invalid blockchain type {config['blockchain_type']}"

        cmds.append(commandline)

    return cmds


@contextmanager
def eth_run_nodes(
    eth_node_descs: List[EthNodeDescription],
    nodes_configuration: List[Dict],
    base_datadir: str,
    genesis_file: str,
    chain_id: ChainID,
    random_marker: str,
    verbosity: str,
    logdir: str,
) -> Iterator[List[JSONRPCExecutor]]:
    def _validate_jsonrpc_result(result):
        running_marker = result["extraData"][2 : len(random_marker) + 2]
        if running_marker != random_marker:
            return (
                False,
                (
                    "The test marker does not match, maybe two tests are running in "
                    "parallel with the same port?"
                ),
            )
        return True, None

    os.makedirs(logdir, exist_ok=True)

    cmds = eth_nodes_to_cmds(
        nodes_configuration, eth_node_descs, base_datadir, genesis_file, chain_id, verbosity
    )

    with ExitStack() as stack:
        executors = []
        for node_config, cmd in zip(nodes_configuration, cmds):
            log_path = eth_node_to_logpath(node_config, logdir)
            logfile = stack.enter_context(open(log_path, "w+"))

            startup_timeout = 20
            sleep = 0.1

            executor = JSONRPCExecutor(
                command=cmd,
                url=f'http://127.0.0.1:{node_config["rpcport"]}',
                timeout=startup_timeout,
                sleep=sleep,
                jsonrpc_method="eth_getBlockByNumber",
                jsonrpc_params=["0x0", False],
                result_validator=_validate_jsonrpc_result,
                io=(subprocess.DEVNULL, logfile, subprocess.STDOUT),
            )

            stack.enter_context(executor)
            executors.append(executor)

            # The timeout_limit_teardown is necessary to prevent the build
            # being killed because of the lack of output, at the same time the
            # timeout must never happen, because if it does, not all finalizers
            # are executed, leaving dirty state behind and resulting in test
            # flakiness.
            #
            # Because of this, this value is arbitrarily smaller than the
            # teardown timeout, forcing the subprocess to be killed on a timely
            # manner, which should allow the teardown to proceed and finish
            # before the timeout elapses.
            teardown_timeout = 0.5

            # The timeout values for the startup and teardown must be
            # different, however the library doesn't support it. So here we
            # must poke at the private member and overwrite it.
            executor._timeout = teardown_timeout

        yield executors


@contextmanager
def run_private_blockchain(
    web3: Web3,
    eth_nodes: List[EthNodeDescription],
    base_datadir: str,
    log_dir: str,
    verbosity: str,
    genesis_description: GenesisDescription,
) -> Iterator[List[JSONRPCExecutor]]:
    """ Starts a private network with private_keys accounts funded.

    Args:
        web3: A Web3 instance used to check when the private chain is running.
        eth_nodes: A list of geth node
            description, containing the details of each node of the private
            chain.
        base_datadir: Directory used to store the geth databases.
        log_dir: Directory used to store the geth logs.
        verbosity: Verbosity used by the geth nodes.
    """
    # pylint: disable=too-many-locals,too-many-statements,too-many-arguments,too-many-branches

    password_path = os.path.join(base_datadir, "pw")
    with open(password_path, "w") as handler:
        handler.write(DEFAULT_PASSPHRASE)

    nodes_configuration = []
    for node in eth_nodes:
        config = eth_node_config(
            node.private_key, node.p2p_port, node.rpc_port, **node.extra_config
        )

        if node.miner:
            config["unlock"] = to_checksum_address(config["address"])
            config["mine"] = True
            config["password"] = os.path.join(base_datadir, "pw")

        nodes_configuration.append(config)

    eth_node_config_set_bootnodes(nodes_configuration)

    blockchain_type = eth_nodes[0].blockchain_type

    # This is not be configurable because it must be one of the running eth
    # nodes.
    seal_account = privatekey_to_address(eth_nodes[0].private_key)

    if blockchain_type == "geth":
        genesis_path = os.path.join(base_datadir, "custom_genesis.json")
        geth_generate_poa_genesis(
            genesis_path=genesis_path,
            genesis_description=genesis_description,
            seal_account=seal_account,
        )

        for config in nodes_configuration:
            if config.get("mine"):
                datadir = eth_node_to_datadir(config["address"], base_datadir)
                keyfile_path = geth_keyfile(datadir)
                eth_create_account_file(keyfile_path, config["nodekey"])

    elif blockchain_type == "parity":
        genesis_path = os.path.join(base_datadir, "chainspec.json")
        parity_generate_chain_spec(
            genesis_path=genesis_path,
            genesis_description=genesis_description,
            seal_account=seal_account,
        )

        for config in nodes_configuration:
            if config.get("mine"):
                datadir = eth_node_to_datadir(config["address"], base_datadir)
                keyfile_path = parity_keyfile(datadir)
                eth_create_account_file(keyfile_path, config["nodekey"])

    else:
        raise TypeError(f'Unknown blockchain client type "{blockchain_type}"')

    runner: ContextManager[List[JSONRPCExecutor]] = eth_run_nodes(
        eth_node_descs=eth_nodes,
        nodes_configuration=nodes_configuration,
        base_datadir=base_datadir,
        genesis_file=genesis_path,
        chain_id=genesis_description.chain_id,
        random_marker=genesis_description.random_marker,
        verbosity=verbosity,
        logdir=log_dir,
    )
    with runner as executors:
        eth_check_balance(
            web3, [account.address for account in genesis_description.prefunded_accounts]
        )
        yield executors
