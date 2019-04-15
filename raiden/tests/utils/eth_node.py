import json
import os
import shutil
import subprocess
import time
from contextlib import ExitStack, contextmanager
from typing import ContextManager, Union

import gevent
import structlog
from eth_keyfile import create_keyfile_json
from eth_utils import encode_hex, remove_0x_prefix, to_checksum_address, to_normalized_address
from web3 import Web3

from raiden.tests.fixtures.constants import DEFAULT_BALANCE_BIN, DEFAULT_PASSPHRASE
from raiden.tests.utils.genesis import GENESIS_STUB, PARITY_CHAIN_SPEC_STUB
from raiden.utils import privatekey_to_address, privatekey_to_publickey
from raiden.utils.http import JSONRPCExecutor
from raiden.utils.typing import Any, Dict, List, NamedTuple

log = structlog.get_logger(__name__)  # pylint: disable=invalid-name


_GETH_VERBOSITY_LEVEL = {
    'error': 1,
    'warn': 2,
    'info': 3,
    'debug': 4,
}


class EthNodeDescription(NamedTuple):
    private_key: bytes
    rpc_port: int
    p2p_port: int
    miner: bool
    blockchain_type: str = 'geth'


def clique_extradata(extra_vanity, extra_seal):
    if len(extra_vanity) > 64:
        raise ValueError('extra_vanity length must be smaller-or-equal to 64')

    # Format is determined by the clique PoA:
    # https://github.com/ethereum/EIPs/issues/225
    # - First EXTRA_VANITY bytes (fixed) may contain arbitrary signer vanity data
    # - Last EXTRA_SEAL bytes (fixed) is the signer's signature sealing the header
    return '0x{:0<64}{:0<170}'.format(
        extra_vanity,
        extra_seal,
    )


def geth_to_cmd(
        node: Dict,
        datadir: str,
        chain_id: int,
        verbosity: str,
) -> List[str]:
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
        'nodekeyhex',
        'port',
        'rpcport',
        'bootnodes',
        'minerthreads',
        'unlock',
        'password',
    ]

    cmd = ['geth']

    for config in node_config:
        if config in node:
            value = node[config]
            cmd.extend([f'--{config}', str(value)])

    # dont use the '--dev' flag
    cmd.extend([
        '--nodiscover',
        '--rpc',
        '--rpcapi', 'eth,net,web3,personal,txpool',
        '--rpcaddr', '0.0.0.0',
        '--networkid', str(chain_id),
        '--verbosity', str(_GETH_VERBOSITY_LEVEL[verbosity]),
        '--datadir', datadir,
    ])

    if node.get('mine', False):
        cmd.append('--mine')

    log.debug('geth command', command=cmd)

    return cmd


def parity_to_cmd(
        node: Dict,
        datadir: str,
        chain_id: int,
        chain_spec: str,
        verbosity: str,
) -> List[str]:

    node_config = {
        'nodekeyhex': 'node-key',
        'password': 'password',
        'port': 'port',
        'rpcport': 'jsonrpc-port',
    }

    cmd = ['parity']

    for config, option in node_config.items():
        if config in node:
            cmd.append(f'--{option}={node[config]}')

    cmd.extend([
        '--jsonrpc-apis=eth,net,web3,parity,personal',
        '--jsonrpc-interface=0.0.0.0',
        '--no-discovery',
        '--no-ws',
        '--no-ipc',  # Disable IPC to prevent 'path too long' errors on macOS
        '--min-gas-price=1800000000',
        f'--base-path={datadir}',
        f'--chain={chain_spec}',
        f'--network-id={chain_id}',
        f'--logging={verbosity}',
    ])

    if node.get('mine', False):
        cmd.extend([
            f"--engine-signer={to_checksum_address(node['address'])}",
            '--force-sealing',
        ])

    log.debug('parity command', command=cmd)

    return cmd


def geth_create_account(datadir: str, privkey: bytes):
    """
    Create an account in `datadir` -- since we're not interested
    in the rewards, we don't care about the created address.

    Args:
        datadir: the datadir in which the account is created
        privkey: the private key for the account
    """
    keyfile_path = os.path.join(datadir, 'keyfile')
    with open(keyfile_path, 'wb') as handler:
        handler.write(
            remove_0x_prefix(encode_hex(privkey)).encode(),
        )

    create = subprocess.Popen(
        ['geth', '--datadir', datadir, 'account', 'import', keyfile_path],
        stdin=subprocess.PIPE,
        universal_newlines=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    create.stdin.write(DEFAULT_PASSPHRASE + os.linesep)
    time.sleep(.1)
    create.stdin.write(DEFAULT_PASSPHRASE + os.linesep)
    create.communicate()
    assert create.returncode == 0


def parity_generate_chain_spec(
        spec_path: str,
        accounts_addresses: List[bytes],
        seal_account: Union[str, bytes],
        random_marker: str,
        chain_id: int,
):
    chain_spec = PARITY_CHAIN_SPEC_STUB.copy()
    chain_spec['params']['networkID'] = chain_id
    chain_spec['accounts'].update({
        to_checksum_address(address): {'balance': 1000000000000000000}
        for address in accounts_addresses
    })
    chain_spec['engine']['authorityRound']['params']['validators'] = {
        'list': [to_checksum_address(seal_account)],
    }
    chain_spec['genesis']['extraData'] = f'0x{random_marker:0<64}'
    with open(spec_path, "w") as spec_file:
        json.dump(chain_spec, spec_file)


def geth_generate_poa_genesis(
        genesis_path: str,
        accounts_addresses: List[Union[str, bytes]],
        seal_address: Union[str, bytes],
        random_marker: str,
        chain_id: int,
):
    """Writes a bare genesis to `genesis_path`.

    Args:
        genesis_path: the path in which the genesis block is written.
        accounts_addresses: iterable list of privatekeys whose
            corresponding accounts will have a premined balance available.
        seal_address: Address of the ethereum account that can seal
            blocks in the PoA chain
    """

    alloc = {
        to_normalized_address(address): {
            'balance': DEFAULT_BALANCE_BIN,
        }
        for address in accounts_addresses
    }
    genesis = GENESIS_STUB.copy()
    genesis['alloc'].update(alloc)

    genesis['config']['ChainID'] = chain_id
    genesis['config']['clique'] = {'period': 1, 'epoch': 30000}

    genesis['extraData'] = clique_extradata(
        random_marker,
        remove_0x_prefix(to_normalized_address(seal_address)),
    )

    with open(genesis_path, 'w') as handler:
        json.dump(genesis, handler)


def geth_init_datadir(datadir: str, genesis_path: str):
    """Initialize a clients datadir with our custom genesis block.

    Args:
        datadir: the datadir in which the blockchain is initialized.
    """
    try:
        args = [
            'geth',
            '--datadir',
            datadir,
            'init',
            genesis_path,
        ]
        subprocess.check_output(args, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        msg = 'Initializing geth with custom genesis returned {} with error:\n {}'.format(
            e.returncode,
            e.output,
        )
        raise ValueError(msg)


def parity_write_key_file(key: bytes, keyhex: str, password_path: str, base_path: str) -> str:

    path = f'{base_path}/{(keyhex[:8]).lower()}'
    os.makedirs(f'{path}')

    password = DEFAULT_PASSPHRASE
    with open(password_path, 'w') as password_file:
        password_file.write(password)

    keyfile_json = create_keyfile_json(key, bytes(password, 'utf-8'))
    iv = keyfile_json['crypto']['cipherparams']['iv']
    keyfile_json['crypto']['cipherparams']['iv'] = f'{iv:0>32}'
    # Parity expects a string of length 32 here, but eth_keyfile does not pad
    with open(f'{path}/keyfile', 'w') as keyfile:
        json.dump(keyfile_json, keyfile)

    return path


def parity_create_account(
        node_configuration: Dict[str, Any],
        base_path: str,
        chain_spec: str,
) -> str:
    key = node_configuration['nodekey']
    keyhex = node_configuration['nodekeyhex']
    password = node_configuration['password']

    path = parity_write_key_file(key, keyhex, password, base_path)
    try:
        subprocess.run(
            [
                'parity',
                'account',
                'import',
                f'--base-path={path}',
                f'--chain={chain_spec}',
                f'--password={password}',
                f'{path}/keyfile',
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
    except subprocess.CalledProcessError as ex:
        raise RuntimeError(
            f'Creation of parity signer account failed with return code {ex.returncode}. '
            f'Output: {ex.output.decode()}',
        ) from ex
    return path


def eth_check_balance(web3: Web3, accounts_addresses: List[bytes], retries: int = 10) -> None:
    """ Wait until the given addresses have a balance.

    Raises a ValueError if any of the addresses still have no balance after ``retries``.
    """
    addresses = {to_checksum_address(account) for account in accounts_addresses}
    for _ in range(retries):
        for address in addresses.copy():
            if web3.eth.getBalance(address, 'latest') > 0:
                addresses.remove(address)
        gevent.sleep(1)

    if len(addresses) > 0:
        raise ValueError(f'Account(s) {", ".join(addresses)} have no balance')


def eth_node_config(miner_pkey: bytes, p2p_port: int, rpc_port: int) -> Dict[str, Any]:
    address = privatekey_to_address(miner_pkey)
    pub = privatekey_to_publickey(miner_pkey).hex()

    config = {
        'nodekey': miner_pkey,
        'nodekeyhex': remove_0x_prefix(encode_hex(miner_pkey)),
        'pub': pub,
        'address': address,
        'port': p2p_port,
        'rpcport': rpc_port,
        'enode': f'enode://{pub}@127.0.0.1:{p2p_port}',
    }

    return config


def eth_node_config_set_bootnodes(nodes_configuration: List[Dict[str, Any]]) -> None:
    bootnodes = ','.join(node['enode'] for node in nodes_configuration)

    for config in nodes_configuration:
        config['bootnodes'] = bootnodes


def eth_node_to_datadir(node_config, base_datadir):
    # HACK: Use only the first 8 characters to avoid golang's issue
    # https://github.com/golang/go/issues/6895 (IPC bind fails with path
    # longer than 108 characters).
    # BSD (and therefore macOS) socket path length limit is 104 chars
    nodekey_part = node_config['nodekeyhex'][:8]
    datadir = os.path.join(base_datadir, nodekey_part)
    return datadir


def eth_node_to_logpath(node_config, base_logdir):
    # HACK: Use only the first 8 characters to avoid golang's issue
    # https://github.com/golang/go/issues/6895 (IPC bind fails with path
    # longer than 108 characters).
    # BSD (and therefore macOS) socket path length limit is 104 chars
    nodekey_part = node_config['nodekeyhex'][:8]
    logpath = os.path.join(base_logdir, f'{nodekey_part}.log')
    return logpath


def geth_prepare_datadir(datadir, genesis_file):
    node_genesis_path = os.path.join(datadir, 'custom_genesis.json')
    ipc_path = datadir + '/geth.ipc'
    assert len(ipc_path) <= 104, f'geth data path "{ipc_path}" is too large'

    os.makedirs(datadir)
    shutil.copy(genesis_file, node_genesis_path)
    geth_init_datadir(datadir, node_genesis_path)


def eth_nodes_to_cmds(
        nodes_configuration,
        eth_node_descs,
        base_datadir,
        genesis_file,
        chain_id,
        verbosity,
):
    cmds = []
    for config, node_desc in zip(nodes_configuration, eth_node_descs):
        datadir = eth_node_to_datadir(config, base_datadir)

        if node_desc.blockchain_type == 'geth':
            geth_prepare_datadir(datadir, genesis_file)
            if node_desc.miner:
                geth_create_account(datadir, node_desc.private_key)
            commandline = geth_to_cmd(config, datadir, chain_id, verbosity)
        elif node_desc.blockchain_type == 'parity':
            commandline = parity_to_cmd(config, datadir, chain_id, genesis_file, verbosity)

        else:
            assert False, f'Invalid blockchain type {config.blockchain_type}'

        cmds.append(commandline)

    return cmds


@contextmanager
def eth_run_nodes(
        eth_node_descs: List[EthNodeDescription],
        nodes_configuration: List[Dict],
        base_datadir: str,
        genesis_file: str,
        chain_id: int,
        random_marker: str,
        verbosity: str,
        logdir: str,
) -> ContextManager[List[JSONRPCExecutor]]:

    def _validate_jsonrpc_result(result):
        running_marker = result['extraData'][2:len(random_marker) + 2]
        if running_marker != random_marker:
            return (
                False,
                (
                    'The test marker does not match, maybe two tests are running in '
                    'parallel with the same port?'
                ),
            )
        return True, None

    os.makedirs(logdir, exist_ok=True)

    password_path = os.path.join(base_datadir, 'pw')
    with open(password_path, 'w') as handler:
        handler.write(DEFAULT_PASSPHRASE)

    cmds = eth_nodes_to_cmds(
        nodes_configuration,
        eth_node_descs,
        base_datadir,
        genesis_file,
        chain_id,
        verbosity,
    )

    with ExitStack() as stack:
        executors = []
        for node_config, cmd in zip(nodes_configuration, cmds):
            log_path = eth_node_to_logpath(node_config, logdir)
            logfile = stack.enter_context(open(log_path, 'w+'))

            executor = JSONRPCExecutor(
                command=cmd,
                url=f'http://127.0.0.1:{node_config["rpcport"]}',
                timeout=10,
                jsonrpc_method='eth_getBlockByNumber',
                jsonrpc_params=['0x0', False],
                result_validator=_validate_jsonrpc_result,
                io=(subprocess.DEVNULL, logfile, subprocess.STDOUT),
            )

            stack.enter_context(executor)
            executors.append(executor)

        yield executors


@contextmanager
def run_private_blockchain(
        web3: Web3,
        accounts_to_fund: List[bytes],
        eth_nodes: List[EthNodeDescription],
        base_datadir: str,
        log_dir: str,
        chain_id: int,
        verbosity: str,
        random_marker: str,
):
    """ Starts a private network with private_keys accounts funded.

    Args:
        web3: A Web3 instance used to check when the private chain is running.
        accounts_to_fund: Accounts that will start with funds in
            the private chain.
        eth_nodes: A list of geth node
            description, containing the details of each node of the private
            chain.
        base_datadir: Directory used to store the geth databases.
        log_dir: Directory used to store the geth logs.
        verbosity: Verbosity used by the geth nodes.
        random_marker: A random marked used to identify the private chain.
    """
    # pylint: disable=too-many-locals,too-many-statements,too-many-arguments,too-many-branches

    nodes_configuration = []
    for node in eth_nodes:
        config = eth_node_config(
            node.private_key,
            node.p2p_port,
            node.rpc_port,
        )

        if node.miner:
            config['unlock'] = to_checksum_address(config['address'])
            config['mine'] = True
            config['password'] = os.path.join(base_datadir, 'pw')

        nodes_configuration.append(config)

    blockchain_type = eth_nodes[0].blockchain_type
    seal_account = privatekey_to_address(eth_nodes[0].private_key)

    if blockchain_type == 'geth':
        eth_node_config_set_bootnodes(nodes_configuration)

        genesis_path = os.path.join(base_datadir, 'custom_genesis.json')
        geth_generate_poa_genesis(
            genesis_path=genesis_path,
            accounts_addresses=accounts_to_fund,
            seal_address=seal_account,
            random_marker=random_marker,
            chain_id=chain_id,
        )

    elif blockchain_type == 'parity':
        genesis_path = f'{base_datadir}/chainspec.json'
        parity_generate_chain_spec(
            spec_path=genesis_path,
            accounts_addresses=accounts_to_fund,
            seal_account=seal_account,
            random_marker=random_marker,
            chain_id=chain_id,
        )
        parity_create_account(nodes_configuration[0], base_datadir, genesis_path)

    else:
        raise TypeError(f'Unknown blockchain client type "{blockchain_type}"')

    runner = eth_run_nodes(
        eth_node_descs=eth_nodes,
        nodes_configuration=nodes_configuration,
        base_datadir=base_datadir,
        genesis_file=genesis_path,
        chain_id=chain_id,
        random_marker=random_marker,
        verbosity=verbosity,
        logdir=log_dir,
    )
    with runner as executors:
        eth_check_balance(web3, accounts_to_fund)
        yield executors
