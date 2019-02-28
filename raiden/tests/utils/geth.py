import io
import json
import os
import shutil
import subprocess
import sys
import termios
import time

import gevent
import requests
import structlog
from eth_utils import encode_hex, remove_0x_prefix, to_checksum_address, to_normalized_address
from web3 import Web3

from raiden.tests.fixtures.variables import DEFAULT_BALANCE_BIN, DEFAULT_PASSPHRASE
from raiden.tests.utils.genesis import GENESIS_STUB
from raiden.utils import privatekey_to_address, privatekey_to_publickey
from raiden.utils.typing import Any, Dict, List, NamedTuple

log = structlog.get_logger(__name__)  # pylint: disable=invalid-name


class EthNodeDescription(NamedTuple):
    private_key: Any  # TODO
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
        verbosity: int,
) -> List[str]:
    """
    Transform a node configuration into a cmd-args list for `subprocess.Popen`.

    Args:
        node: a node configuration
        datadir: the node's datadir
        verbosity: geth structlog verbosity, 0 - nothing, 5 - max

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
        '--verbosity', str(verbosity),
        '--datadir', datadir,
    ])

    if node.get('mine', False):
        cmd.append('--mine')

    log.debug('geth command', command=cmd)

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


def eth_generate_poa_genesis(
        genesis_path: str,
        accounts_addresses: List[str],
        seal_address: str,
        random_marker: str,
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


def eth_wait_and_check(
        web3,
        accounts_addresses,
        random_marker,
        processes_list,
):
    """ Wait until the geth/parity cluster is ready.

    This will raise an exception if either:

    - The geth/parity process exits (successfully or not)
    - The JSON RPC interface is not available after a very short moment
    """
    jsonrpc_running = False

    tries = 5
    while not jsonrpc_running and tries > 0:
        try:
            # don't use web3 here as this will cause problem in the middleware
            response = web3.providers[0].make_request(
                'eth_getBlockByNumber',
                ['0x0', False],
            )
        except requests.exceptions.ConnectionError:
            gevent.sleep(0.5)
            tries -= 1
        else:
            jsonrpc_running = True

            block = response['result']
            running_marker = block['extraData'][2:len(random_marker) + 2]
            if running_marker != random_marker:
                raise RuntimeError(
                    'the test marker does not match, maybe two tests are running in '
                    'parallel with the same port?',
                )

    for process in processes_list:
        process.poll()

        if process.returncode is not None:
            raise ValueError(f'geth process failed with exit code {process.returncode}')

    if jsonrpc_running is False:
        raise ValueError('geth didnt start the jsonrpc interface')

    for account in accounts_addresses:
        tries = 10
        balance = 0
        while balance == 0 and tries > 0:
            balance = web3.eth.getBalance(to_checksum_address(account), 'latest')
            gevent.sleep(1)
            tries -= 1

        if balance == 0:
            raise ValueError('account is with a balance of 0')


def eth_node_config(miner_pkey, p2p_port, rpc_port):
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


def eth_node_config_set_bootnodes(nodes_configuration: Dict) -> None:
    bootnodes = ','.join(node['enode'] for node in nodes_configuration)

    for config in nodes_configuration:
        config['bootnodes'] = bootnodes


def geth_node_to_datadir(node_config, base_datadir):
    # HACK: Use only the first 8 characters to avoid golang's issue
    # https://github.com/golang/go/issues/6895 (IPC bind fails with path
    # longer than 108 characters).
    # BSD (and therefore macOS) socket path length limit is 104 chars
    nodekey_part = node_config['nodekeyhex'][:8]
    datadir = os.path.join(base_datadir, nodekey_part)
    return datadir


def geth_node_to_logpath(node_config, base_logdir):
    # HACK: Use only the first 8 characters to avoid golang's issue
    # https://github.com/golang/go/issues/6895 (IPC bind fails with path
    # longer than 108 characters).
    # BSD (and therefore macOS) socket path length limit is 104 chars
    nodekey_part = node_config['nodekeyhex'][:8]
    logdir = os.path.join(base_logdir, nodekey_part)
    return logdir


def geth_prepare_datadir(datadir, genesis_file):
    node_genesis_path = os.path.join(datadir, 'custom_genesis.json')
    ipc_path = datadir + '/geth.ipc'
    assert len(ipc_path) <= 104, f'geth data path "{ipc_path}" is too large'

    os.makedirs(datadir)
    shutil.copy(genesis_file, node_genesis_path)
    geth_init_datadir(datadir, node_genesis_path)


def eth_nodes_to_cmds(
        nodes_configuration,
        eth_nodes,
        base_datadir,
        genesis_file,
        chain_id,
        verbosity,
):
    cmds = []
    for config, node in zip(nodes_configuration, eth_nodes):
        if node.blockchain_type == 'geth':
            datadir = geth_node_to_datadir(config, base_datadir)
            geth_prepare_datadir(datadir, genesis_file)

            if node.miner:
                geth_create_account(datadir, node.private_key)

            commandline = geth_to_cmd(config, datadir, chain_id, verbosity)

        elif node.blockchain_type == 'parity':
            # TODO
            commandline = ''

        else:
            assert False, f'Invalid blockchain type {config.blockchain_type}'

        cmds.append(commandline)

    return cmds


def eth_run_nodes(
        eth_nodes: List[EthNodeDescription],
        nodes_configuration: List[Dict],
        base_datadir: str,
        genesis_file: str,
        chain_id: int,
        verbosity: int,
        logdir: str,
):
    os.makedirs(logdir, exist_ok=True)

    password_path = os.path.join(base_datadir, 'pw')
    with open(password_path, 'w') as handler:
        handler.write(DEFAULT_PASSPHRASE)

    cmds = eth_nodes_to_cmds(
        nodes_configuration,
        eth_nodes,
        base_datadir,
        genesis_file,
        chain_id,
        verbosity,
    )

    processes_list = []
    for node_config, cmd in zip(nodes_configuration, cmds):
        log_path = geth_node_to_logpath(node_config, logdir)
        logfile = open(log_path, 'w')
        stdout = logfile

        if '--unlock' in cmd:
            process = subprocess.Popen(
                cmd,
                universal_newlines=True,
                stdin=subprocess.PIPE,
                stdout=stdout,
                stderr=subprocess.STDOUT,
            )

            # --password wont work, write password to unlock
            process.stdin.write(DEFAULT_PASSPHRASE + os.linesep)  # Passphrase:
            process.stdin.write(DEFAULT_PASSPHRASE + os.linesep)  # Repeat passphrase:
        else:
            process = subprocess.Popen(
                cmd,
                universal_newlines=True,
                stdout=stdout,
                stderr=subprocess.STDOUT,
            )

        processes_list.append(process)

    return processes_list


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
            config['unlock'] = 0
            config['mine'] = True
            config['password'] = os.path.join(base_datadir, 'pw')

        nodes_configuration.append(config)

    eth_node_config_set_bootnodes(nodes_configuration)

    seal_account = privatekey_to_address(eth_nodes[0].private_key)
    genesis_path = os.path.join(base_datadir, 'custom_genesis.json')
    eth_generate_poa_genesis(
        genesis_path,
        accounts_to_fund,
        seal_account,
        random_marker,
    )

    # check that the test is running on non-capture mode, and if it is save
    # current term settings before running geth
    if isinstance(sys.stdin, io.IOBase):
        term_settings = termios.tcgetattr(sys.stdin)

    processes_list = eth_run_nodes(
        eth_nodes=eth_nodes,
        nodes_configuration=nodes_configuration,
        base_datadir=base_datadir,
        genesis_file=genesis_path,
        chain_id=chain_id,
        verbosity=verbosity,
        logdir=log_dir,
    )

    try:
        eth_wait_and_check(
            web3=web3,
            accounts_addresses=accounts_to_fund,
            random_marker=random_marker,
            processes_list=processes_list,
        )
    except (ValueError, RuntimeError) as e:
        # If geth_wait_and_check or the above loop throw an exception make sure
        # we don't end up with a rogue geth process running in the background
        for process in processes_list:
            process.terminate()
        raise e

    finally:
        # reenter echo mode (disabled by geth pasphrase prompt)
        if isinstance(sys.stdin, io.IOBase):
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, term_settings)

    return processes_list
