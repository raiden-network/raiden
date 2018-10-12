import io
import json
import os
import shutil
import subprocess
import sys
import termios
import time
from collections import namedtuple

import gevent
import structlog
from eth_utils import encode_hex, remove_0x_prefix, to_checksum_address, to_normalized_address
from requests import ConnectionError
from web3 import Web3

from raiden.tests.fixtures.variables import DEFAULT_BALANCE_BIN, DEFAULT_PASSPHRASE
from raiden.tests.utils.genesis import GENESIS_STUB
from raiden.utils import privatekey_to_address, privtopub, typing

log = structlog.get_logger(__name__)  # pylint: disable=invalid-name


GethNodeDescription = namedtuple(
    'GethNodeDescription',
    [
        'private_key',
        'rpc_port',
        'p2p_port',
        'miner',
    ],
)


def wait_until_block(chain, block):
    # we expect `next_block` to block until the next block, but, it could
    # advance miss and advance two or more
    curr_block = chain.block_number()
    while curr_block < block:
        curr_block = chain.next_block()
        gevent.sleep(0.001)


def geth_clique_extradata(extra_vanity, extra_seal):
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
        node: typing.Dict,
        datadir: str,
        chain_id: int,
        verbosity: int,
) -> typing.List[str]:
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
        '--rpcapi', 'eth,net,web3,personal',
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
    )

    create.stdin.write(DEFAULT_PASSPHRASE + os.linesep)
    time.sleep(.1)
    create.stdin.write(DEFAULT_PASSPHRASE + os.linesep)
    create.communicate()
    assert create.returncode == 0


def geth_generate_poa_genesis(
        genesis_path: str,
        accounts_addresses: typing.List[str],
        seal_address: str,
        random_marker,
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

    genesis['extraData'] = geth_clique_extradata(
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


def geth_wait_and_check(web3, accounts_addresses, random_marker):
    """ Wait until the geth cluster is ready. """
    jsonrpc_running = False

    tries = 5
    while not jsonrpc_running and tries > 0:
        try:
            # don't use web3 here as this will cause problem in the middleware
            response = web3.providers[0].make_request(
                'eth_getBlockByNumber',
                ['0x0', False],
            )
        except ConnectionError:
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


def geth_node_config(miner_pkey, p2p_port, rpc_port):
    address = privatekey_to_address(miner_pkey)
    pub = remove_0x_prefix(encode_hex(privtopub(miner_pkey)))

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


def geth_node_config_set_bootnodes(nodes_configuration: typing.Dict) -> None:
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


def geth_prepare_datadir(datadir, genesis_file):
    node_genesis_path = os.path.join(datadir, 'custom_genesis.json')
    assert len(datadir + '/geth.ipc') <= 104, 'geth data path is too large'

    os.makedirs(datadir)
    shutil.copy(genesis_file, node_genesis_path)
    geth_init_datadir(datadir, node_genesis_path)


def geth_nodes_to_cmds(
        nodes_configuration,
        geth_nodes,
        base_datadir,
        genesis_file,
        chain_id,
        verbosity,
):
    cmds = []
    for config, node in zip(nodes_configuration, geth_nodes):
        datadir = geth_node_to_datadir(config, base_datadir)
        geth_prepare_datadir(datadir, genesis_file)

        if node.miner:
            geth_create_account(datadir, node.private_key)

        commandline = geth_to_cmd(config, datadir, chain_id, verbosity)
        cmds.append(commandline)

    return cmds


def geth_run_nodes(
        geth_nodes,
        nodes_configuration,
        base_datadir,
        genesis_file,
        chain_id,
        verbosity,
        logdir,
):
    os.makedirs(logdir)

    password_path = os.path.join(base_datadir, 'pw')
    with open(password_path, 'w') as handler:
        handler.write(DEFAULT_PASSPHRASE)

    cmds = geth_nodes_to_cmds(
        nodes_configuration,
        geth_nodes,
        base_datadir,
        genesis_file,
        chain_id,
        verbosity,
    )

    processes_list = []
    for pos, cmd in enumerate(cmds):
        log_path = os.path.join(logdir, str(pos))
        logfile = open(log_path, 'w')
        stdout = logfile
        stderr = logfile

        if '--unlock' in cmd:
            process = subprocess.Popen(
                cmd,
                universal_newlines=True,
                stdin=subprocess.PIPE,
                stdout=stdout,
                stderr=stderr,
            )

            # --password wont work, write password to unlock
            process.stdin.write(DEFAULT_PASSPHRASE + os.linesep)  # Passphrase:
            process.stdin.write(DEFAULT_PASSPHRASE + os.linesep)  # Repeat passphrase:
        else:
            process = subprocess.Popen(
                cmd,
                universal_newlines=True,
                stdout=stdout,
                stderr=stderr,
            )

        processes_list.append(process)

    return processes_list


def geth_run_private_blockchain(
        web3: Web3,
        accounts_to_fund: typing.List[bytes],
        geth_nodes: typing.List[GethNodeDescription],
        base_datadir: str,
        chain_id: int,
        verbosity: str,
        random_marker: str,
):
    """ Starts a private network with private_keys accounts funded.

    Args:
        web3: A Web3 instance used to check when the private chain is running.
        accounts_to_fund: Accounts that will start with funds in
            the private chain.
        geth_nodes: A list of geth node
            description, containing the details of each node of the private
            chain.
        base_datadir: The directory that will be used for the private
            chain data.
        verbosity: Verbosity used by the geth nodes.
        random_marker: A random marked used to identify the private chain.
    """
    # pylint: disable=too-many-locals,too-many-statements,too-many-arguments,too-many-branches

    nodes_configuration = []
    for node in geth_nodes:
        config = geth_node_config(
            node.private_key,
            node.p2p_port,
            node.rpc_port,
        )

        if node.miner:
            config['unlock'] = 0
            config['mine'] = True
            config['password'] = os.path.join(base_datadir, 'pw')

        nodes_configuration.append(config)

    geth_node_config_set_bootnodes(nodes_configuration)

    seal_account = privatekey_to_address(geth_nodes[0].private_key)
    genesis_path = os.path.join(base_datadir, 'custom_genesis.json')
    geth_generate_poa_genesis(
        genesis_path,
        accounts_to_fund,
        seal_account,
        random_marker,
    )
    logdir = os.path.join(base_datadir, 'logs')

    # check that the test is running on non-capture mode, and if it is save
    # current term settings before running geth
    if isinstance(sys.stdin, io.IOBase):
        term_settings = termios.tcgetattr(sys.stdin)

    processes_list = geth_run_nodes(
        geth_nodes,
        nodes_configuration,
        base_datadir,
        genesis_path,
        chain_id,
        verbosity,
        logdir,
    )

    try:
        geth_wait_and_check(web3, accounts_to_fund, random_marker)

        for process in processes_list:
            process.poll()

            if process.returncode is not None:
                raise ValueError(f'geth process failed with exit code {process.returncode}')

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
