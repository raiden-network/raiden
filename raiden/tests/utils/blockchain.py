# -*- coding: utf-8 -*-
from binascii import hexlify
import json
import io
import os
import shutil
import subprocess
import sys
import termios
import time
import gevent

from eth_utils import (
    denoms,
    to_checksum_address,
    to_normalized_address,
)
import structlog
from requests import ConnectionError

from raiden.utils import (
    privatekey_to_address,
    privtopub,
    encode_hex,
)
from raiden.tests.utils.genesis import GENESIS_STUB

log = structlog.get_logger(__name__)  # pylint: disable=invalid-name

DEFAULT_BALANCE = denoms.ether * 10000000
DEFAULT_BALANCE_BIN = str(denoms.ether * 10000000)
DEFAULT_PASSPHRASE = 'notsosecret'  # Geth's account passphrase


def wait_until_block(chain, block):
    # we expect `next_block` to block until the next block, but, it could
    # advance miss and advance two or more
    curr_block = chain.block_number()
    while curr_block < block:
        curr_block = chain.next_block()
        gevent.sleep(0.001)


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


def geth_to_cmd(node, datadir, verbosity):
    """
    Transform a node configuration into a cmd-args list for `subprocess.Popen`.

    Args:
        node (dict): a node configuration
        datadir (str): the node's datadir
        verbosity (int): geth structlog verbosity, 0 - nothing, 5 - max

    Return:
        List[str]: cmd-args list
    """
    node_config = [
        'nodekeyhex',
        'port',
        'rpcport',
        'bootnodes',
        'minerthreads',
        'unlock',
    ]

    cmd = ['geth']

    for config in node_config:
        if config in node:
            value = node[config]
            cmd.extend(['--{}'.format(config), str(value)])

    # dont use the '--dev' flag
    cmd.extend([
        '--nodiscover',
        '--rpc',
        '--rpcapi', 'eth,net,web3',
        '--rpcaddr', '0.0.0.0',
        '--networkid', '627',
        '--verbosity', str(verbosity),
        '--datadir', datadir,
        '--password', os.path.join(datadir, 'pw'),
    ])

    log.debug('geth command: {}'.format(cmd))

    return cmd


def geth_create_account(datadir, privkey):
    """
    Create an account in `datadir` -- since we're not interested
    in the rewards, we don't care about the created address.

    Args:
        datadir (str): the datadir in which the account is created
    """
    keyfile_path = os.path.join(datadir, 'keyfile')
    with open(keyfile_path, 'wb') as handler:
        handler.write(hexlify(privkey))

    password_path = os.path.join(datadir, 'pw')
    with open(password_path, 'w') as handler:
        handler.write(DEFAULT_PASSPHRASE)

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


def geth_bare_genesis(genesis_path, private_keys, random_marker):
    """Writes a bare genesis to `genesis_path`.

    Args:
        genesis_path (str): the path in which the genesis block is written.
        private_keys list(str): iterable list of privatekeys whose corresponding accounts will
                    have a premined balance available.
    """

    account_addresses = [
        privatekey_to_address(key)
        for key in sorted(set(private_keys))
    ]

    alloc = {
        to_normalized_address(address): {
            'balance': DEFAULT_BALANCE_BIN,
        }
        for address in account_addresses
    }
    genesis = GENESIS_STUB.copy()
    genesis['alloc'].update(alloc)

    genesis['config']['clique'] = {'period': 1, 'epoch': 30000}

    genesis['extraData'] = clique_extradata(
        random_marker,
        to_normalized_address(account_addresses[0])[2:],
    )

    with open(genesis_path, 'w') as handler:
        json.dump(genesis, handler)


def geth_init_datadir(datadir, genesis_path):
    """Initialize a clients datadir with our custom genesis block.

    Args:
        datadir (str): the datadir in which the blockchain is initialized.
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


def geth_wait_and_check(web3, privatekeys, random_marker):
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

    for key in sorted(set(privatekeys)):
        address = to_checksum_address(privatekey_to_address(key))

        tries = 10
        balance = 0
        while balance == 0 and tries > 0:
            balance = web3.eth.getBalance(address, 'latest')
            gevent.sleep(1)
            tries -= 1

        if balance == 0:
            raise ValueError('account is with a balance of 0')


def geth_create_blockchain(
        deploy_key,
        web3,
        private_keys,
        blockchain_private_keys,
        rpc_ports,
        p2p_ports,
        base_datadir,
        verbosity,
        random_marker,
        genesis_path=None,
        logdirectory=None,
):
    # pylint: disable=too-many-locals,too-many-statements,too-many-arguments,too-many-branches

    nodes_configuration = []
    key_p2p_rpc = zip(blockchain_private_keys, p2p_ports, rpc_ports)

    for pos, (key, p2p_port, rpc_port) in enumerate(key_p2p_rpc):
        config = dict()

        address = privatekey_to_address(key)
        # make the first node miner
        if pos == 0:
            config['unlock'] = 0

        config['nodekey'] = key
        config['nodekeyhex'] = encode_hex(key)
        config['pub'] = encode_hex(privtopub(key))
        config['address'] = address
        config['port'] = p2p_port
        config['rpcport'] = rpc_port
        config['enode'] = 'enode://{pub}@127.0.0.1:{port}'.format(
            pub=config['pub'],
            port=config['port'],
        )
        nodes_configuration.append(config)

    for config in nodes_configuration:
        config['bootnodes'] = ','.join(node['enode'] for node in nodes_configuration)

    all_keys = set(private_keys)
    all_keys.add(deploy_key)
    all_keys = sorted(all_keys)

    cmds = []
    for i, config in enumerate(nodes_configuration):
        # HACK: Use only the first 8 characters to avoid golang's issue
        # https://github.com/golang/go/issues/6895 (IPC bind fails with path
        # longer than 108 characters).
        # BSD (and therefore macOS) socket path length limit is 104 chars
        nodekey_part = config['nodekeyhex'][:8]
        nodedir = os.path.join(base_datadir, nodekey_part)
        node_genesis_path = os.path.join(nodedir, 'custom_genesis.json')

        assert len(nodedir + '/geth.ipc') <= 104, 'geth data path is too large'

        os.makedirs(nodedir)

        if genesis_path is None:
            geth_bare_genesis(node_genesis_path, all_keys, random_marker)
        else:
            shutil.copy(genesis_path, node_genesis_path)

        geth_init_datadir(nodedir, node_genesis_path)

        if 'unlock' in config:
            geth_create_account(nodedir, all_keys[i])

        commandline = geth_to_cmd(config, nodedir, verbosity)
        cmds.append(commandline)

    # save current term settings before running geth
    if isinstance(sys.stdin, io.IOBase):  # check that the test is running on non-capture mode
        term_settings = termios.tcgetattr(sys.stdin)

    stdout = None
    stderr = None
    processes_list = []
    for pos, cmd in enumerate(cmds):
        if logdirectory:
            log_path = os.path.join(logdirectory, str(pos))
            logfile = open(log_path, 'w')

            stdout = logfile
            stderr = logfile

        if '--unlock' in cmd:
            cmd.append('--mine')
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

    try:
        geth_wait_and_check(web3, private_keys, random_marker)

        for process in processes_list:
            process.poll()

            if process.returncode is not None:
                raise ValueError('geth failed to start')

    except (ValueError, RuntimeError) as e:
        # If geth_wait_and_check or the above loop throw an exception make sure
        # we don't end up with a rogue geth process running in the background
        for proccess in processes_list:
            process.terminate()
        raise e

    finally:
        # reenter echo mode (disabled by geth pasphrase prompt)
        if isinstance(sys.stdin, io.IOBase):
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, term_settings)

    return processes_list
