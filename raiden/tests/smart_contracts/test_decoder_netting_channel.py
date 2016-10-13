#!/usr/bin/env python
import os
import sys
import pytest
import json
from ethereum import tester, slogging
from ethereum.utils import remove_0x_head

log = slogging.getLogger(__name__)  # pylint: disable=invalid-name
root_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def strip_0x(value):
    if isinstance(value, basestring):
        return remove_0x_head(value)
    return value


def dump(contract_paths):
    """Create a state dump after deploying all solidity contracts from `contract_paths`
    including only the deployed accounts.

    Note: if you have library dependencies, all prior contracts are supplied as
    `--libraries` argument to `solc`, so make sure the order is right.
    Args:
        contract_paths (list): list of absolute paths to solidity files.
    Returns:
        dump (dict): dictionary containing account state of contracts to be used in genesis['alloc']
    """
    state = tester.state(num_accounts=1)
    state.block.number = 1158001
    deployed = []
    libraries = dict()
    for path in contract_paths:
        contract = state.abi_contract(
            None,
            path=path,
            language='solidity',
            libraries=libraries,
            extra_args="raiden={}".format(os.path.join(root_dir, "smart_contracts"))
        )
        state.mine(number_of_blocks=1)
        libraries[os.path.split(path)[-1].split('.')[0]] = contract.address.encode('hex')
        deployed.append(contract.address.encode('hex'))

    alloc = dict()
    for account in deployed:
        alloc[account] = {key: strip_0x(value)
                          for key, value in state.block.account_to_dict(account).items()}
    return alloc


if __name__ == '__main__':
    if len(sys.argv) < 2 or '-h' in sys.argv:
        print "Usage:\n\ttester_dump.py <solidity_contract_path>..."
    else:
        print json.dumps(dump(sys.argv[1:]))


def test_stuff():
    dump([
        os.path.join(root_dir, "smart_contracts", "NettingChannelLibrary.sol"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "DecoderTester.sol")
    ])
