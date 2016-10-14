# -*- coding: utf8 -*-
import os

from secp256k1 import PrivateKey
from ethereum import tester
from raiden.utils import sha3, privatekey_to_address
from raiden.messages import DirectTransfer
from raiden.encoding.signing import GLOBAL_CTX

root_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PRIVKEY = 'x' * 32
ADDRESS = privatekey_to_address(PRIVKEY)
HASH = sha3(PRIVKEY)


def deploy_decoder_tester(asset_address, address1, address2, settle_timeout):
    state = tester.state(num_accounts=1)
    nettingchannel_lib = state.abi_contract(
        None,
        path=os.path.join(root_dir, "smart_contracts", "NettingChannelLibrary.sol"),
        language='solidity'
    )
    state.mine(number_of_blocks=1)

    decode_tester = state.abi_contract(
        None,
        path=os.path.join(os.path.dirname(os.path.abspath(__file__)), "DecoderTester.sol"),
        language='solidity',
        libraries={
            'NettingChannelLibrary': nettingchannel_lib.address.encode('hex')
        },
        constructor_parameters=(
            asset_address,
            address1,
            address2,
            settle_timeout
        ),
        extra_args="raiden={}".format(os.path.join(root_dir, "smart_contracts"))
    )
    state.mine(number_of_blocks=1)

    return decode_tester


def test_decode_singletransfer(
        private_keys,
        settle_timeout,
        tester_state,
        tester_token,
        tester_events,
        tester_registry):

    privatekey0 = private_keys[0]
    privatekey1 = private_keys[1]
    address0 = privatekey_to_address(privatekey0)
    address1 = privatekey_to_address(privatekey1)

    dtester = deploy_decoder_tester(tester_token.address, address0, address1, settle_timeout)

    locksroot = HASH

    message = DirectTransfer(
        identifier=1,
        nonce=2,
        asset=tester_token.address,
        transferred_amount=1,
        recipient=address1,
        locksroot=locksroot
    )

    message.sign(PrivateKey(privatekey0, ctx=GLOBAL_CTX, raw=True), address0)
    assert dtester.testCloseSingleTransfer() is True
