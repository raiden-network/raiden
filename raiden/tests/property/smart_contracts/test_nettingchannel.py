# -*- coding: utf-8 -*-
import contextlib

from coincurve import PrivateKey
from ethereum.utils import normalize_address
from ethereum.tools.tester import TransactionFailed
from ethereum.exceptions import BlockGasLimitReached
from hypothesis import assume
from hypothesis.stateful import GenericStateMachine
from hypothesis.strategies import (
    integers,
    just,
    one_of,
    sampled_from,
    tuples,
)

from raiden.messages import (
    EMPTY_MERKLE_ROOT,
)
from raiden.tests.utils.tester import (
    deploy_channelmanager_library,
    deploy_nettingchannel_library,
    new_channelmanager,
    new_nettingcontract,
    new_registry,
    new_token,
)
from raiden.tests.property.smart_contracts.strategies import (
    direct_transfer,
)
from raiden.tests.fixtures.tester import tester_chain
from raiden.utils import (
    privatekey_to_address,
    sha3,
    address_decoder,
)
from raiden.tests.utils.factories import make_address

DEPOSIT = 'deposit'
CLOSE = 'close'
UPDATE_TRANSFER = 'updateTransfer'
MINE = 'mine'


@contextlib.contextmanager
def transaction_must_fail(error_message):
    try:
        yield
    except TransactionFailed:
        pass
    else:
        raise ValueError(error_message)


class NettingChannelStateMachine(GenericStateMachine):
    """ Generates random operations (e.g. deposit, close, updateTransfer) to
    test against a netting channel.
    """

    def __init__(self):
        super().__init__()

        deploy_key = sha3(b'deploy_key')
        gas_limit = 10 ** 10

        self.private_keys = [
            sha3(b'p1'),
            sha3(b'p2'),
            sha3(b'p3'),  # third key used to generate signed but invalid transfers
        ]
        self.addresses = list(map(privatekey_to_address, self.private_keys))
        self.log = list()
        self.tester_chain = tester_chain(
            deploy_key,
            self.private_keys,
            gas_limit,
        )
        self.settle_timeout = 10
        self.token_amount = 1000

        self.tokens = [
            new_token(
                deploy_key,
                self.tester_chain,
                self.token_amount,
                self.log.append,
            ),
            new_token(
                deploy_key,
                self.tester_chain,
                self.token_amount,
                self.log.append,
            ),
        ]
        self.token = self.tokens[0]

        self.token_addresses = [
            token.address
            for token in self.tokens
        ]

        self.nettingchannel_library_address = deploy_nettingchannel_library(
            deploy_key,
            self.tester_chain,
        )
        self.channel_manager_library_address = deploy_channelmanager_library(
            deploy_key,
            self.tester_chain,
            self.nettingchannel_library_address,
        )
        self.registry = new_registry(
            deploy_key,
            self.tester_chain,
            self.channel_manager_library_address,
            self.log.append,
        )
        self.channelmanager = new_channelmanager(
            deploy_key,
            self.tester_chain,
            self.log.append,
            self.registry,
            self.token.address,
        )
        self.netting_channel = new_nettingcontract(
            self.private_keys[0],
            self.private_keys[1],
            self.tester_chain,
            self.log.append,
            self.channelmanager,
            self.settle_timeout,
        )

        address_and_balance = self.netting_channel.addressAndBalance(  # pylint: disable=no-member
            sender=self.private_keys[0],
        )

        self.closing_address = None
        self.update_transfer_called = False
        self.participant_addresses = {
            address_decoder(address_and_balance[0]),
            address_decoder(address_and_balance[2]),
        }

        self.channel_addresses = [
            address_decoder(self.netting_channel.address),
            make_address(),  # used to test invalid transfers
        ]

    def steps(self):
        transfer = direct_transfer(  # pylint: disable=no-value-for-parameter
            sampled_from(self.token_addresses),
            sampled_from(self.channel_addresses),
            sampled_from(self.addresses),
            just(EMPTY_MERKLE_ROOT),
        )

        deposit_op = tuples(
            just(DEPOSIT),
            integers(min_value=0),
            sampled_from(self.private_keys),
        )

        close_op = tuples(
            just(CLOSE),
            transfer,
            sampled_from(self.private_keys),
            sampled_from(self.private_keys),
        )

        update_transfer_op = tuples(
            just(UPDATE_TRANSFER),
            transfer,
            sampled_from(self.private_keys),
            sampled_from(self.private_keys),
        )

        transaction_ops = one_of(
            deposit_op,
            close_op,
            update_transfer_op,
        )

        mine_op = tuples(
            just(MINE),
            integers(min_value=1, max_value=self.settle_timeout * 5),
        )

        # increases likely hood of the mine op, while permitting transactions
        # to run in the same block
        return one_of(
            transaction_ops,
            mine_op,
        )

    def execute_step(self, step):
        op = step[0]

        if op == DEPOSIT:
            try:
                self.contract_deposit(step[1], step[2])
            except BlockGasLimitReached:
                assume(False)

        elif op == CLOSE:
            try:
                self.contract_close(step[1], step[2], step[3])
            except BlockGasLimitReached:
                assume(False)

        elif op == UPDATE_TRANSFER:
            try:
                self.contract_update_transfer(step[1], step[2], step[3])
            except BlockGasLimitReached:
                assume(False)

        elif op == MINE:
            self.tester_chain.mine(number_of_blocks=step[1])

    def is_participant(self, address):
        return address in self.participant_addresses

    def contract_deposit(self, deposit_amount, sender_pkey):
        sender_address = privatekey_to_address(sender_pkey)

        token_balance = self.token.balanceOf(  # pylint: disable=no-member
            sender_address,
            sender=sender_pkey,
        )

        if not self.is_participant(sender_address):
            with transaction_must_fail('deposit from non-participant didnt fail'):
                self.netting_channel.deposit(  # pylint: disable=no-member
                    deposit_amount,
                    sender=sender_pkey,
                )

        elif self.netting_channel.closed(sender=sender_pkey) != 0:  # pylint: disable=no-member
            with transaction_must_fail('deposit with closed channel didnt fail'):
                self.netting_channel.deposit(  # pylint: disable=no-member
                    deposit_amount,
                    sender=sender_pkey,
                )

        elif token_balance < deposit_amount:
            with transaction_must_fail('having insufficient funds for a deposit didnt fail'):
                self.netting_channel.deposit(  # pylint: disable=no-member
                    deposit_amount,
                    sender=sender_pkey,
                )

        else:
            self.netting_channel.deposit(  # pylint: disable=no-member
                deposit_amount,
                sender=sender_pkey,
            )

    def contract_close(self, transfer, signing_pkey, sender_pkey):
        transfer.sign(
            PrivateKey(signing_pkey),
            privatekey_to_address(signing_pkey),
        )

        sender_address = privatekey_to_address(sender_pkey)
        transfer_data = transfer.encode()

        transfer_hash = sha3(transfer_data[:-65])

        if not self.is_participant(transfer.sender):
            msg = 'close with transfer data from a non participant didnt fail'
            with transaction_must_fail(msg):
                self.netting_channel.close(  # pylint: disable=no-member
                    transfer.nonce,
                    transfer.transferred_amount,
                    transfer.locksroot,
                    transfer_hash,
                    transfer.signature,
                    sender=sender_pkey,
                )

        elif transfer.sender == sender_address:
            with transaction_must_fail('close with self signed transfer didnt fail'):
                self.netting_channel.close(  # pylint: disable=no-member
                    transfer.nonce,
                    transfer.transferred_amount,
                    transfer.locksroot,
                    transfer_hash,
                    transfer.signature,
                    sender=sender_pkey,
                )

        elif self.netting_channel.closed(sender=sender_pkey) != 0:  # pylint: disable=no-member
            with transaction_must_fail('close called twice didnt fail'):
                self.netting_channel.close(  # pylint: disable=no-member
                    transfer.nonce,
                    transfer.transferred_amount,
                    transfer.locksroot,
                    transfer_hash,
                    transfer.signature,
                    sender=sender_pkey,
                )

        elif not self.is_participant(sender_address):
            with transaction_must_fail('close called by a non participant didnt fail'):
                self.netting_channel.close(  # pylint: disable=no-member
                    transfer.nonce,
                    transfer.transferred_amount,
                    transfer.locksroot,
                    transfer_hash,
                    transfer.signature,
                    sender=sender_pkey,
                )

        elif transfer.channel != normalize_address(self.netting_channel.address):
            msg = 'close called with a transfer for a different channe didnt fail'
            with transaction_must_fail(msg):
                self.netting_channel.close(  # pylint: disable=no-member
                    transfer.nonce,
                    transfer.transferred_amount,
                    transfer.locksroot,
                    transfer_hash,
                    transfer.signature,
                    sender=sender_pkey,
                )

        else:
            self.netting_channel.close(  # pylint: disable=no-member
                transfer.nonce,
                transfer.transferred_amount,
                transfer.locksroot,
                transfer_hash,
                transfer.signature,
                sender=sender_pkey,
            )

            self.closing_address = sender_address

    def contract_update_transfer(self, transfer, signing_pkey, sender_pkey):
        transfer.sign(
            PrivateKey(signing_pkey),
            privatekey_to_address(signing_pkey),
        )

        sender_address = privatekey_to_address(sender_pkey)

        transfer_data = transfer.encode()
        transfer_hash = sha3(transfer_data[:-65])

        close_block = self.netting_channel.closed(sender=sender_pkey)  # pylint: disable=no-member
        settlement_end = close_block + self.settle_timeout

        is_closed = close_block != 0
        is_settlement_period_over = is_closed and settlement_end < self.tester_chain.block.number

        if not self.is_participant(transfer.sender):
            msg = 'updateTransfer with transfer data from a non participant didnt fail'
            with transaction_must_fail(msg):
                self.netting_channel.updateTransfer(  # pylint: disable=no-member
                    transfer.nonce,
                    transfer.transferred_amount,
                    transfer.locksroot,
                    transfer_hash,
                    transfer.signature,
                    sender=sender_pkey,
                )

        elif transfer.sender == sender_address:
            with transaction_must_fail('updateTransfer with self signed transfer didnt fail'):
                self.netting_channel.updateTransfer(  # pylint: disable=no-member
                    transfer.nonce,
                    transfer.transferred_amount,
                    transfer.locksroot,
                    transfer_hash,
                    transfer.signature,
                    sender=sender_pkey,
                )

        elif self.update_transfer_called:
            with transaction_must_fail('updateTransfer called twice didnt fail'):
                self.netting_channel.updateTransfer(  # pylint: disable=no-member
                    transfer.nonce,
                    transfer.transferred_amount,
                    transfer.locksroot,
                    transfer_hash,
                    transfer.signature,
                    sender=sender_pkey,
                )

        elif not self.is_participant(sender_address):
            with transaction_must_fail('updateTransfer called by a non participant didnt fail'):
                self.netting_channel.updateTransfer(  # pylint: disable=no-member
                    transfer.nonce,
                    transfer.transferred_amount,
                    transfer.locksroot,
                    transfer_hash,
                    transfer.signature,
                    sender=sender_pkey,
                )

        elif transfer.channel != normalize_address(self.netting_channel.address):
            msg = 'updateTransfer called with a transfer for a different channel didnt fail'
            with transaction_must_fail(msg):
                self.netting_channel.updateTransfer(  # pylint: disable=no-member
                    transfer.nonce,
                    transfer.transferred_amount,
                    transfer.locksroot,
                    transfer_hash,
                    transfer.signature,
                    sender=sender_pkey,
                )

        elif not is_closed:
            with transaction_must_fail('updateTransfer called on an open channel and didnt fail'):
                self.netting_channel.updateTransfer(  # pylint: disable=no-member
                    transfer.nonce,
                    transfer.transferred_amount,
                    transfer.locksroot,
                    transfer_hash,
                    transfer.signature,
                    sender=sender_pkey,
                )

        elif is_settlement_period_over:
            msg = 'updateTransfer called after end of the settlement period and didnt fail'
            with transaction_must_fail(msg):
                self.netting_channel.updateTransfer(  # pylint: disable=no-member
                    transfer.nonce,
                    transfer.transferred_amount,
                    transfer.locksroot,
                    transfer_hash,
                    transfer.signature,
                    sender=sender_pkey,
                )

        elif sender_address == self.closing_address:
            with transaction_must_fail('updateTransfer called by the closer and it didnt fail'):
                self.netting_channel.updateTransfer(  # pylint: disable=no-member
                    transfer.nonce,
                    transfer.transferred_amount,
                    transfer.locksroot,
                    transfer_hash,
                    transfer.signature,
                    sender=sender_pkey,
                )

        else:
            self.netting_channel.updateTransfer(  # pylint: disable=no-member
                transfer.nonce,
                transfer.transferred_amount,
                transfer.locksroot,
                transfer_hash,
                transfer.signature,
                sender=sender_pkey,
            )
            self.update_transfer_called = True


NettingChannelTestCase = NettingChannelStateMachine.TestCase
