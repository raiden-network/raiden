# -*- coding: utf-8 -*-
from coincurve import PrivateKey
from ethereum.tester import TransactionFailed
from hypothesis.stateful import GenericStateMachine
from hypothesis.strategies import (
    integers,
    just,
    one_of,
    sampled_from,
    tuples,
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
from raiden.tests.fixtures.tester import tester_state
from raiden.utils import (
    make_address,
    privatekey_to_address,
    sha3,
)

DEPOSIT = 'deposit'
CLOSE = 'close'
UPDATE_TRANSFER = 'updateTransfer'
MINE = 'mine'


class NettingChannelStateMachine(GenericStateMachine):
    """ Generates random operations (e.g. deposit, close, updateTransfer) to
    test against a netting channel.
    """

    def __init__(self):
        super(NettingChannelStateMachine, self).__init__()

        deploy_key = sha3('deploy_key')
        gas_limit = 10 ** 10

        self.private_keys = [
            sha3('p1'),
            sha3('p2'),
            sha3('p3'),  # third key used to generate signed but invalid transfers
        ]
        self.addresses = map(privatekey_to_address, self.private_keys)
        self.log = list()
        self.tester_state = tester_state(
            deploy_key,
            self.private_keys,
            gas_limit,
        )
        self.settle_timeout = 50
        self.token_amount = 1000

        self.tokens = [
            new_token(
                deploy_key,
                self.tester_state,
                self.token_amount,
                self.log.append,
            ),
            new_token(
                deploy_key,
                self.tester_state,
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
            self.tester_state,
        )
        self.channel_manager_library_address = deploy_channelmanager_library(
            deploy_key,
            self.tester_state,
            self.nettingchannel_library_address,
        )
        self.registry = new_registry(
            deploy_key,
            self.tester_state,
            self.channel_manager_library_address,
            self.log.append,
        )
        self.channelmanager = new_channelmanager(
            deploy_key,
            self.tester_state,
            self.log.append,
            self.registry,
            self.token.address,
        )
        self.netting_channel = new_nettingcontract(
            self.private_keys[0],
            self.private_keys[1],
            self.tester_state,
            self.log.append,
            self.channelmanager,
            self.settle_timeout,
        )

        address_and_balance = self.netting_channel.addressAndBalance(  # pylint: disable=no-member
            sender=self.private_keys[0],
        )

        self.update_transfer_called = False
        self.participant_addresses = {
            address_and_balance[0].decode('hex'),
            address_and_balance[2].decode('hex'),
        }

        self.channel_addresses = [
            self.netting_channel.address.decode('hex'),
            make_address(),  # used to test invalid transfers
        ]

    def steps(self):
        transfer = direct_transfer(  # pylint: disable=no-value-for-parameter
            sampled_from(self.token_addresses),
            sampled_from(self.channel_addresses),
            sampled_from(self.addresses),
            just(''),
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

        mine_op = tuples(
            just(MINE),
            integers(min_value=1, max_value=100),
        )

        return one_of(
            deposit_op,
            close_op,
            update_transfer_op,
            mine_op,
        )

    def execute_step(self, step):
        op = step[0]

        if op == DEPOSIT:
            self.contract_deposit(step[1], step[2])

        elif op == CLOSE:
            self.contract_close(step[1], step[2], step[3])

        elif op == UPDATE_TRANSFER:
            self.contract_update_transfer(step[1], step[2], step[3])

        elif op == MINE:
            self.tester_state.mine(number_of_blocks=step[1])

    def is_participant(self, address):
        return address in self.participant_addresses

    def contract_deposit(self, deposit_amount, sender_pkey):
        sender_address = privatekey_to_address(sender_pkey)

        token_balance = self.token.balanceOf(  # pylint: disable=no-member
            sender_address,
            sender=sender_pkey,
        )

        if not self.is_participant(sender_address):
            try:
                self.netting_channel.deposit(  # pylint: disable=no-member
                    deposit_amount,
                    sender=sender_pkey,
                )
            except TransactionFailed:
                pass
            else:
                raise ValueError('deposit from non-participant didnt fail')

        elif self.netting_channel.closed(sender=sender_pkey) != 0:  # pylint: disable=no-member
            try:
                self.netting_channel.deposit(  # pylint: disable=no-member
                    deposit_amount,
                    sender=sender_pkey,
                )
            except TransactionFailed:
                pass
            else:
                raise ValueError('deposit with closed channel didnt fail')

        elif token_balance < deposit_amount:
            try:
                self.netting_channel.deposit(  # pylint: disable=no-member
                    deposit_amount,
                    sender=sender_pkey,
                )
            except TransactionFailed:
                pass
            else:
                raise ValueError('having insufficient funds for a deposit didnt fail')

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
            try:
                self.netting_channel.close(  # pylint: disable=no-member
                    transfer.nonce,
                    transfer.transferred_amount,
                    transfer.locksroot,
                    transfer_hash,
                    transfer.signature,
                    sender=sender_pkey,
                )
            except TransactionFailed:
                pass
            else:
                raise ValueError('close with transfer data from a non participant didnt fail')

        elif transfer.sender == sender_address:
            try:
                self.netting_channel.close(  # pylint: disable=no-member
                    transfer.nonce,
                    transfer.transferred_amount,
                    transfer.locksroot,
                    transfer_hash,
                    transfer.signature,
                    sender=sender_pkey,
                )
            except TransactionFailed:
                pass
            else:
                raise ValueError('close with self signed transfer didnt fail')

        elif self.netting_channel.closed(sender=sender_pkey) != 0:  # pylint: disable=no-member
            try:
                self.netting_channel.close(  # pylint: disable=no-member
                    transfer.nonce,
                    transfer.transferred_amount,
                    transfer.locksroot,
                    transfer_hash,
                    transfer.signature,
                    sender=sender_pkey,
                )
            except TransactionFailed:
                pass
            else:
                raise ValueError('close called twice didnt fail')

        elif not self.is_participant(sender_address):
            try:
                self.netting_channel.close(  # pylint: disable=no-member
                    transfer.nonce,
                    transfer.transferred_amount,
                    transfer.locksroot,
                    transfer_hash,
                    transfer.signature,
                    sender=sender_pkey,
                )
            except TransactionFailed:
                pass
            else:
                raise ValueError('close called by a non participant didnt fail')

        elif transfer.channel != self.netting_channel.address.decode('hex'):
            try:
                self.netting_channel.close(  # pylint: disable=no-member
                    transfer.nonce,
                    transfer.transferred_amount,
                    transfer.locksroot,
                    transfer_hash,
                    transfer.signature,
                    sender=sender_pkey,
                )
            except TransactionFailed:
                pass
            else:
                raise ValueError('close called with a transfer for a different channe didnt fail')

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

        if not self.is_participant(transfer.sender):
            try:
                self.netting_channel.updateTransfer(  # pylint: disable=no-member
                    transfer.nonce,
                    transfer.transferred_amount,
                    transfer.locksroot,
                    transfer_hash,
                    transfer.signature,
                    sender=sender_pkey,
                )
            except TransactionFailed:
                pass
            else:
                raise ValueError(
                    'updateTransfer with transfer data from a non participant didnt fail'
                )

        elif transfer.sender == sender_address:
            try:
                self.netting_channel.updateTransfer(  # pylint: disable=no-member
                    transfer.nonce,
                    transfer.transferred_amount,
                    transfer.locksroot,
                    transfer_hash,
                    transfer.signature,
                    sender=sender_pkey,
                )
            except TransactionFailed:
                pass
            else:
                raise ValueError('updateTransfer with self signed transfer didnt fail')

        elif self.update_transfer_called:
            try:
                self.netting_channel.updateTransfer(  # pylint: disable=no-member
                    transfer.nonce,
                    transfer.transferred_amount,
                    transfer.locksroot,
                    transfer_hash,
                    transfer.signature,
                    sender=sender_pkey,
                )
            except TransactionFailed:
                pass
            else:
                raise ValueError('updateTransfer called twice didnt fail')

        elif not self.is_participant(sender_address):
            try:
                self.netting_channel.updateTransfer(  # pylint: disable=no-member
                    transfer.nonce,
                    transfer.transferred_amount,
                    transfer.locksroot,
                    transfer_hash,
                    transfer.signature,
                    sender=sender_pkey,
                )
            except TransactionFailed:
                pass
            else:
                raise ValueError('updateTransfer called by a non participant didnt fail')

        elif transfer.channel != self.netting_channel.address.decode('hex'):
            try:
                self.netting_channel.updateTransfer(  # pylint: disable=no-member
                    transfer.nonce,
                    transfer.transferred_amount,
                    transfer.locksroot,
                    transfer_hash,
                    transfer.signature,
                    sender=sender_pkey,
                )
            except TransactionFailed:
                pass
            else:
                raise ValueError(
                    'updateTransfer called with a transfer for a different channel didnt fail'
                )

        elif self.netting_channel.closed(sender=sender_pkey) == 0:  # pylint: disable=no-member
            try:
                self.netting_channel.updateTransfer(  # pylint: disable=no-member
                    transfer.nonce,
                    transfer.transferred_amount,
                    transfer.locksroot,
                    transfer_hash,
                    transfer.signature,
                    sender=sender_pkey,
                )
            except TransactionFailed:
                pass
            else:
                raise ValueError('updateTransfer called on an open channel and didnt fail')

        elif sender_address == self.closing_address:
            try:
                self.netting_channel.updateTransfer(  # pylint: disable=no-member
                    transfer.nonce,
                    transfer.transferred_amount,
                    transfer.locksroot,
                    transfer_hash,
                    transfer.signature,
                    sender=sender_pkey,
                )
            except TransactionFailed:
                pass
            else:
                raise ValueError('updateTransfer called by the closer and it didnt fail')

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
