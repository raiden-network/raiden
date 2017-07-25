# -*- coding: utf-8 -*-
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
    signed_transfer,
)
from raiden.tests.fixtures.tester import tester_state
from raiden.utils import privatekey_to_address, sha3

DEPOSIT = 'deposit'
CLOSE = 'close'
UPDATE_TRANSFER = 'updateTransfer'
MINE = 'mine'


class NettingChannelStateMachine(GenericStateMachine):
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

        self.privatekey_and_addresses = list(zip(self.private_keys, self.addresses))

        address_and_balance = self.netting_channel.addressAndBalance(
            sender=self.private_keys[0],
        )

        self.update_transfer_called = False
        self.participant_addresses = {
            address_and_balance[0].decode('hex'),
            address_and_balance[2].decode('hex'),
        }

    def steps(self):
        transfer = signed_transfer(
            direct_transfer(
                sampled_from(self.token_addresses),
                sampled_from(self.addresses),
                just(''),
            ),
            sampled_from(self.private_keys),
        )

        deposit_op = tuples(
            just(DEPOSIT),
            integers(min_value=0),
            sampled_from(self.privatekey_and_addresses),
        )

        close_op = tuples(
            just(CLOSE),
            transfer,
            sampled_from(self.privatekey_and_addresses),
        )

        update_transfer_op = tuples(
            just(UPDATE_TRANSFER),
            transfer,
            sampled_from(self.privatekey_and_addresses),
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
            self.contract_close(step[1], step[2])

        elif op == UPDATE_TRANSFER:
            self.contract_update_transfer(step[1], step[2])

        elif op == MINE:
            self.tester_state.mine(number_of_blocks=step[1])

    def is_participant(self, pkey_address):
        address = pkey_address[1]
        return address in self.participant_addresses

    def contract_deposit(self, deposit_amount, pkey_address):
        token_balance = self.token.balanceOf(  # pylint: disable=no-member
            pkey_address[1],
            sender=pkey_address[0],
        )

        if not self.is_participant(pkey_address):
            try:
                self.netting_channel.deposit(  # pylint: disable=no-member
                    deposit_amount,
                    sender=pkey_address[0],
                )
            except TransactionFailed:
                pass
            else:
                raise ValueError('deposit from non-participant didnt fail')

        elif self.netting_channel.closed(sender=pkey_address[0]) != 0:  # pylint: disable=no-member
            try:
                self.netting_channel.deposit(  # pylint: disable=no-member
                    deposit_amount,
                    sender=pkey_address[0],
                )
            except TransactionFailed:
                pass
            else:
                raise ValueError('deposit with closed channel didnt fail')

        elif token_balance < deposit_amount:
            try:
                self.netting_channel.deposit(  # pylint: disable=no-member
                    deposit_amount,
                    sender=pkey_address[0],
                )
            except TransactionFailed:
                pass
            else:
                raise ValueError('deposit without balance didnt fail')

        else:
            self.netting_channel.deposit(  # pylint: disable=no-member
                deposit_amount,
                sender=pkey_address[0],
            )

    def contract_close(self, transfer, pkey_address):
        transfer_data = transfer.encode()

        if not self.is_participant(transfer.sender):
            try:
                self.netting_channel.close(  # pylint: disable=no-member
                    transfer_data,
                    sender=pkey_address[0],
                )
            except TransactionFailed:
                pass
            else:
                raise ValueError('close with transfer data from a non participant didnt fail')

        elif transfer.sender == pkey_address[1]:
            try:
                self.netting_channel.close(  # pylint: disable=no-member
                    transfer_data,
                    sender=pkey_address[0],
                )
            except TransactionFailed:
                pass
            else:
                raise ValueError('close with self signed transfer didnt fail')

        elif self.netting_channel.closed(sender=pkey_address[0]) != 0:  # pylint: disable=no-member
            try:
                self.netting_channel.close(  # pylint: disable=no-member
                    transfer_data,
                    sender=pkey_address[0],
                )
            except TransactionFailed:
                pass
            else:
                raise ValueError('close called twice didnt fail')

        elif self.is_participant(pkey_address[1]):
            try:
                self.netting_channel.close(  # pylint: disable=no-member
                    transfer_data,
                    sender=pkey_address[0],
                )
            except TransactionFailed:
                pass
            else:
                raise ValueError('close called by a non participant didnt fail')

        else:
            self.netting_channel.close(  # pylint: disable=no-member
                transfer_data,
                sender=pkey_address[0],
            )

    def contract_update_transfer(self, transfer, pkey_address):
        transfer_data = transfer.encode()

        if not self.is_participant(transfer.sender):
            try:
                self.netting_channel.updateTransfer(  # pylint: disable=no-member
                    transfer_data,
                    sender=pkey_address[0],
                )
            except TransactionFailed:
                pass
            else:
                raise ValueError(
                    'updateTransfer with transfer data from a non participant didnt fail'
                )

        elif transfer.sender == pkey_address[1]:
            try:
                self.netting_channel.updateTransfer(  # pylint: disable=no-member
                    transfer_data,
                    sender=pkey_address[0],
                )
            except TransactionFailed:
                pass
            else:
                raise ValueError('updateTransfer with self signed transfer didnt fail')

        elif self.update_transfer_called:
            try:
                self.netting_channel.updateTransfer(  # pylint: disable=no-member
                    transfer_data,
                    sender=pkey_address[0],
                )
            except TransactionFailed:
                pass
            else:
                raise ValueError('updateTransfer called twice didnt fail')

        elif not self.is_participant(pkey_address[1]):
            try:
                self.netting_channel.updateTransfer(  # pylint: disable=no-member
                    transfer_data,
                    sender=pkey_address[0],
                )
            except TransactionFailed:
                pass
            else:
                raise ValueError('updateTransfer called by a non participant didnt fail')

        else:
            self.netting_channel.updateTransfer(  # pylint: disable=no-member
                transfer_data,
                sender=pkey_address[0],
            )
            self.update_transfer_called = True


NettingChannelTestCase = NettingChannelStateMachine.TestCase
