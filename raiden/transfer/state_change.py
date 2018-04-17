# -*- coding: utf-8 -*-
# pylint: disable=too-few-public-methods,too-many-arguments,too-many-instance-attributes
from raiden.transfer.architecture import StateChange
from raiden.transfer.state import (
    BalanceProofSignedState,
    PaymentNetworkState,
    TokenNetworkState,
)
from raiden.utils import pex, sha3
from raiden.utils import typing


class Block(StateChange):
    """ Transition used when a new block is mined.
    Args:
        block_number: The current block_number.
    """

    def __init__(self, block_number: typing.BlockNumber):
        if not isinstance(block_number, typing._BlockNumber):
            raise ValueError('block_number must be of type block_number')

        self.block_number = block_number

    def __repr__(self):
        return '<Block {}>'.format(self.block_number)

    def __eq__(self, other):
        return (
            isinstance(other, Block) and
            self.block_number == other.block_number
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class ActionCancelPayment(StateChange):
    """ The user requests the transfer to be cancelled.
    This state change can fail, it depends on the node's role and the current
    state of the transfer.
    """

    def __init__(self, identifier):
        self.identifier = identifier

    def __repr__(self):
        return '<ActionCancelPayment identifier:{}>'.format(
            self.identifier,
        )

    def __eq__(self, other):
        return (
            isinstance(other, ActionCancelPayment) and
            self.identifier == other.identifier
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class ActionChannelClose(StateChange):
    """ User is closing an existing channel. """

    def __init__(self, payment_network_identifier, token_address, channel_identifier):
        self.payment_network_identifier = payment_network_identifier
        self.token_address = token_address
        self.channel_identifier = channel_identifier

    def __repr__(self):
        return '<ActionChannelClose channel:{}>'.format(
            pex(self.channel_identifier),
        )

    def __eq__(self, other):
        return (
            isinstance(other, ActionChannelClose) and
            self.payment_network_identifier == other.payment_network_identifier and
            self.token_address == other.token_address and
            self.channel_identifier == other.channel_identifier
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class ActionCancelTransfer(StateChange):
    """ The user requests the transfer to be cancelled.

    This state change can fail, it depends on the node's role and the current
    state of the transfer.
    """

    def __init__(self, identifier):
        self.identifier = identifier

    def __repr__(self):
        return '<ActionCancelTransfer identifier:{}>'.format(
            self.identifier,
        )

    def __eq__(self, other):
        return (
            isinstance(other, ActionCancelTransfer) and
            self.identifier == other.identifier
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class ActionTransferDirect(StateChange):
    def __init__(
            self,
            payment_network_identifier,
            token_address,
            receiver_address: typing._Address,
            identifier,
            amount: int,
    ):
        if not isinstance(receiver_address, typing._Address):
            raise ValueError('receiver_address must be address')

        if not isinstance(amount, int):
            raise ValueError('amount must be int')

        self.payment_network_identifier = payment_network_identifier
        self.token_address = token_address
        self.identifier = identifier
        self.amount = amount
        self.receiver_address = receiver_address

    def __repr__(self):
        return '<ActionTransferDirect receiver_address:{} identifier:{} amount:{}>'.format(
            pex(self.receiver_address),
            self.identifier,
            self.amount,
        )

    def __eq__(self, other):
        return (
            isinstance(other, ActionTransferDirect) and
            self.payment_network_identifier == other.payment_network_identifier and
            self.token_address == other.token_address and
            self.receiver_address == other.receiver_address and
            self.identifier == other.identifier and
            self.amount == other.amount
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class ContractReceiveChannelNew(StateChange):
    """ A new channel was created and this node IS a participant. """

    def __init__(self, payment_network_identifier, token_address, channel_state):
        self.payment_network_identifier = payment_network_identifier
        self.token_address = token_address
        self.channel_state = channel_state

    def __repr__(self):
        return '<ContractReceiveChannelNew network:{} token:{} state:{}>'.format(
            pex(self.payment_network_identifier),
            pex(self.token_address),
            self.channel_state,
        )

    def __eq__(self, other):
        return (
            isinstance(other, ContractReceiveChannelNew) and
            self.payment_network_identifier == other.payment_network_identifier and
            self.token_address == other.token_address and
            self.channel_state == other.channel_state
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class ContractReceiveChannelClosed(StateChange):
    """ A channel to which this node IS a participant was closed. """

    def __init__(
            self,
            payment_network_identifier,
            token_address,
            channel_identifier,
            closing_address: typing.Address,
            closed_block_number: typing.BlockNumber):

        if not isinstance(closing_address, typing._Address):
            raise ValueError('closing_address must be of type address')

        if not isinstance(closed_block_number, typing._BlockNumber):
            raise ValueError('closed_block_number must be of type block_number')

        self.payment_network_identifier = payment_network_identifier
        self.token_address = token_address
        self.channel_identifier = channel_identifier
        self.closing_address = closing_address
        self.closed_block_number = closed_block_number

    def __repr__(self):
        return (
            '<ContractReceiveChannelClosed'
            ' network:{} token:{} channel:{} closer:{} closed_at:{}'
            '>'
        ).format(
            pex(self.payment_network_identifier),
            pex(self.token_address),
            pex(self.channel_identifier),
            pex(self.closing_address),
            self.closed_block_number
        )

    def __eq__(self, other):
        return (
            isinstance(other, ContractReceiveChannelClosed) and
            self.payment_network_identifier == other.payment_network_identifier and
            self.token_address == other.token_address and
            self.channel_identifier == other.channel_identifier and
            self.closing_address == other.closing_address and
            self.closed_block_number == other.closing_address
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class ActionInitNode(StateChange):
    def __init__(self, block_number: int):
        if not isinstance(block_number, int):
            raise ValueError('block_number must be int')

        self.block_number = block_number

    def __repr__(self):
        return '<ActionInitNode block_number:{}>'.format(self.block_number)

    def __eq__(self, other):
        return (
            isinstance(other, ActionInitNode) and
            self.block_number == other.block_number
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class ActionNewTokenNetwork(StateChange):
    """ Registers a new token network.
    A token network corresponds to a channel manager smart contract.
    """

    def __init__(self, payment_network_identifier, token_network: TokenNetworkState):
        if not isinstance(token_network, TokenNetworkState):
            raise ValueError('token_network must be a TokenNetworkState instance.')

        self.payment_network_identifier = payment_network_identifier
        self.token_network = token_network

    def __repr__(self):
        return '<ActionNewTokenNetwork network:{} token:{}>'.format(
            pex(self.payment_network_identifier),
            self.token_network,
        )

    def __eq__(self, other):
        return (
            isinstance(other, ActionNewTokenNetwork) and
            self.payment_network_identifier == other.payment_network_identifier and
            self.token_network == other.token_network
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class ContractReceiveChannelNewBalance(StateChange):
    """ A channel to which this node IS a participant had a deposit. """
    def __init__(
            self,
            payment_network_identifier,
            token_address,
            channel_identifier,
            deposit_transaction,
    ):
        self.payment_network_identifier = payment_network_identifier
        self.token_address = token_address
        self.channel_identifier = channel_identifier
        self.deposit_transaction = deposit_transaction

    def __repr__(self):
        return (
            '<ContractReceiveChannelNewBalance network:{} token:{} '
            'channel:{} transaction:{}>'.format(
                pex(self.payment_network_identifier),
                pex(self.token_address),
                pex(self.channel_identifier),
                self.deposit_transaction,
            )
        )

    def __eq__(self, other):
        return (
            isinstance(other, ContractReceiveChannelNewBalance) and
            self.payment_network_identifier == other.payment_network_identifier and
            self.token_address == other.token_address and
            self.channel_identifier == other.channel_identifier and
            self.deposit_transaction == other.deposit_transaction
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class ContractReceiveChannelSettled(StateChange):
    """ A channel to which this node IS a participant was settled. """

    def __init__(
            self,
            payment_network_identifier,
            token_address,
            channel_identifier,
            settle_block_number: int,
    ):
        if not isinstance(settle_block_number, int):
            raise ValueError('settle_block_number must be of type int')

        self.payment_network_identifier = payment_network_identifier
        self.token_address = token_address
        self.channel_identifier = channel_identifier
        self.settle_block_number = settle_block_number

    def __repr__(self):
        return (
            '<ContractReceiveChannelSettled'
            ' network:{} token:{} channel:{} settle_block:{}'
            '>'
        ).format(
            pex(self.payment_network_identifier),
            pex(self.token_address),
            pex(self.channel_identifier),
            self.settle_block_number,
        )

    def __eq__(self, other):
        return (
            isinstance(other, ContractReceiveChannelSettled) and
            self.payment_network_identifier == other.payment_network_identifier and
            self.token_address == other.token_address and
            self.channel_identifier == other.channel_identifier and
            self.settle_block_number == other.settle_block_number
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class ActionLeaveAllNetworks(StateChange):
    """ User is quitting all payment networks. """

    def __repr__(self):
        return '<ActionLeaveAllNetworks>'

    def __eq__(self, other):
        return isinstance(other, ActionLeaveAllNetworks)

    def __ne__(self, other):
        return not self.__eq__(other)


class ActionChangeNodeNetworkState(StateChange):
    """ The network state of `node_address` changed. """

    def __init__(self, node_address: typing.Address, network_state):
        if not isinstance(node_address, typing._Address):
            raise ValueError('node_address must be an address instance')

        self.node_address = node_address
        self.network_state = network_state

    def __repr__(self):
        return '<ActionChangeNodeNetworkState node:{} state:{}>'.format(
            pex(self.node_address),
            self.network_state,
        )

    def __eq__(self, other):
        return (
            isinstance(other, ActionChangeNodeNetworkState) and
            self.node_address == other.node_address and
            self.network_state == other.network_state
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class ContractReceiveNewPaymentNetwork(StateChange):
    """ Registers a new payment network.
    A payment network corresponds to a registry smart contract.
    """

    def __init__(self, payment_network: PaymentNetworkState):
        if not isinstance(payment_network, PaymentNetworkState):
            raise ValueError('payment_network must be a PaymentNetworkState instance')

        self.payment_network = payment_network

    def __repr__(self):
        return '<ContractReceiveNewPaymentNetwork network:{}>'.format(
            self.payment_network,
        )

    def __eq__(self, other):
        return (
            isinstance(other, ContractReceiveNewPaymentNetwork) and
            self.payment_network == other.payment_network
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class ContractReceiveNewTokenNetwork(StateChange):
    """ A new token was registered with the payment network. """

    def __init__(self, payment_network_identifier, token_network):
        if not isinstance(token_network, TokenNetworkState):
            raise ValueError('token_network must be a TokenNetworkState instance')

        self.payment_network_identifier = payment_network_identifier
        self.token_network = token_network

    def __repr__(self):
        return '<ContractReceiveNewTokenNetwork payment_network:{} network:{}>'.format(
            pex(self.payment_network_identifier),
            self.token_network,
        )

    def __eq__(self, other):
        return (
            isinstance(other, ContractReceiveNewTokenNetwork) and
            self.payment_network_identifier == other.payment_network_identifier and
            self.token_network == other.token_network
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class ContractReceiveChannelWithdraw(StateChange):
    """ A lock was withdrawn via the blockchain.
    Used when a hash time lock was withdrawn and a log ChannelSecretRevealed is
    emitted by the netting channel.
    Note:
        For this state change the contract caller is not important but only the
        receiving address. `receiver` is the address to which the lock's token
        was transferred, this may be either of the channel participants.
        If the channel was used for a mediated transfer that was refunded, this
        event must be used twice, once for each receiver.
    """

    def __init__(
            self,
            payment_network_identifier,
            token_address,
            channel_identifier,
            secret,
            receiver: typing.Address):

        if not isinstance(receiver, typing._Address):
            raise ValueError('receiver must be of type address')

        hashlock = sha3(secret)

        self.payment_network_identifier = payment_network_identifier
        self.token_address = token_address
        self.channel_identifier = channel_identifier
        self.secret = secret
        self.hashlock = hashlock
        self.receiver = receiver

    def __repr__(self):
        return '<ContractReceiveChannelWithdraw channel:{} receive:{} hashlock:{}>'.format(
            pex(self.channel_identifier),
            pex(self.receiver),
            pex(self.hashlock),
        )

    def __eq__(self, other):
        return (
            isinstance(other, ContractReceiveChannelWithdraw) and
            self.payment_network_identifier == other.payment_network_identifier and
            self.token_network_identifier == other.token_network_identifier and
            self.channel_identifier == other.channel_identifier and
            self.secret == other.secret and
            self.hashlock == other.hashlock and
            self.receiver == other.receiver
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class ContractReceiveNewRoute(StateChange):
    """ New channel was created and this node is NOT a participant. """

    def __init__(self, participant1: typing.Address, participant2: typing.Address):
        if not isinstance(participant1, typing._Address):
            raise ValueError('participant1 must be of type address')

        if not isinstance(participant2, typing._Address):
            raise ValueError('participant2 must be of type address')

        self.participant1 = participant1
        self.participant2 = participant2

    def __repr__(self):
        return '<ContractReceiveNewRoute node1:{} node2:{}>'.format(
            pex(self.participant1),
            pex(self.participant2),
        )

    def __eq__(self, other):
        return (
            isinstance(other, ContractReceiveNewRoute) and
            self.participant1 == other.participant1 and
            self.participant2 == other.participant2
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class ContractReceiveRouteNew(StateChange):
    """ New channel was created and this node is NOT a participant. """

    def __init__(
            self,
            payment_network_identifier,
            token_address,
            participant1: typing.Address,
            participant2: typing.Address,
    ):

        if not isinstance(participant1, typing.T_Address):
            raise ValueError('participant1 must be of type address')

        if not isinstance(participant2, typing._Address):
            raise ValueError('participant2 must be of type address')

        self.payment_network_identifier = payment_network_identifier
        self.token_address = token_address
        self.participant1 = participant1
        self.participant2 = participant2

    def __repr__(self):
        return '<ContractReceiveRouteNew network:{} token:{} node1:{} node2:{}>'.format(
            pex(self.payment_network_identifier),
            pex(self.token_address),
            pex(self.participant1),
            pex(self.participant2),
        )

    def __eq__(self, other):
        return (
            isinstance(other, ContractReceiveRouteNew) and
            self.payment_network_identifier == other.payment_network_identifier and
            self.token_address == other.token_address and
            self.participant1 == other.participant1 and
            self.participant2 == other.participant2
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class ReceiveTransferDirect(StateChange):
    def __init__(
            self,
            payment_network_identifier,
            token_address,
            transfer_identifier,
            balance_proof,
    ):
        if not isinstance(balance_proof, BalanceProofSignedState):
            raise ValueError('balance_proof must be a BalanceProofSignedState instance')

        self.payment_network_identifier = payment_network_identifier
        self.token_address = token_address
        self.transfer_identifier = transfer_identifier
        self.balance_proof = balance_proof

    def __repr__(self):
        return (
            '<ReceiveTransferDirect'
            ' network:{} token:{} id:{} balance_proof:{}'
            '>'
        ).format(
            pex(self.payment_network_identifier),
            pex(self.token_address),
            self.transfer_identifier,
            self.balance_proof,
        )

    def __eq__(self, other):
        return (
            isinstance(other, ReceiveTransferDirect) and
            self.payment_network_identifier == other.payment_network_identifier and
            self.token_address == other.token_address and
            self.transfer_identifier == other.transfer_identifier and
            self.balance_proof == other.balance_proof
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class ReceiveUnlock(StateChange):
    def __init__(self, secret, balance_proof: BalanceProofSignedState):
        if not isinstance(balance_proof, BalanceProofSignedState):
            raise ValueError('balance_proof must be an instance of BalanceProofSignedState')

        hashlock = sha3(secret)

        self.secret = secret
        self.hashlock = hashlock
        self.balance_proof = balance_proof

    def __repr__(self):
        return '<ReceiveUnlock hashlock: {} balance_proof: {}>'.format(
            pex(self.hashlock),
            self.balance_proof,
        )

    def __eq__(self, other):
        return (
            isinstance(other, ReceiveUnlock) and
            self.secret == other.secret and
            self.hashlock == other.hashlock and
            self.balance_proof == other.balance_proof
        )

    def __ne__(self, other):
        return not self.__eq__(other)
