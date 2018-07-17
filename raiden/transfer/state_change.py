# pylint: disable=too-few-public-methods,too-many-arguments,too-many-instance-attributes
from raiden.transfer.architecture import StateChange
from raiden.transfer.state import (
    BalanceProofSignedState,
    NettingChannelState,
    PaymentNetworkState,
    TransactionChannelNewBalance,
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
        if not isinstance(block_number, typing.T_BlockNumber):
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

    def __init__(self, payment_identifier: typing.PaymentID):
        self.payment_identifier = payment_identifier

    def __repr__(self):
        return '<ActionCancelPayment identifier:{}>'.format(
            self.payment_identifier,
        )

    def __eq__(self, other):
        return (
            isinstance(other, ActionCancelPayment) and
            self.payment_identifier == other.payment_identifier
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class ActionChannelClose(StateChange):
    """ User is closing an existing channel. """

    def __init__(
            self,
            token_network_identifier: typing.TokenNetworkID,
            channel_identifier: typing.ChannelID,
    ):
        self.token_network_identifier = token_network_identifier
        self.channel_identifier = channel_identifier

    def __repr__(self):
        return '<ActionChannelClose channel:{}>'.format(
            pex(self.channel_identifier),
        )

    def __eq__(self, other):
        return (
            isinstance(other, ActionChannelClose) and
            self.token_network_identifier == other.token_network_identifier and
            self.channel_identifier == other.channel_identifier
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class ActionCancelTransfer(StateChange):
    """ The user requests the transfer to be cancelled.

    This state change can fail, it depends on the node's role and the current
    state of the transfer.
    """

    def __init__(self, transfer_identifier: typing.TransferID) -> None:
        self.transfer_identifier = transfer_identifier

    def __repr__(self):
        return '<ActionCancelTransfer identifier:{}>'.format(
            self.transfer_identifier,
        )

    def __eq__(self, other):
        return (
            isinstance(other, ActionCancelTransfer) and
            self.transfer_identifier == other.transfer_identifier
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class ActionTransferDirect(StateChange):
    def __init__(
            self,
            token_network_identifier: typing.TokenNetworkIdentifier,
            receiver_address: typing.Address,
            payment_identifier: typing.PaymentID,
            amount: typing.PaymentAmount,
    ):
        if not isinstance(receiver_address, typing.T_Address):
            raise ValueError('receiver_address must be address')

        if not isinstance(amount, int):
            raise ValueError('amount must be int')

        self.token_network_identifier = token_network_identifier
        self.amount = amount
        self.receiver_address = receiver_address
        self.payment_identifier = payment_identifier

    def __repr__(self):
        return '<ActionTransferDirect receiver_address:{} identifier:{} amount:{}>'.format(
            pex(self.receiver_address),
            self.payment_identifier,
            self.amount,
        )

    def __eq__(self, other):
        return (
            isinstance(other, ActionTransferDirect) and
            self.token_network_identifier == other.token_network_identifier and
            self.receiver_address == other.receiver_address and
            self.payment_identifier == other.payment_identifier and
            self.amount == other.amount
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class ContractReceiveChannelNew(StateChange):
    """ A new channel was created and this node IS a participant. """

    def __init__(
            self,
            token_network_identifier: typing.TokenNetworkID,
            channel_state: NettingChannelState,
    ):
        self.token_network_identifier = token_network_identifier
        self.channel_state = channel_state

    def __repr__(self):
        return '<ContractReceiveChannelNew token_network:{} state:{}>'.format(
            pex(self.token_network_identifier),
            self.channel_state,
        )

    def __eq__(self, other):
        return (
            isinstance(other, ContractReceiveChannelNew) and
            self.token_network_identifier == other.token_network_identifier and
            self.channel_state == other.channel_state
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class ContractReceiveChannelClosed(StateChange):
    """ A channel to which this node IS a participant was closed. """

    def __init__(
            self,
            token_network_identifier: typing.TokenNetworkID,
            channel_identifier: typing.ChannelID,
            closing_address: typing.Address,
            closed_block_number: typing.BlockNumber,
    ):

        if not isinstance(closing_address, typing.T_Address):
            raise ValueError('closing_address must be of type address')

        if not isinstance(closed_block_number, typing.T_BlockNumber):
            raise ValueError('closed_block_number must be of type block_number')

        self.token_network_identifier = token_network_identifier
        self.channel_identifier = channel_identifier
        self.closing_address = closing_address
        self.closed_block_number = closed_block_number

    def __repr__(self):
        return (
            '<ContractReceiveChannelClosed'
            ' token_network:{} channel:{} closer:{} closed_at:{}'
            '>'
        ).format(
            pex(self.token_network_identifier),
            pex(self.channel_identifier),
            pex(self.closing_address),
            self.closed_block_number,
        )

    def __eq__(self, other):
        return (
            isinstance(other, ContractReceiveChannelClosed) and
            self.token_network_identifier == other.token_network_identifier and
            self.channel_identifier == other.channel_identifier and
            self.closing_address == other.closing_address and
            self.closed_block_number == other.closing_address
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class ActionInitChain(StateChange):
    def __init__(
            self,
            pseudo_random_generator,
            block_number: typing.BlockNumber,
            chain_id: typing.ChainID,
    ):
        if not isinstance(block_number, int):
            raise ValueError('block_number must be int')

        if not isinstance(chain_id, int):
            raise ValueError('chain_id must be int')

        self.pseudo_random_generator = pseudo_random_generator
        self.block_number = block_number
        self.chain_id = chain_id

    def __repr__(self):
        return '<ActionInitChain block_number:{} chain_id:{}>'.format(
            self.block_number,
            self.chain_id,
        )

    def __eq__(self, other):
        return (
            isinstance(other, ActionInitChain) and
            self.pseudo_random_generator == other.pseudo_random_generator and
            self.block_number == other.block_number and
            self.chain_id == other.chain_id
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class ActionNewTokenNetwork(StateChange):
    """ Registers a new token network.
    A token network corresponds to a channel manager smart contract.
    """

    def __init__(
            self,
            payment_network_identifier: typing.PaymentNetworkID,
            token_network: TokenNetworkState,
    ):
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
            token_network_identifier: typing.TokenNetworkID,
            channel_identifier: typing.ChannelID,
            deposit_transaction: TransactionChannelNewBalance,
    ):
        self.token_network_identifier = token_network_identifier
        self.channel_identifier = channel_identifier
        self.deposit_transaction = deposit_transaction

    def __repr__(self):
        return (
            '<ContractReceiveChannelNewBalance token_network:{} channel:{} transaction:{}>'.format(
                pex(self.token_network_identifier),
                pex(self.channel_identifier),
                self.deposit_transaction,
            )
        )

    def __eq__(self, other):
        return (
            isinstance(other, ContractReceiveChannelNewBalance) and
            self.token_network_identifier == other.token_network_identifier and
            self.channel_identifier == other.channel_identifier and
            self.deposit_transaction == other.deposit_transaction
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class ContractReceiveChannelSettled(StateChange):
    """ A channel to which this node IS a participant was settled. """

    def __init__(
            self,
            token_network_identifier: typing.TokenNetworkID,
            channel_identifier: typing.ChannelID,
            settle_block_number: typing.BlockNumber,
    ):
        if not isinstance(settle_block_number, int):
            raise ValueError('settle_block_number must be of type int')

        self.token_network_identifier = token_network_identifier
        self.channel_identifier = channel_identifier
        self.settle_block_number = settle_block_number

    def __repr__(self):
        return (
            '<ContractReceiveChannelSettled token_network:{} channel:{} settle_block:{}'
            '>'
        ).format(
            pex(self.token_network_identifier),
            pex(self.channel_identifier),
            self.settle_block_number,
        )

    def __eq__(self, other):
        return (
            isinstance(other, ContractReceiveChannelSettled) and
            self.token_network_identifier == other.token_network_identifier and
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

    def __init__(
            self,
            node_address: typing.Address,
            network_state,
    ):
        if not isinstance(node_address, typing.T_Address):
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

    def __init__(
            self,
            payment_network_identifier: typing.PaymentNetworkID,
            token_network: TokenNetworkState,
    ):
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


class ContractReceiveSecretReveal(StateChange):
    """ A new secret was registered with the SecretRegistry contract. """

    def __init__(
        self,
        secret_registry_address: typing.SecretRegistryAddress,
        secrethash: typing.SecretHash,
        secret: typing.Secret,
    ):
        if not isinstance(secret_registry_address, typing.T_SecretRegistryAddress):
            raise ValueError('secret_registry_address must be of type SecretRegistryAddress')
        if not isinstance(secrethash, typing.T_SecretHash):
            raise ValueError('secrethash must be of type SecretHash')
        if not isinstance(secret, typing.T_Secret):
            raise ValueError('secret must be of type Secret')

        self.secret_registry_address = secret_registry_address
        self.secrethash = secrethash
        self.secret = secret

    def __repr__(self):
        return '<ContractReceiveSecretReveal secret_registry:{} secrethash:{} secret:{}>'.format(
            pex(self.secret_registry_address),
            pex(self.secrethash),
            pex(self.secret),
        )

    def __eq__(self, other):
        return (
            isinstance(other, ContractReceiveSecretReveal) and
            self.secret_registry_address == other.secret_registry_address and
            self.secrethash == other.secrethash and
            self.secret == other.secret
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class ContractReceiveChannelBatchUnlock(StateChange):
    """ All the locks were claimed via the blockchain.

    Used when all the hash time locks were unlocked and a log ChannelUnlocked is emitted
    by the token network contract.
    Note:
        For this state change the contract caller is not important but only the
        receiving address. `participant` is the address to which the `unlocked_amount`
        was transferred. `returned_tokens` was transferred to the channel partner.
    """

    def __init__(
            self,
            token_network_identifier: typing.TokenNetworkIdentifier,
            participant: typing.Address,
            partner: typing.Address,
            locksroot: typing.Locksroot,
            unlocked_amount: typing.TokenAmount,
            returned_tokens: typing.TokenAmount,
    ):

        if not isinstance(token_network_identifier, typing.T_TokenNetworkIdentifier):
            raise ValueError('token_network_identifier must be of type TokenNtetworkIdentifier')

        if not isinstance(participant, typing.T_Address):
            raise ValueError('participant must be of type address')

        if not isinstance(partner, typing.T_Address):
            raise ValueError('partner must be of type address')

        self.token_network_identifier = token_network_identifier
        self.participant = participant
        self.partner = partner
        self.locksroot = locksroot
        self.unlocked_amount = unlocked_amount
        self.returned_tokens = returned_tokens

    def __repr__(self):
        return (
            '<ContractReceiveChannelBatchUnlock'
            'token_network:{} participant:{} partner:{} locksroot:{} unlocked:{} returned:{}'
            '>'
        ).format(
            self.token_network_identifier,
            self.participant,
            self.partner,
            self.locksroot,
            self.unlocked_amount,
            self.returned_tokens,
        )

    def __eq__(self, other):
        return (
            isinstance(other, ContractReceiveChannelBatchUnlock) and
            self.token_network_identifier == other.token_network_identifier and
            self.participant == other.participant and
            self.partner == other.partner and
            self.locksroot == other.locksroot and
            self.unlocked_amount == other.unlocked_amount and
            self.returned_tokens == other.returned_tokens
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class ContractReceiveNewRoute(StateChange):
    """ New channel was created and this node is NOT a participant. """

    def __init__(self, participant1: typing.Address, participant2: typing.Address):
        if not isinstance(participant1, typing.T_Address):
            raise ValueError('participant1 must be of type address')

        if not isinstance(participant2, typing.T_Address):
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
            token_network_identifier: typing.TokenNetworkID,
            participant1: typing.Address,
            participant2: typing.Address,
    ):

        if not isinstance(participant1, typing.T_Address):
            raise ValueError('participant1 must be of type address')

        if not isinstance(participant2, typing.T_Address):
            raise ValueError('participant2 must be of type address')

        self.token_network_identifier = token_network_identifier
        self.participant1 = participant1
        self.participant2 = participant2

    def __repr__(self):
        return '<ContractReceiveRouteNew token_network:{} node1:{} node2:{}>'.format(
            pex(self.token_network_identifier),
            pex(self.participant1),
            pex(self.participant2),
        )

    def __eq__(self, other):
        return (
            isinstance(other, ContractReceiveRouteNew) and
            self.token_network_identifier == other.token_network_identifier and
            self.participant1 == other.participant1 and
            self.participant2 == other.participant2
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class ReceiveTransferDirect(StateChange):
    def __init__(
            self,
            token_network_identifier: typing.TokenNetworkID,
            message_identifier: typing.MessageID,
            payment_identifier: typing.PaymentID,
            balance_proof: BalanceProofSignedState,
    ):
        if not isinstance(balance_proof, BalanceProofSignedState):
            raise ValueError('balance_proof must be a BalanceProofSignedState instance')

        self.token_network_identifier = token_network_identifier
        self.message_identifier = message_identifier
        self.payment_identifier = payment_identifier
        self.balance_proof = balance_proof

    def __repr__(self):
        return (
            '<ReceiveTransferDirect'
            ' token_network:{} msgid:{} paymentid:{} balance_proof:{}'
            '>'
        ).format(
            pex(self.token_network_identifier),
            self.message_identifier,
            self.payment_identifier,
            self.balance_proof,
        )

    def __eq__(self, other):
        return (
            isinstance(other, ReceiveTransferDirect) and
            self.token_network_identifier == other.token_network_identifier and
            self.message_identifier == other.message_identifier and
            self.payment_identifier == other.payment_identifier and
            self.balance_proof == other.balance_proof
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class ReceiveUnlock(StateChange):
    def __init__(
            self,
            message_identifier: typing.MessageID,
            secret: typing.Secret,
            balance_proof: BalanceProofSignedState,
    ):
        if not isinstance(balance_proof, BalanceProofSignedState):
            raise ValueError('balance_proof must be an instance of BalanceProofSignedState')

        secrethash: typing.SecretHash = typing.SecretHash(sha3(secret))

        self.message_identifier = message_identifier
        self.secret = secret
        self.secrethash = secrethash
        self.balance_proof = balance_proof

    def __repr__(self):
        return '<ReceiveUnlock msgid:{} secrethash:{} balance_proof:{}>'.format(
            self.message_identifier,
            pex(self.secrethash),
            self.balance_proof,
        )

    def __eq__(self, other):
        return (
            isinstance(other, ReceiveUnlock) and
            self.message_identifier == other.message_identifier and
            self.secret == other.secret and
            self.secrethash == other.secrethash and
            self.balance_proof == other.balance_proof
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class ReceiveDelivered(StateChange):
    def __init__(self, message_identifier: typing.MessageID):
        self.message_identifier = message_identifier

    def __repr__(self):
        return '<ReceiveDelivered msgid:{}>'.format(
            self.message_identifier,
        )

    def __eq__(self, other):
        return (
            isinstance(other, ReceiveDelivered) and
            self.message_identifier == other.message_identifier
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class ReceiveProcessed(StateChange):
    def __init__(self, message_identifier: typing.MessageID):
        self.message_identifier = message_identifier

    def __repr__(self):
        return '<ReceiveProcessed msgid:{}>'.format(
            self.message_identifier,
        )

    def __eq__(self, other):
        return (
            isinstance(other, ReceiveProcessed) and
            self.message_identifier == other.message_identifier
        )

    def __ne__(self, other):
        return not self.__eq__(other)
