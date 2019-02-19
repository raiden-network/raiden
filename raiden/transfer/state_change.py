# pylint: disable=too-few-public-methods,too-many-arguments,too-many-instance-attributes
from eth_utils import to_canonical_address, to_checksum_address

from raiden.transfer.architecture import (
    AuthenticatedSenderStateChange,
    BalanceProofStateChange,
    ContractReceiveStateChange,
    StateChange,
)
from raiden.transfer.state import (
    BalanceProofSignedState,
    NettingChannelState,
    PaymentNetworkState,
    TokenNetworkState,
    TransactionChannelNewBalance,
)
from raiden.transfer.utils import pseudo_random_generator_from_json
from raiden.utils import pex, sha3
from raiden.utils.serialization import deserialize_bytes, serialize_bytes
from raiden.utils.typing import (
    Address,
    Any,
    BlockGasLimit,
    BlockHash,
    BlockNumber,
    ChainID,
    ChannelID,
    Dict,
    Locksroot,
    MessageID,
    Nonce,
    PaymentID,
    PaymentNetworkID,
    Secret,
    SecretHash,
    SecretRegistryAddress,
    T_Address,
    T_BlockHash,
    T_BlockNumber,
    T_Secret,
    T_SecretHash,
    T_SecretRegistryAddress,
    T_TokenNetworkID,
    TokenAmount,
    TokenNetworkID,
    TransactionHash,
    TransferID,
)


class Block(StateChange):
    """ Transition used when a new block is mined.
    Args:
        block_number: The current block_number.
    """

    def __init__(
            self,
            block_number: BlockNumber,
            gas_limit: BlockGasLimit,
            block_hash: BlockHash,
    ):
        if not isinstance(block_number, T_BlockNumber):
            raise ValueError('block_number must be of type block_number')

        self.block_number = block_number
        self.gas_limit = gas_limit
        self.block_hash = block_hash

    def __repr__(self):
        return (
            f'<Block '
            f'number={self.block_number} gas_limit={self.gas_limit} '
            f'block_hash={pex(self.block_hash)}'
            f'>'
        )

    def __eq__(self, other):
        return (
            isinstance(other, Block) and
            self.block_number == other.block_number and
            self.gas_limit == other.gas_limit and
            self.block_hash == other.block_hash
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'block_number': str(self.block_number),
            'gas_limit': self.gas_limit,
            'block_hash': serialize_bytes(self.block_hash),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Block':
        return cls(
            block_number=BlockNumber(int(data['block_number'])),
            gas_limit=data['gas_limit'],
            block_hash=deserialize_bytes(data['block_hash']),
        )


class ActionUpdateTransportAuthData(StateChange):
    """ Holds the last "timestamp" at which we synced
    with the transport. The timestamp could be a date/time value
    or any other value provided by the transport backend.
    Can be used later to filter the messages which have not been processed.
    """

    def __init__(self, auth_data: str):
        self.auth_data = auth_data

    def __repr__(self) -> str:
        return '<ActionUpdateTransportAuthData value:{}>'.format(
            self.auth_data,
        )

    def __eq__(self, other: 'ActionUpdateTransportAuthData') -> bool:
        return (
            isinstance(other, ActionUpdateTransportAuthData) and
            self.auth_data == other.auth_data
        )

    def __ne__(self, other: 'ActionUpdateTransportAuthData') -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'auth_data': str(self.auth_data),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ActionUpdateTransportAuthData':
        return cls(
            auth_data=data['auth_data'],
        )


class ActionCancelPayment(StateChange):
    """ The user requests the transfer to be cancelled.
    This state change can fail, it depends on the node's role and the current
    state of the transfer.
    """

    def __init__(self, payment_identifier: PaymentID):
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

    def to_dict(self) -> Dict[str, Any]:
        return {
            'payment_identifier': str(self.payment_identifier),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ActionCancelPayment':
        return cls(
            payment_identifier=int(data['payment_identifier']),
        )


class ActionChannelClose(StateChange):
    """ User is closing an existing channel. """

    def __init__(
            self,
            token_network_identifier: TokenNetworkID,
            channel_identifier: ChannelID,
    ):
        self.token_network_identifier = token_network_identifier
        self.channel_identifier = channel_identifier

    def __repr__(self):
        return '<ActionChannelClose channel_identifier:{}>'.format(
            self.channel_identifier,
        )

    def __eq__(self, other):
        return (
            isinstance(other, ActionChannelClose) and
            self.token_network_identifier == other.token_network_identifier and
            self.channel_identifier == other.channel_identifier
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'token_network_identifier': to_checksum_address(self.token_network_identifier),
            'channel_identifier': str(self.channel_identifier),
        }

    @classmethod
    def from_dict(cls, data):
        return cls(
            token_network_identifier=to_canonical_address(data['token_network_identifier']),
            channel_identifier=int(data['channel_identifier']),
        )


class ActionCancelTransfer(StateChange):
    """ The user requests the transfer to be cancelled.

    This state change can fail, it depends on the node's role and the current
    state of the transfer.
    """

    def __init__(self, transfer_identifier: TransferID) -> None:
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

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ActionCancelTransfer':
        return cls(
            transfer_identifier=data['transfer_identifier'],
        )


class ContractReceiveChannelNew(ContractReceiveStateChange):
    """ A new channel was created and this node IS a participant. """

    def __init__(
            self,
            transaction_hash: TransactionHash,
            token_network_identifier: TokenNetworkID,
            channel_state: NettingChannelState,
            block_number: BlockNumber,
            block_hash: BlockHash,
    ):
        super().__init__(transaction_hash, block_number, block_hash)

        self.token_network_identifier = token_network_identifier
        self.channel_state = channel_state
        self.channel_identifier = channel_state.identifier

    def __repr__(self):
        return (
            '<ContractReceiveChannelNew token_network:{} state:{} block:{}>'.format(
                pex(self.token_network_identifier),
                self.channel_state,
                self.block_number,
            )
        )

    def __eq__(self, other):
        return (
            isinstance(other, ContractReceiveChannelNew) and
            self.token_network_identifier == other.token_network_identifier and
            self.channel_state == other.channel_state and
            super().__eq__(other)
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'transaction_hash': serialize_bytes(self.transaction_hash),
            'token_network_identifier': to_checksum_address(self.token_network_identifier),
            'channel_state': self.channel_state,
            'block_number': str(self.block_number),
            'block_hash': serialize_bytes(self.block_hash),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ContractReceiveChannelNew':
        return cls(
            transaction_hash=deserialize_bytes(data['transaction_hash']),
            token_network_identifier=to_canonical_address(data['token_network_identifier']),
            channel_state=data['channel_state'],
            block_number=BlockNumber(int(data['block_number'])),
            block_hash=BlockHash(deserialize_bytes(data['block_hash'])),
        )


class ContractReceiveChannelClosed(ContractReceiveStateChange):
    """ A channel to which this node IS a participant was closed. """

    def __init__(
            self,
            transaction_hash: TransactionHash,
            transaction_from: Address,
            token_network_identifier: TokenNetworkID,
            channel_identifier: ChannelID,
            block_number: BlockNumber,
            block_hash: BlockHash,
    ):
        super().__init__(transaction_hash, block_number, block_hash)

        self.transaction_from = transaction_from
        self.token_network_identifier = token_network_identifier
        self.channel_identifier = channel_identifier

    def __repr__(self):
        return (
            '<ContractReceiveChannelClosed'
            ' token_network:{} channel:{} closer:{} closed_at:{}'
            '>'
        ).format(
            pex(self.token_network_identifier),
            self.channel_identifier,
            pex(self.transaction_from),
            self.block_number,
        )

    def __eq__(self, other):
        return (
            isinstance(other, ContractReceiveChannelClosed) and
            self.transaction_from == other.transaction_from and
            self.token_network_identifier == other.token_network_identifier and
            self.channel_identifier == other.channel_identifier and
            super().__eq__(other)
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'transaction_hash': serialize_bytes(self.transaction_hash),
            'transaction_from': to_checksum_address(self.transaction_from),
            'token_network_identifier': to_checksum_address(self.token_network_identifier),
            'channel_identifier': str(self.channel_identifier),
            'block_number': str(self.block_number),
            'block_hash': serialize_bytes(self.block_hash),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ContractReceiveChannelClosed':
        return cls(
            transaction_hash=deserialize_bytes(data['transaction_hash']),
            transaction_from=to_canonical_address(data['transaction_from']),
            token_network_identifier=to_canonical_address(data['token_network_identifier']),
            channel_identifier=ChannelID(int(data['channel_identifier'])),
            block_number=BlockNumber(int(data['block_number'])),
            block_hash=BlockHash(deserialize_bytes(data['block_hash'])),
        )


class ActionInitChain(StateChange):
    def __init__(
            self,
            pseudo_random_generator,
            block_number: BlockNumber,
            block_hash: BlockHash,
            our_address: Address,
            chain_id: ChainID,
    ):
        if not isinstance(block_number, T_BlockNumber):
            raise ValueError('block_number must be of type BlockNumber')

        if not isinstance(block_hash, T_BlockHash):
            raise ValueError('block_hash must be of type BlockHash')

        if not isinstance(chain_id, int):
            raise ValueError('chain_id must be int')

        self.block_number = block_number
        self.block_hash = block_hash
        self.chain_id = chain_id
        self.our_address = our_address
        self.pseudo_random_generator = pseudo_random_generator

    def __repr__(self):
        return '<ActionInitChain block_number:{} block_hash:{} chain_id:{}>'.format(
            self.block_number,
            pex(self.block_hash),
            self.chain_id,
        )

    def __eq__(self, other):
        return (
            isinstance(other, ActionInitChain) and
            self.pseudo_random_generator.getstate() == other.pseudo_random_generator.getstate() and
            self.block_number == other.block_number and
            self.block_hash == other.block_hash and
            self.our_address == other.our_address and
            self.chain_id == other.chain_id
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'block_number': str(self.block_number),
            'block_hash': serialize_bytes(self.block_hash),
            'our_address': to_checksum_address(self.our_address),
            'chain_id': self.chain_id,
            'pseudo_random_generator': self.pseudo_random_generator.getstate(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ActionInitChain':
        pseudo_random_generator = pseudo_random_generator_from_json(data)

        return cls(
            pseudo_random_generator=pseudo_random_generator,
            block_number=BlockNumber(int(data['block_number'])),
            block_hash=deserialize_bytes(data['block_hash']),
            our_address=to_canonical_address(data['our_address']),
            chain_id=data['chain_id'],
        )


class ActionNewTokenNetwork(StateChange):
    """ Registers a new token network.
    A token network corresponds to a channel manager smart contract.
    """

    def __init__(
            self,
            payment_network_identifier: PaymentNetworkID,
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

    def to_dict(self) -> Dict[str, Any]:
        return {
            'payment_network_identifier': to_checksum_address(self.payment_network_identifier),
            'token_network': self.token_network,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ActionNewTokenNetwork':
        return cls(
            payment_network_identifier=to_canonical_address(data['payment_network_identifier']),
            token_network=data['token_network'],
        )


class ContractReceiveChannelNewBalance(ContractReceiveStateChange):
    """ A channel to which this node IS a participant had a deposit. """

    def __init__(
            self,
            transaction_hash: TransactionHash,
            token_network_identifier: TokenNetworkID,
            channel_identifier: ChannelID,
            deposit_transaction: TransactionChannelNewBalance,
            block_number: BlockNumber,
            block_hash: BlockHash,
    ):
        super().__init__(transaction_hash, block_number, block_hash)

        self.token_network_identifier = token_network_identifier
        self.channel_identifier = channel_identifier
        self.deposit_transaction = deposit_transaction

    def __repr__(self):
        return (
            '<ContractReceiveChannelNewBalance'
            ' token_network:{} channel:{} transaction:{} block_number:{}'
            '>'
        ).format(
            pex(self.token_network_identifier),
            self.channel_identifier,
            self.deposit_transaction,
            self.block_number,
        )

    def __eq__(self, other):
        return (
            isinstance(other, ContractReceiveChannelNewBalance) and
            self.token_network_identifier == other.token_network_identifier and
            self.channel_identifier == other.channel_identifier and
            self.deposit_transaction == other.deposit_transaction and
            super().__eq__(other)
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'transaction_hash': serialize_bytes(self.transaction_hash),
            'token_network_identifier': to_checksum_address(self.token_network_identifier),
            'channel_identifier': str(self.channel_identifier),
            'deposit_transaction': self.deposit_transaction,
            'block_number': str(self.block_number),
            'block_hash': serialize_bytes(self.block_hash),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ContractReceiveChannelNewBalance':
        return cls(
            transaction_hash=deserialize_bytes(data['transaction_hash']),
            token_network_identifier=to_canonical_address(data['token_network_identifier']),
            channel_identifier=ChannelID(int(data['channel_identifier'])),
            deposit_transaction=data['deposit_transaction'],
            block_number=BlockNumber(int(data['block_number'])),
            block_hash=BlockHash(deserialize_bytes(data['block_hash'])),
        )


class ContractReceiveChannelSettled(ContractReceiveStateChange):
    """ A channel to which this node IS a participant was settled. """

    def __init__(
            self,
            transaction_hash: TransactionHash,
            token_network_identifier: TokenNetworkID,
            channel_identifier: ChannelID,
            block_number: BlockNumber,
            block_hash: BlockHash,
    ):
        super().__init__(transaction_hash, block_number, block_hash)

        self.token_network_identifier = token_network_identifier
        self.channel_identifier = channel_identifier

    def __repr__(self):
        return (
            '<ContractReceiveChannelSettled token_network:{} channel:{} settle_block:{}>'
        ).format(
            pex(self.token_network_identifier),
            self.channel_identifier,
            self.block_number,
        )

    def __eq__(self, other):
        return (
            isinstance(other, ContractReceiveChannelSettled) and
            self.token_network_identifier == other.token_network_identifier and
            self.channel_identifier == other.channel_identifier and
            super().__eq__(other)
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'transaction_hash': serialize_bytes(self.transaction_hash),
            'token_network_identifier': to_checksum_address(self.token_network_identifier),
            'channel_identifier': str(self.channel_identifier),
            'block_number': str(self.block_number),
            'block_hash': serialize_bytes(self.block_hash),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ContractReceiveChannelSettled':
        return cls(
            transaction_hash=deserialize_bytes(data['transaction_hash']),
            token_network_identifier=to_canonical_address(data['token_network_identifier']),
            channel_identifier=ChannelID(int(data['channel_identifier'])),
            block_number=BlockNumber(int(data['block_number'])),
            block_hash=BlockHash(deserialize_bytes(data['block_hash'])),
        )


class ActionLeaveAllNetworks(StateChange):
    """ User is quitting all payment networks. """

    def __repr__(self):
        return '<ActionLeaveAllNetworks>'

    def __eq__(self, other):
        return isinstance(other, ActionLeaveAllNetworks)

    def __ne__(self, other):
        return not self.__eq__(other)

    @classmethod
    def from_dict(cls, _data: Dict[str, Any]) -> 'ActionLeaveAllNetworks':
        return cls()


class ActionChangeNodeNetworkState(StateChange):
    """ The network state of `node_address` changed. """

    def __init__(
            self,
            node_address: Address,
            network_state: str,
    ):
        if not isinstance(node_address, T_Address):
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

    def to_dict(self) -> Dict[str, Any]:
        return {
            'node_address': to_checksum_address(self.node_address),
            'network_state': self.network_state,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ActionChangeNodeNetworkState':
        return cls(
            node_address=to_canonical_address(data['node_address']),
            network_state=data['network_state'],
        )


class ContractReceiveNewPaymentNetwork(ContractReceiveStateChange):
    """ Registers a new payment network.
    A payment network corresponds to a registry smart contract.
    """

    def __init__(
            self,
            transaction_hash: TransactionHash,
            payment_network: PaymentNetworkState,
            block_number: BlockNumber,
            block_hash: BlockHash,
    ):
        if not isinstance(payment_network, PaymentNetworkState):
            raise ValueError('payment_network must be a PaymentNetworkState instance')

        super().__init__(transaction_hash, block_number, block_hash)

        self.payment_network = payment_network

    def __repr__(self):
        return '<ContractReceiveNewPaymentNetwork network:{} block:{}>'.format(
            self.payment_network,
            self.block_number,
        )

    def __eq__(self, other):
        return (
            isinstance(other, ContractReceiveNewPaymentNetwork) and
            self.payment_network == other.payment_network and
            super().__eq__(other)
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'transaction_hash': serialize_bytes(self.transaction_hash),
            'payment_network': self.payment_network,
            'block_number': str(self.block_number),
            'block_hash': serialize_bytes(self.block_hash),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ContractReceiveNewPaymentNetwork':
        return cls(
            transaction_hash=deserialize_bytes(data['transaction_hash']),
            payment_network=data['payment_network'],
            block_number=BlockNumber(int(data['block_number'])),
            block_hash=BlockHash(deserialize_bytes(data['block_hash'])),
        )


class ContractReceiveNewTokenNetwork(ContractReceiveStateChange):
    """ A new token was registered with the payment network. """

    def __init__(
            self,
            transaction_hash: TransactionHash,
            payment_network_identifier: PaymentNetworkID,
            token_network: TokenNetworkState,
            block_number: BlockNumber,
            block_hash: BlockHash,
    ):
        if not isinstance(token_network, TokenNetworkState):
            raise ValueError('token_network must be a TokenNetworkState instance')

        super().__init__(transaction_hash, block_number, block_hash)

        self.payment_network_identifier = payment_network_identifier
        self.token_network = token_network

    def __repr__(self):
        return (
            '<ContractReceiveNewTokenNetwork payment_network:{} network:{} block:{}>'.format(
                pex(self.payment_network_identifier),
                self.token_network,
                self.block_number,
            )
        )

    def __eq__(self, other):
        return (
            isinstance(other, ContractReceiveNewTokenNetwork) and
            self.payment_network_identifier == other.payment_network_identifier and
            self.token_network == other.token_network and
            super().__eq__(other)
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'transaction_hash': serialize_bytes(self.transaction_hash),
            'payment_network_identifier': to_checksum_address(self.payment_network_identifier),
            'token_network': self.token_network,
            'block_number': str(self.block_number),
            'block_hash': serialize_bytes(self.block_hash),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ContractReceiveNewTokenNetwork':
        return cls(
            transaction_hash=deserialize_bytes(data['transaction_hash']),
            payment_network_identifier=to_canonical_address(data['payment_network_identifier']),
            token_network=data['token_network'],
            block_number=BlockNumber(int(data['block_number'])),
            block_hash=BlockHash(deserialize_bytes(data['block_hash'])),
        )


class ContractReceiveSecretReveal(ContractReceiveStateChange):
    """ A new secret was registered with the SecretRegistry contract. """

    def __init__(
            self,
            transaction_hash: TransactionHash,
            secret_registry_address: SecretRegistryAddress,
            secrethash: SecretHash,
            secret: Secret,
            block_number: BlockNumber,
            block_hash: BlockHash,
    ):
        if not isinstance(secret_registry_address, T_SecretRegistryAddress):
            raise ValueError('secret_registry_address must be of type SecretRegistryAddress')
        if not isinstance(secrethash, T_SecretHash):
            raise ValueError('secrethash must be of type SecretHash')
        if not isinstance(secret, T_Secret):
            raise ValueError('secret must be of type Secret')

        super().__init__(transaction_hash, block_number, block_hash)

        self.secret_registry_address = secret_registry_address
        self.secrethash = secrethash
        self.secret = secret

    def __repr__(self):
        return (
            '<ContractReceiveSecretReveal'
            ' secret_registry:{} secrethash:{} secret:{} block:{}'
            '>'
        ).format(
            pex(self.secret_registry_address),
            pex(self.secrethash),
            pex(self.secret),
            self.block_number,
        )

    def __eq__(self, other):
        return (
            isinstance(other, ContractReceiveSecretReveal) and
            self.secret_registry_address == other.secret_registry_address and
            self.secrethash == other.secrethash and
            self.secret == other.secret and
            super().__eq__(other)
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'transaction_hash': serialize_bytes(self.transaction_hash),
            'secret_registry_address': to_checksum_address(self.secret_registry_address),
            'secrethash': serialize_bytes(self.secrethash),
            'secret': serialize_bytes(self.secret),
            'block_number': str(self.block_number),
            'block_hash': serialize_bytes(self.block_hash),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ContractReceiveSecretReveal':
        return cls(
            transaction_hash=deserialize_bytes(data['transaction_hash']),
            secret_registry_address=to_canonical_address(data['secret_registry_address']),
            secrethash=deserialize_bytes(data['secrethash']),
            secret=deserialize_bytes(data['secret']),
            block_number=BlockNumber(int(data['block_number'])),
            block_hash=BlockHash(deserialize_bytes(data['block_hash'])),
        )


class ContractReceiveChannelBatchUnlock(ContractReceiveStateChange):
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
            transaction_hash: TransactionHash,
            token_network_identifier: TokenNetworkID,
            participant: Address,
            partner: Address,
            locksroot: Locksroot,
            unlocked_amount: TokenAmount,
            returned_tokens: TokenAmount,
            block_number: BlockNumber,
            block_hash: BlockHash,
    ):

        if not isinstance(token_network_identifier, T_TokenNetworkID):
            raise ValueError('token_network_identifier must be of type TokenNtetworkIdentifier')

        if not isinstance(participant, T_Address):
            raise ValueError('participant must be of type address')

        if not isinstance(partner, T_Address):
            raise ValueError('partner must be of type address')

        super().__init__(transaction_hash, block_number, block_hash)

        self.token_network_identifier = token_network_identifier
        self.participant = participant
        self.partner = partner
        self.locksroot = locksroot
        self.unlocked_amount = unlocked_amount
        self.returned_tokens = returned_tokens

    def __repr__(self):
        return (
            '<ContractReceiveChannelBatchUnlock '
            ' token_network:{} participant:{} partner:{}'
            ' locksroot:{} unlocked:{} returned:{} block:{}'
            '>'
        ).format(
            self.token_network_identifier,
            self.participant,
            self.partner,
            self.locksroot,
            self.unlocked_amount,
            self.returned_tokens,
            self.block_number,
        )

    def __eq__(self, other):
        return (
            isinstance(other, ContractReceiveChannelBatchUnlock) and
            self.token_network_identifier == other.token_network_identifier and
            self.participant == other.participant and
            self.partner == other.partner and
            self.locksroot == other.locksroot and
            self.unlocked_amount == other.unlocked_amount and
            self.returned_tokens == other.returned_tokens and
            super().__eq__(other)
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'transaction_hash': serialize_bytes(self.transaction_hash),
            'token_network_identifier': to_checksum_address(self.token_network_identifier),
            'participant': to_checksum_address(self.participant),
            'partner': to_checksum_address(self.partner),
            'locksroot': serialize_bytes(self.locksroot),
            'unlocked_amount': str(self.unlocked_amount),
            'returned_tokens': str(self.returned_tokens),
            'block_number': str(self.block_number),
            'block_hash': serialize_bytes(self.block_hash),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ContractReceiveChannelBatchUnlock':
        return cls(
            transaction_hash=deserialize_bytes(data['transaction_hash']),
            token_network_identifier=to_canonical_address(data['token_network_identifier']),
            participant=to_canonical_address(data['participant']),
            partner=to_canonical_address(data['partner']),
            locksroot=deserialize_bytes(data['locksroot']),
            unlocked_amount=int(data['unlocked_amount']),
            returned_tokens=int(data['returned_tokens']),
            block_number=BlockNumber(int(data['block_number'])),
            block_hash=BlockHash(deserialize_bytes(data['block_hash'])),
        )


class ContractReceiveRouteNew(ContractReceiveStateChange):
    """ New channel was created and this node is NOT a participant. """

    def __init__(
            self,
            transaction_hash: TransactionHash,
            token_network_identifier: TokenNetworkID,
            channel_identifier: ChannelID,
            participant1: Address,
            participant2: Address,
            block_number: BlockNumber,
            block_hash: BlockHash,
    ):

        if not isinstance(participant1, T_Address):
            raise ValueError('participant1 must be of type address')

        if not isinstance(participant2, T_Address):
            raise ValueError('participant2 must be of type address')

        super().__init__(transaction_hash, block_number, block_hash)

        self.token_network_identifier = token_network_identifier
        self.channel_identifier = channel_identifier
        self.participant1 = participant1
        self.participant2 = participant2

    def __repr__(self):
        return (
            '<ContractReceiveRouteNew'
            ' token_network:{} id:{} node1:{}'
            ' node2:{} block:{}>'
        ).format(
            pex(self.token_network_identifier),
            self.channel_identifier,
            pex(self.participant1),
            pex(self.participant2),
            self.block_number,
        )

    def __eq__(self, other):
        return (
            isinstance(other, ContractReceiveRouteNew) and
            self.token_network_identifier == other.token_network_identifier and
            self.channel_identifier == other.channel_identifier and
            self.participant1 == other.participant1 and
            self.participant2 == other.participant2 and
            super().__eq__(other)
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'transaction_hash': serialize_bytes(self.transaction_hash),
            'token_network_identifier': to_checksum_address(self.token_network_identifier),
            'channel_identifier': str(self.channel_identifier),
            'participant1': to_checksum_address(self.participant1),
            'participant2': to_checksum_address(self.participant2),
            'block_number': str(self.block_number),
            'block_hash': serialize_bytes(self.block_hash),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ContractReceiveRouteNew':
        return cls(
            transaction_hash=deserialize_bytes(data['transaction_hash']),
            token_network_identifier=to_canonical_address(data['token_network_identifier']),
            channel_identifier=ChannelID(int(data['channel_identifier'])),
            participant1=to_canonical_address(data['participant1']),
            participant2=to_canonical_address(data['participant2']),
            block_number=BlockNumber(int(data['block_number'])),
            block_hash=BlockHash(deserialize_bytes(data['block_hash'])),
        )


class ContractReceiveRouteClosed(ContractReceiveStateChange):
    """ A channel was closed and this node is NOT a participant. """

    def __init__(
            self,
            transaction_hash: TransactionHash,
            token_network_identifier: TokenNetworkID,
            channel_identifier: ChannelID,
            block_number: BlockNumber,
            block_hash: BlockHash,
    ):
        super().__init__(transaction_hash, block_number, block_hash)

        self.token_network_identifier = token_network_identifier
        self.channel_identifier = channel_identifier

    def __repr__(self):
        return '<ContractReceiveRouteClosed token_network:{} id:{} block:{}>'.format(
            pex(self.token_network_identifier),
            self.channel_identifier,
            self.block_number,
        )

    def __eq__(self, other):
        return (
            isinstance(other, ContractReceiveRouteClosed) and
            self.token_network_identifier == other.token_network_identifier and
            self.channel_identifier == other.channel_identifier and
            super().__eq__(other)
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'transaction_hash': serialize_bytes(self.transaction_hash),
            'token_network_identifier': to_checksum_address(self.token_network_identifier),
            'channel_identifier': str(self.channel_identifier),
            'block_number': str(self.block_number),
            'block_hash': serialize_bytes(self.block_hash),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ContractReceiveRouteClosed':
        return cls(
            transaction_hash=deserialize_bytes(data['transaction_hash']),
            token_network_identifier=to_canonical_address(data['token_network_identifier']),
            channel_identifier=ChannelID(int(data['channel_identifier'])),
            block_number=BlockNumber(int(data['block_number'])),
            block_hash=BlockHash(deserialize_bytes(data['block_hash'])),
        )


class ContractReceiveUpdateTransfer(ContractReceiveStateChange):
    def __init__(
            self,
            transaction_hash: TransactionHash,
            token_network_identifier: TokenNetworkID,
            channel_identifier: ChannelID,
            nonce: Nonce,
            block_number: BlockNumber,
            block_hash: BlockHash,
    ):
        super().__init__(transaction_hash, block_number, block_hash)

        self.token_network_identifier = token_network_identifier
        self.channel_identifier = channel_identifier
        self.nonce = nonce

    def __repr__(self):
        return (
            f'<ContractReceiveUpdateTransfer nonce:{self.nonce} block:{self.block_number}>'
        )

    def __eq__(self, other):
        return (
            isinstance(other, ContractReceiveUpdateTransfer) and
            self.token_network_identifier == other.token_network_identifier and
            self.channel_identifier == other.channel_identifier and
            self.nonce == other.nonce and
            super().__eq__(other)
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'transaction_hash': serialize_bytes(self.transaction_hash),
            'token_network_identifier': to_checksum_address(self.token_network_identifier),
            'channel_identifier': str(self.channel_identifier),
            'nonce': str(self.nonce),
            'block_number': str(self.block_number),
            'block_hash': serialize_bytes(self.block_hash),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ContractReceiveUpdateTransfer':
        return cls(
            transaction_hash=deserialize_bytes(data['transaction_hash']),
            token_network_identifier=to_canonical_address(data['token_network_identifier']),
            channel_identifier=ChannelID(int(data['channel_identifier'])),
            nonce=int(data['nonce']),
            block_number=BlockNumber(int(data['block_number'])),
            block_hash=BlockHash(deserialize_bytes(data['block_hash'])),
        )


class ReceiveUnlock(BalanceProofStateChange):
    def __init__(
            self,
            message_identifier: MessageID,
            secret: Secret,
            balance_proof: BalanceProofSignedState,
    ):
        if not isinstance(balance_proof, BalanceProofSignedState):
            raise ValueError('balance_proof must be an instance of BalanceProofSignedState')

        super().__init__(balance_proof)

        secrethash: SecretHash = SecretHash(sha3(secret))

        self.message_identifier = message_identifier
        self.secret = secret
        self.secrethash = secrethash

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
            super().__eq__(other)
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'message_identifier': str(self.message_identifier),
            'secret': serialize_bytes(self.secret),
            'balance_proof': self.balance_proof,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ReceiveUnlock':
        return cls(
            message_identifier=int(data['message_identifier']),
            secret=deserialize_bytes(data['secret']),
            balance_proof=data['balance_proof'],
        )


class ReceiveDelivered(AuthenticatedSenderStateChange):
    def __init__(self, sender: Address, message_identifier: MessageID):
        super().__init__(sender)

        self.message_identifier = message_identifier

    def __repr__(self):
        return '<ReceiveDelivered msgid:{} sender:{}>'.format(
            self.message_identifier,
            pex(self.sender),
        )

    def __eq__(self, other):
        return (
            isinstance(other, ReceiveDelivered) and
            self.message_identifier == other.message_identifier and
            super().__eq__(other)
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'sender': to_checksum_address(self.sender),
            'message_identifier': str(self.message_identifier),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ReceiveDelivered':
        return cls(
            sender=to_canonical_address(data['sender']),
            message_identifier=int(data['message_identifier']),
        )


class ReceiveProcessed(AuthenticatedSenderStateChange):
    def __init__(self, sender: Address, message_identifier: MessageID):
        super().__init__(sender)
        self.message_identifier = message_identifier

    def __repr__(self):
        return '<ReceiveProcessed msgid:{} sender:{}>'.format(
            self.message_identifier,
            pex(self.sender),
        )

    def __eq__(self, other):
        return (
            isinstance(other, ReceiveProcessed) and
            self.message_identifier == other.message_identifier and
            super().__eq__(other)
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'sender': to_checksum_address(self.sender),
            'message_identifier': str(self.message_identifier),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ReceiveProcessed':
        return cls(
            sender=to_canonical_address(data['sender']),
            message_identifier=int(data['message_identifier']),
        )
