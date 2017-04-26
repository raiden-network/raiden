# -*- coding: utf-8 -*-
"""
A pure python implementation of a contract responsable to open a channel.
"""
from ethereum import slogging

from raiden.utils import sha3, pex
from raiden.mtree import check_proof
from raiden.messages import (
    MediatedTransfer,
    RefundTransfer,
    DirectTransfer,
    Lock,
)
from raiden.encoding.messages import (
    DIRECTTRANSFER,
    MEDIATEDTRANSFER,
    REFUNDTRANSFER,
)

log = slogging.getLogger(__name__)  # pylint: disable=invalid-name

# Blockspam attack mitigation:
#     - Oracles, certifying, that previous blocks were full.
#     - Direct access to gasused of previous blocks.
#     - Heuristic, no settlements in the previous blocks.
# Todos:
#     Compatible Token/Token/Coin Contract
#     Channel Opening sequence
#     Channel Fees (i.e. Accounts w/ higher reputation could charge a fee/deposit).
#     use channel.opened to collect reputation of an account (long lasting channels == good)


STATE_UNKNOW = 0
STATE_PARTICIPANT = 1
STATE_THIRDPARTY = 2  # also used when close() is called


def tuple32(data):
    """ A helper to split a concatenated merkle proof into its individual
    elements.
    """
    start = 0
    end = 8

    result = []
    while end <= len(data):
        pair = (data[start:end - 4], data[end - 4:end])
        result.append(pair)
        start = end
        end += 8

    return result


def decode_transfer(transfer_encoded):
    if transfer_encoded[0] == DIRECTTRANSFER:
        return DirectTransfer.decode(transfer_encoded)
    elif transfer_encoded[0] == MEDIATEDTRANSFER:
        return MediatedTransfer.decode(transfer_encoded)
    elif transfer_encoded[0] == REFUNDTRANSFER:
        return RefundTransfer.decode(transfer_encoded)
    else:
        raise ValueError('invalid transfer type {}'.format(type(transfer_encoded[0])))


class Participant(object):
    # pylint: disable=too-few-public-methods

    def __init__(self):
        self.deposit = 0
        """ int: Amount of token deposited by the participant. """

        self.netted = 0
        """ int: Amount of token netted after the channel is settled. """

        # Used to track the latest know transfer from the partner
        self.transfer = None
        """ The transfer exchanged by the nodes used for settling. """

        # Used to track if the node who called close lied
        self.transfer_from_self = None
        """ The transfer informed by the node itself when calling close, used to detect frauds. """

        self.unlocked = []
        """ A list of (Lock, merkle_proof, secret). """

        self.has_deposited = False
        """ Flag indicating if the participant has called the deposit(). """

        # Allow thrid-parties to update `transfer`
        self.state = STATE_UNKNOW
        """ From who the contract received this transfer. """


class NettingChannelContract(object):
    """ Contract that allows users to perform fast off-chain transactions.

    The netting contract allows two parties to engage in off-chain token
    transfers without trust among them, with the functionality of detecting
    frauds, penalise the wrongdoers, and to participate in an off-chain network
    for fast and cheap transactions.

    Operation
    ---------

    These transactions are done by external clients without interaction with
    the contract, the contract's role is only to secure the token and create
    the mechanism that allows settlement of conflicts.

    The token transfers are done through the exchange of signed messages among
    the participants, each message works as a proof of the transfer made from a
    given participant. These messages are composed of:

        - The message signature, proving authenticity of the message.
        - The increasing counter `nonce`, identifying the order of the
        transfers.
        - The partner's total amount transferred, determining each balance.
        - The merkle root of the locked transfers tree.
        - Possibly a `Lock` structure describing a new locked transfer.

    Since the contract does not mediate these off-chain transfers, it is the
    interest of each participant to reject invalid messages, these are the
    points of concern:

        - Signatures need to be from a key recognized by the contract.
        - `Nonce`s are unique and increasing to identify the transfer order.
        - Negative transfers are invalid, and the transferred amount is always
        increasing.
        - Maintain a correct merkle root with all non-expired locked transfer.
        - A valid timeout for `Lock`ed transfers.

    Transfers
    ---------

    There are two kinds of transfers that are recognized by the contract, a
    transfer initiated by a channel participant to the other participant, called
    a direct transfer, or a mediated transfer involving multiple channels, used
    for cooperatively transfer tokens for nodes without a direct channel.

    Multiple transfers are expected to occur from the opening of a channel
    onwards. The `nonce` field is used by this contract to compare transfers
    and define which is the latest. It's the responsability of each participant to
    reject messages with an decreasing or equal `nonce`, ensuring that this
    value is increasing.

    Direct Transfer
    ===============

    Direct transfers require only the exchange of a single signed message
    containing the current `nonce`, with an up-to-date amount transferred and
    merkle proof.

    Mediated Transfer
    =================

    Direct transfer depend on the existence of direct channels among the
    participants, since direct channels are expected to be the exception and
    not the rule a different mechanism is required for indirect transfers, this
    is done by exploiting existing channels to mediate a token transfer.

    The path discovery required to find which channels will be used to mediate
    the transfer isn't part of this contract, only the means to protect the
    individual tokens.

    Mediated transfers require the participation of one or more intermediary
    nodes, these intermediaries compose a path from the initiator to the
    target. The path of length `n` has its transfer started by the initiator
    `1`, with each intermediary `i` mediating a transfer from `i-1` to `i+1`
    until the the target node `n` is reached. This contract has the required
    mechanisms to protect the individual node's tokens, the contract allows any
    `i` to safely transfer its token to `i+1` with the guarantee that it will
    have the transfer from `i-1` done.

    Penalization
    ------------

    An evil participant can reduce its spending in two ways:

        1. Tampered messages: Send a transfer signed with a lower
        `amount_transferred`.
        2. Older messages: Send a valid but older message, which has a lower
        `amount_transferred`.

    To detect these tatics:

        1. A single message with a equal or lower nonce, with a larger amount.
        2. A single message with a higher nonce.

    Note:
        Implementation in pure python that reproduces the expected behavior of
        the blockchain NettingContract. This implementation is useful for
        testing.
    """

    def __init__(self, token_address, netcontract_address, address_A,
                 address_B, settle_timeout):
        log.debug(
            'creating nettingchannelcontract',
            a=pex(address_A),
            b=pex(address_B),
        )

        self.token_address = token_address
        self.netcontract_address = netcontract_address
        self.participants = {
            address_A: Participant(),
            address_B: Participant(),
        }

        # opened, settled, and closed default to 0 as it's the value used in
        # the contract

        self.opened = 0
        """ Block number when deposit() was first called. """

        self.settled = 0
        """ Block number when settle was sucessfully called. """

        self.closed = 0
        """ Block number when close() was first called (might be zero in testing scenarios). """

        self.closer = None
        """ The participant that called the close method. """

        self.settle_timeout = settle_timeout
        """ Number of blocks that we are required to wait before allowing settlement. """
        # The settle_timeout could be either fixed or variable:
        # - Fixed/Absolute block number. A maximum life time is choosen for the
        # contract, the contract can be settled before but not after. The
        # application must not accept any locked transfers that could expire after
        # `settle_timeout` blocks, at the cost of being susceptible to timming
        # attacks.
        # - Relative block number:
        #   - With a fixed waiting time. The application must not accept
        #   any locked transfers that could expire more than `settle_timeout` blocks,
        #   at the cost of being susceptible to timming attacks.
        #   - With a variable waiting time. The `settle_timeout` depends on the locked
        #   transfer and a list of all the lock's timeouts need to be sent to the
        #   contract.
        # This implementation's settle_timeout is a "fixed waiting time"

    @property
    def isopen(self):
        """ The contract is open after both participants have deposited, and if
        it has not being closed.

        Returns:
            bool: True if the contract is open, False otherwise
        """
        # 0 is used for uninitialized values
        if self.closed is not 0:
            return False

        # allow single funded channels
        return any(
            state.has_deposited
            for state in self.participants.values()
        )

    def deposit(self, address, amount, block_number):
        """ Method for `address` to make a deposit of `amount` token. """

        if address not in self.participants:
            msg = 'The address {address} is not a participant of this contract.'.format(
                address=address,
            )

            log.debug('Unknow address.', address=address, participants=self.participants)

            raise ValueError(msg)

        if amount < 0:
            raise ValueError('Amount cannot be negative.')

        participant = self.participants[address]
        participant.has_deposited = True
        participant.deposit += amount

        if self.isopen and self.opened is 0:
            # track the block were the contract was openned
            self.opened = block_number

    def partner(self, address):
        """ Returns the address of the other participant in the contract. """

        if address not in self.participants:
            msg = 'The address {address} is not a participant of this contract'.format(
                address=pex(address),
            )
            raise ValueError(msg)

        all_participants = list(self.participants.keys())
        all_participants.remove(address)
        return all_participants[0]

    def _get_transferred_amount(self, transfer1, transfer2):
        amount1, amount2 = 0.0, 0.0

        if transfer1:
            amount1 = transfer1.transferred_amount

        if transfer2:
            amount2 = transfer2.transferred_amount

        return amount1, amount2

    def close(self, ctx, first_encoded):
        """" Request the closing of the channel. Can be called once by one of
        the participants. Lock period starts counting once this method is
        called.

        Args:
            ctx:
                Block chain state used for mocking.

            first_encoded (bin):
                One of the last sent transfers, can be a transfer from either
                side of the cannel. May be None.

            second_encoded (Optional[bin]):
                The last sent transfer from the other end of the channel, in
                respect to `first_encoded`. May be None.
        """

        if self.settled is not 0:
            raise RuntimeError('Contract is settled.')

        if self.closed is not 0:
            raise RuntimeError('Contract is closing.')

        # Close cannot accept a message that is not from a participant,
        # otherwise a third-party could close a channel that both participants
        # want open
        if ctx['msg.sender'] not in self.participants:
            raise ValueError('Caller is not a participant')

        # may be None, a node is not required to make a transfer
        transfer = decode_transfer(first_encoded)

        closer_state = self.participants[ctx['msg.sender']]
        partner_state = self.participants[self.partner(ctx['msg.sender'])]

        closer_state.state = STATE_PARTICIPANT

        partner_state.transfer = transfer
        partner_state.state = STATE_THIRDPARTY

        self.closed = ctx['block_number']
        self.closer = closer_state

        amount1, amount2 = self._get_transferred_amount(None, transfer)
        allowance = closer_state.deposit + partner_state.deposit
        difference = abs(amount1 - amount2)

        if difference > allowance:
            # TODO: penalize closer
            raise Exception('Invalid netted value')

    def update_transfer(self, ctx, transfer_encoded):
        """" Used by the partner to inform the latest known transfer.

        Args:
            ctx:
                Block chain state used for mocking.

            transfer_encoded (bin):
                Last sent transfers received by the partner (can be sent by a third party).
        """
        if self.settled is not 0:
            raise RuntimeError('Contract is settled.')

        if self.closed is 0:
            raise RuntimeError('Contract is open.')

        # third-parties need to call a separate method that receives:
        # - a fee amount
        # - a signature of the transfer and fee amount, proving that the
        #   participant required the third-party services
        if ctx['msg.sender'] not in self.participants:
            raise ValueError('Caller is not participant.')

        transfer = decode_transfer(transfer_encoded)

        if not transfer.sender == self.closer.transfer_from_self.sender:
            raise ValueError('Invalid transfer address')

        state = self.participants[transfer.sender]

        tampered = False
        if transfer and state.transfer:
            # A message is tampered if `value_transferred` was raised without raising
            # the `nonce`.
            # Only need to compare against transfer_from_self because that is
            # the only variable in uniquiely controlled by the closer.
            tampered = (
                (
                    state.transfer_from_self.nonce < transfer.nonce and
                    state.transfer_from_self.value_transferred > transfer.value_transferred
                ) or (
                    state.transfer_from_self.nonce == transfer.nonce and
                    state.transfer_from_self.value_transferred != transfer.value_transferred
                )
            )

        if tampered:
            raise RuntimeError('Tampered message.')  # TODO: penalize

        outdated = (
            (state.transfer_from_self is None and transfer is not None) or
            state.transfer_from_self.nonce < transfer.nonce
        )

        if outdated:
            raise RuntimeError('Closer informed an outdated transfer.')  # TODO: penalize

        state.transfer = transfer
        state.state = STATE_PARTICIPANT

        # elif state.state == STATE_THIRDPARTY and state.transfer.nonce < transfer.nonce:
        #     state.transfer = transfer

    def withdraw(self, ctx, locked_encoded, merkleproof_encoded, secret):
        if self.settled is not 0:
            raise RuntimeError('Contract is settled.')

        if self.closed is 0:
            raise RuntimeError('Contract is open.')

        if ctx['msg.sender'] not in self.participants:
            raise ValueError('Unknow address.')

        partner = self.partner(ctx['msg.sender'])
        state = self.participants[partner]
        transfer = state.transfer

        # if partner haven't made a single transfer
        if transfer is None:
            return

        merkle_proof = tuple32(merkleproof_encoded)
        lock = Lock.from_bytes(locked_encoded)

        hashlock = lock.hashlock
        if hashlock != sha3(secret):
            raise ValueError('Invalid secret')

        is_valid_proof = check_proof(
            merkle_proof,
            transfer.locksroot,
            sha3(lock.as_bytes),
        )

        if not is_valid_proof:
            raise ValueError('Invalid merkle proof')

        transfer.append(lock)

    def _get_netted(self, our_state, partner_state):
        # do not use floats
        our_transferred_amount = 0
        partner_transferred_amount = 0

        if our_state.transfer:
            our_transferred_amount = our_state.transfer.transferred_amount

        if partner_state.transfer:
            partner_transferred_amount = partner_state.transfer.transferred_amount

        return our_state.deposit + partner_transferred_amount - our_transferred_amount

    def settle(self, ctx):
        assert self.settled is 0
        assert self.closed is not 0
        assert self.closed + self.settle_timeout <= ctx['block_number']

        for address, state in self.participants.items():
            other = self.participants[self.partner(address)]
            state.netted = self._get_netted(state, other)

        # add locked
        for address, state in self.participants.items():
            other = self.participants[self.partner(address)]

            for locked in state.unlocked:
                state.netted += locked.amount
                other.netted -= locked.amount

        total_netted = sum(state.netted for state in self.participants.values())
        total_deposit = sum(state.deposit for state in self.participants.values())

        assert total_netted <= total_deposit

        self.settled = ctx['block_number']
