# -*- coding: utf8 -*-
"""
A pure python implementation of a contract responsable to open a channel.
"""
from ethereum import slogging

from raiden.utils import sha3, pex
from raiden.mtree import check_proof
from raiden.messages import MediatedTransfer, CancelTransfer, DirectTransfer, Lock, LockedTransfer
from raiden.encoding.messages import (
    DIRECTTRANSFER, LOCKEDTRANSFER, MEDIATEDTRANSFER, CANCELTRANSFER,
)
from raiden.encoding.signing import c_ecdsa_recover_compact, address_from_key

log = slogging.getLogger(__name__)  # pylint: disable=invalid-name

# Blockspam attack mitigation:
#     - Oracles, certifying, that previous blocks were full.
#     - Direct access to gasused of previous blocks.
#     - Heuristic, no settlements in the previous blocks.
# Todos:
#     Compatible Asset/Token/Coin Contract
#     Channel Opening sequence
#     Channel Fees (i.e. Accounts w/ higher reputation could charge a fee/deposit).
#     use channel.opened to collect reputation of an account (long lasting channels == good)


STATE_UNKNOW = 0
STATE_PARTICIPANT = 1
STATE_THIRDPARTY = 2  # also used when close() is called


def tuple32(data):
    """ A helper to split a concatenated merkle proof into it's individual
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
    elif transfer_encoded[0] == CANCELTRANSFER:
        return CancelTransfer.decode(transfer_encoded)
    # convinience for testing only (LockedTransfer are not exchanged between nodes)
    elif transfer_encoded[0] == LOCKEDTRANSFER:
        return LockedTransfer.decode(transfer_encoded)
    else:
        raise ValueError('invalid transfer type {}'.format(type(transfer_encoded[0])))


class Participant(object):
    # pylint: disable=too-few-public-methods

    def __init__(self):
        self.deposit = 0
        """ Amount of asset deposited by the participant. """

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
    """ Allows users to perform fast off-chain transactions.

    Two parties can engage in fast and cheap transfers without trusting each
    other. Each party only needs to rely on the contract and it's correct
    behavior.

    Operation
    ---------

    These transactions are done by external clients without interaction with
    the contract, the contract's role is only to secure the asset and create
    the mechanism that allows settlement of conflicts.

    The asset transfers are done through the exchange of signed messages among
    the participants, each message works as a proof of the transfer made from a
    given participant. These messages are composed of:

        - The message signature, proving authenticity of the message.
        - The increasing counter `nonce`, identifying the order of the
        transfers.
        - The partner's total amount transfered, determining each balance.
        - The merkle root of the locked transfers tree.
        - Possibly a `Lock` structure describing a new locked transfer.

    Since the contract does not mediate these off-chain transfers, it is the
    interest of each participant to reject invalid messages, these are the
    points of concern:

        - Signatures need to be from a key recognized by the contract.
        - `Nonce`s are unique and increasing to identify the transfer order.
        - Negative transfers are invalid, and the transfered amount is always
        increasing.
        - Maintain a correct merkle root with all non-expired locked transfer.
        - A valid timeout for `Lock`ed transfers.

    Transfers
    ---------

    There are two kinds of transfers that are recognized by the contract, a
    transfer initiate by a channel participant to the other participant, called
    a direct transfer, or a mediated transfer involving multiple channels, used
    for cooperatively transfer assets for nodes without a direct channel.

    Multiple transfers are expected to occur from the opening of a channel
    onwards. The `nonce` field is used by this contract to compare transfers
    and define which is the latest, it's responsability of each participant to
    reject messages with an decreasing or equal `nonce`, ensuring that this
    value is increasing.

    Direct Transfer
    ===============

    Direct transfers require only the exchange of a single signed message
    containing the current `nonce`, with an up-to-date amount transfered and
    merkle proof.

    Mediated Transfer
    =================

    Direct transfer depend on the existence of direct channels among the
    participants, since direct channels are expected to be the exception and
    not the rule a different mechanism is required for indirect transfers, this
    is done by exploiting existing channels to mediate an asset transfer.

    The path discovery required to find which channels will be used to mediate
    the transfer isn't part of this contract, only the means to protect the
    individual assets.

    Mediated transfers require the participation of one or more intermediary
    nodes, these intermediaries compose a path from the initiator to the
    target. The path of length `n` has it's transfer started by the initiator
    `1`, with each intermediary `i` mediating a transfer from `i-1` to `i+1`
    until the the target node `n` is reached. This contract has the required
    mechanisms to protect the individual node's assets, the contract allows any
    `i` to safely transfer it's asset to `i+1` with the guarantee that it will
    have the transfer from `i-1` done.

    Penalization
    ------------

    An evil participant can reduce it's spending in two ways:

        1. Tampered messages: Send a transfer signed with a lower
        `amount_transfered`.
        2. Older messages: Send a valid but older message, which has a lower
        `amount_transfered`.

    To detect these tatics:

        1. A single message with a equal or lower nonce, with a larger amount.
        2. A single message with a higher nonce.
    """

    locked_time = 20
    """ Number of blocks that we are required to wait before allowing settlement. """
    # - Absolute block number. A maximum life time is choosen for the contract,
    # the contract can be settled before but not after. The application must
    # not accept any transfer that expire after the given block.
    # - Relative block number:
    #   - With a fixed waiting time. The application must not accept
    #   any locked transfers that could expire more than `locked_time` blocks,
    #   at the cost of being susceptible to timming attacks.
    #   - With a variable waiting time. The `locked_time` depends on the locked
    #   transfer and a list of all the lock's timeouts need to be sent to the
    #   contract.
    #
    # This implementation's locked_time is a "fixed waiting time"

    def __init__(self, asset_address, netcontract_address, address_A, address_B):
        log.debug(
            'creating nettingchannelcontract',
            a=pex(address_A),
            b=pex(address_B),
        )

        self.asset_address = asset_address
        self.netcontract_address = netcontract_address
        self.participants = {
            address_A: Participant(),
            address_B: Participant(),
        }

        self.opened = None
        """ Block number when deposit() was first called. """

        self.settled = False
        """ Block number when settle was sucessfully called. """

        self.closed = None
        """ Block number when close() was first called (might be zero in testing scenarios) """

        self.closer = None
        """ The participant that called the close method. """

    @property
    def isopen(self):
        """ The contract is open after both participants have deposited, and if
        it has not being closed.

        Returns:
            bool: True if the contract is open, False otherwise
        """
        # during testing closed can be 0 and it is falsy
        if self.closed is not None:
            return False

        return all(
            state.has_deposited
            for state in self.participants.values()
        )

    def deposit(self, address, amount, block_number):
        """ Address maked a deposit of `amount` coins. """

        if address not in self.participants:
            msg = 'The address {address} is not a participant of this contract'.format(
                address=address,
            )

            log.debug('unknow address', address=address, participants=self.participants)

            raise ValueError(msg)

        if amount < 0:
            raise ValueError('amount cannot be negative')

        participant = self.participants[address]
        participant.has_deposited = True
        participant.deposit += amount

        if self.isopen and self.opened is None:
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

    def _decode(self, first_encoded, second_encoded):
        transfer1 = None
        transfer2 = None

        if first_encoded:
            transfer1 = decode_transfer(first_encoded)

            if transfer1.sender not in self.participants:
                raise ValueError('Invalid transfer address')

        if second_encoded:
            transfer2 = decode_transfer(second_encoded)

            if transfer2.sender not in self.participants:
                raise ValueError('Invalid transfer address')

        if first_encoded and second_encoded and transfer1.sender == transfer2.sender:
            raise ValueError('Both transfer are for the same address')

        return transfer1, transfer2

    def close(self, ctx, first_encoded, second_encoded):
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

        if self.settled:
            raise RuntimeError('contract is settled.')

        if self.closed:
            raise RuntimeError('contract is closing.')

        # Close cannot accept a message that is not from a participant,
        # otherwise a third-party could close a channel that both participants
        # want open
        if ctx['msg.sender'] not in self.participants:
            raise ValueError('Caller is not a participant')

        closer_state = self.participants[ctx['msg.sender']]
        partner_state = self.participants[self.partner(ctx['msg.sender'])]

        # may be None, a node is not required to make a transfer
        transfer1, transfer2 = self._decode(first_encoded, second_encoded)

        # The order is undetermined
        if transfer1.sender == ctx['msg.sender']:
            closer = transfer1
            partner = transfer2
        else:
            closer = transfer2
            partner = transfer1

        closer_state.transfer = closer
        closer_state.transfer_from_self = closer
        closer_state.state = STATE_PARTICIPANT

        partner_state.transfer = partner
        partner_state.state = STATE_THIRDPARTY

        self.closed = ctx['block_number']
        self.closer = closer_state

    def update_transfer(self, ctx, transfer_encoded, signature):
        """" Used by the partner to inform the latest know transfer.

        Args:
            ctx:
                Block chain state used for mocking.

            transfer_encoded (bin):
                Last sent transfers received by the partner (can be sent by a third party).

            signature (bin):
                The signature for `sha3(transfer_encoded)`, allows third
                parties to send message on behalf of a participant.
        """
        if self.settled:
            raise RuntimeError('Contract is settled.')

        if not self.closed:
            raise RuntimeError('Contract is open.')

        # required to prove authenticity from third-parties.
        messages_hash = sha3(first_encoded + second_encoded)
        publickey = c_ecdsa_recover_compact(messages_hash, signature)
        address = address_from_key(publickey)

        if address not in self.participants:
            raise ValueError('Invalid address.')

        transfer = decode_transfer(transfer_encoded)

        if not transfer.sender == self.closer.transfer_from_self.sender:
            raise ValueError('Invalid transfer address')

        state = self.participants[transfer.sender]

        tampered = False
        if transfer and state.transfer:
            # A message is tampered if `value_transfered` was raised without raising
            # the `nonce`.
            # Only need to compare against transfer_from_self because that is
            # the only variable in uniquiely controlled by the closer.
            tampered = (
                (
                    state.transfer_from_self.nonce < transfer.nonce and
                    state.transfer_from_self.value_transfered > transfer.value_transfered
                ) or (
                    state.transfer_from_self.nonce == transfer.nonce and
                    state.transfer_from_self.value_transfered != transfer.value_transfered
                )
            )

        if tampered:
            raise RuntimeError('Tampered message.')  # TODO: penalize

        outdated = (
            (state.transfer_from_self is None and transfer is not None)
            or state.transfer_from_self.nonce < transfer.nonce
        )

        if outdated:
            raise RuntimeError('Closer informed an outdated transfer.')  # TODO: penalize

        if ctx['msg.sender'] == address:
            state.transfer = transfer
            state.state = STATE_PARTICIPANT
        elif state.state == STATE_THIRDPARTY and state.transfer.nonce < transfer.nonce:
            state.transfer = transfer

    def unlock(self, ctx, locked_encoded, merkleproof_encoded, secret):
        if self.settled:
            raise RuntimeError('Contract is settled.')

        if not self.closed:
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
            sha3(transfer.lock.as_bytes),
        )

        if not is_valid_proof:
            raise ValueError('Invalid merkle proof')

        transfer.append(lock)

    def settle(self, ctx):
        assert not self.settled
        assert self.closed is not None  # closed can be 0 during testing
        assert self.closed + self.locked_time <= ctx['block_number']

        for address, state in self.participants.items():
            other = self.participants[self.partner(address)]
            state['netted'] = state['deposit']

            # FIXME: use the latest transfer only
            if state.get('last_sent_transfer'):
                state['netted'] = state['last_sent_transfer'].balance

            if other.get('last_sent_transfer'):
                state['netted'] = other['last_sent_transfer'].balance

        # add locked
        for address, state in self.participants.items():
            other = self.participants[self.partner(address)]
            for locked in state['unlocked']:
                state['netted'] += locked.amount
                other['netted'] -= locked.amount

        total_netted = sum(state['netted'] for state in self.participants.values())
        total_deposit = sum(state['deposit'] for state in self.participants.values())

        assert total_netted <= total_deposit

        self.settled = ctx['block_number']

        return dict(
            (address, state['netted'])
            for address, state in self.participants.items()
        )
