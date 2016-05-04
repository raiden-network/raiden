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

TRANSFER_UNKNOW = 0
""" State before close() is called."""

TRANSFER_FROM_SELF = 1
""" State for a transfer sent by the participant itself by calling close or update_transfers. """

TRANSFER_FROM_THIRDPARTY = 2
""" State used if a thirdparty updated a transfer on behalf of a node. """

TRANSFER_FROM_PARTNER = 3
""" State used for the transfer that was exchange and informed by the other node in close(). """

# Blockspam attack mitigation:
#     - Oracles, certifying, that previous blocks were full.
#     - Direct access to gasused of previous blocks.
#     - Heuristic, no settlements in the previous blocks.
# Todos:
#     Compatible Asset/Token/Coin Contract
#     Channel Opening sequence
#     Channel Fees (i.e. Accounts w/ higher reputation could charge a fee/deposit).
#     use channel.opened to collect reputation of an account (long lasting channels == good)


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

        self.transfer = None
        """ The last transfer used for settling the balances. This transfer can
        be sent from either participant or a third-party.
        """

        self.state = TRANSFER_UNKNOW
        """ Indicate the origin of the transfer. """

        self.unlocked = []
        """ A list of (Lock, merkle_proof, secret). """

        self.has_deposited = False
        """ Flag indicating if the participant has called the deposit(). """


class NettingChannelContract(object):
    """ Contract that allows users to perform fast off-chain transactions.

    The netting contract allows two parties to engage in off-chain asset
    transfers without trust among them, with the functionality of detecting
    frauds, penalize the wrongdoers, and to participate in an off-chain network
    for fast and cheap transactions.

    Operation
    ---------

    Off-chain transactions are done by external clients without interaction
    with the channel's contract, the contract's role is only to secure the
    asset and create the mechanism that allows settlement of conflicts.

    The asset transfers are done through the exchange of signed messages among
    the participants, each message works as a proof of balance for a given
    participant at each moment. These messages are composed of:

        - The message signature, proving authenticity of the message.
        - The increasing counter `nonce`, identifying the order of the
        transfers.
        - The partner's current balance.
        - The merkle root of the locked transfers tree.
        - Possibly a `Lock` structure describing a new locked transfer.

    Since the contract does not mediate these off-chain transfers, it is the
    interest of each participant to reject invalid messages, these are the
    points of concern:

        - Signatures need to be from a key recognized by the contract.
        - `Nonce`s are unique and increasing to identify the transfer order.
        - Negative transfers are invalid.
        - Maintain a correct merkle root with all non-expired locked transfer.
        - A valid timeout for `Lock`ed transfers.

    Transfers
    ---------

    There are two kinds of transfers that are recognized by the contract, a
    transfer initiate by a channel participant to the other participant, called
    a direct transfer, or a mediated transfer involving multiple channels, used
    for cooperatively transfer assets for nodes without a direct channel.

    Multiple transfers are expected to occur from the opening of a channel
    onwards, and only the latest with it's balance is valid. The `nonce` field
    is used by this contract to compare transfers and define which is the
    latest, it's responsability of each participant to reject messages with an
    decreasing or equal `nonce`, ensuring that this value is increasing, not
    necessarilly sequential/unitarily.

    Direct Transfer
    ===============

    Direct transfers require only the exchange of a single signed message
    containing the current `nonce`, with an up-to-date balance and merkle
    proof.

    Mediated Transfer
    =================

    Direct transfer are possible only with the existence of a direct channel
    among the participants, since direct channels are expected to be the
    exception and not the rule a different mechanism is required for indirect
    transfers, this is done by exploiting existing channels to mediate an asset
    transfer.

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

    Note:
        Implementation in pure python that reproduces the expected behavior of
        the blockchain NettingContract. This implementation is useful for
        testing.
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
        """ Deposit `amount` coins for the address `address`. """

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
        transfer1 = decode_transfer(first_encoded)
        transfer2 = decode_transfer(second_encoded)

        if transfer1.sender not in self.participants:
            raise ValueError('Invalid transfer address')

        if transfer2.sender not in self.participants:
            raise ValueError('Invalid transfer address')

        if transfer1.sender == transfer2.sender:
            raise ValueError('Both transfer are for the same address')

        return transfer1, transfer2

    def close(self, ctx, first_encoded, second_encoded):
        """" Request the closing of the channel. Can be called once by one of
        the participants. Lock period starts counting once this method is
        called.

        Args:
            ctx:
                Block chain state used for mocking.

            first_encoded:
                One of the last sent transfers, can be a transfer from either
                side of the cannel. May be None.

            second_encoded:
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
            raise ValueError('Invalid call, caller is not a participant')

        transfer1, transfer2 = self._decode(first_encoded, second_encoded)

        # The order is undetermined
        if transfer1.sender == ctx['msg.sender']:
            sender = transfer1
            partner = transfer2
        else:
            sender = transfer2
            partner = transfer1

        self.closed = ctx['block_number']

        # Flag the transfer from the node that called close, if a new transfer
        # appears the closer will be penalized for lying, since it know all the
        # messages that itself sent.
        sender_state = self.participants[sender.sender]
        sender_state.state = TRANSFER_FROM_SELF
        sender_state.transfer = sender

        # Since the closer sent it's last message, there is an incentive to it
        # send the partner's latest message, because the balance is defined by
        # the value_transfered that can only increase, any message that is not
        # the latest will result in a lower balance for itself.
        partner_state = self.participants[partner.sender]
        partner_state.state = TRANSFER_FROM_PARTNER
        partner_state.trasnfer = partner

    def _check_increasing(self, transfer):  # pylint: disable=no-self-use,unused-argument
        """ Helper to penalize any participant that created a transfer message
        which isn't monotonically increasing the value_transfered.
        """
        # Both messages are know to be signed by the participant, so they were
        # not faked. Independent of the origin, if these messages disagree in
        # value the participant must have tampered it.

        penalize = False
        # state = self.participants[transfer.sender]
        # penalize = (
        #     (
        #         state.transfer.nonce < transfer.nonce and
        #         state.transfer.value_transfered > transfer.value_transfered
        #     ) or (
        #         state.transfer.nonce == transfer.nonce and
        #         state.transfer.value_transfered != transfer.value_transfered
        #     )
        # )

        if penalize:
            # TODO: penalize
            raise RuntimeError('Signed message with forged values encoutered')

    def _aquired_update(self, new_transfer):
        """ Helper to validate a TRANSFER_FROM_SELF or to update a
        TRANSFER_FROM_PARTNER.

        Use this method to update the contract state with a transfer that
        cannot be made by the caller, or to check that the transfer informed by
        the participant is the latest.
        """
        state = self.participants[new_transfer.sender]
        current_transfer = state.transfer

        if state.state == TRANSFER_FROM_SELF:
            # Each participant knows the very last transfer that it has sent,
            # if it informed anything but the lastest transfer it is penalized.

            # The message informed by the participant can be one of the following:
            # - The correct transfer (non-tampered and the latest), and we get the
            # correct behavior.
            # - Not the latest transfer, in which case the node will be penalized
            # and lose it's assets.
            # - A valid tampered transfer with a higher nonce, were the sender can
            # only increase the `value_transfered` and lose asset.

            # XXX: how to handle unacknowledged transfers?

            # TODO: penalize the node if it that called close() passing an
            # out-of-date transfer
            # if current_transfer.nonce < new_transfer.nonce
            pass
        elif state.state in (TRANSFER_FROM_THIRDPARTY, TRANSFER_FROM_PARTNER):
            # This happens either if the closer didn't inform the partner's
            # latest transfer or if the partner created a new and valid
            # transfer afterwards.
            if current_transfer.nonce < new_transfer.nonce:
                state.transfer = new_transfer
                state.state = TRANSFER_FROM_THIRDPARTY
        else:
            raise Exception('Unexpected state')

    def _participant_update(self, transfer):
        """ Helper to update the participant transfer. """

        state = self.participants[transfer.sender]

        if state.state == TRANSFER_FROM_SELF:
            # TODO: penalize the participant for calling twice
            raise RuntimeError('Participant trying to call the contract twice.')

        # TODO: penalize if the participant is sending an older transfer
        # state.transfer.nonce > transfer.nonce

        state.state = TRANSFER_FROM_SELF
        state.transfer = transfer

    def update_transfers(self, ctx, first_encoded, second_encoded, signature):
        """" Update the last know transfers. Can be called multiple times.

        Args:
            ctx:
                Block chain state used for mocking.

            first_encoded (bin):
                One of the last sent transfers, can be a transfer from either
                side of the cannel. May be None.

            second_encoded (bin):
                The last sent transfer from the other end of the channel, in
                respect to `first_encoded`. May be None.

            signature (bin):
                The signature for `sha3(first_encoded || second_encoded)`.
        """
        if self.settled:
            raise RuntimeError('Contract is settled.')

        if not self.closed:
            raise RuntimeError('Contract is open.')

        # signature required for third-parties (could use a separate method to save gas)
        messages_hash = sha3(first_encoded + second_encoded)
        publickey = c_ecdsa_recover_compact(messages_hash, signature)
        address = address_from_key(publickey)

        if address not in self.participants:
            raise ValueError('Invalid address.')

        transfer1, transfer2 = self._decode(first_encoded, second_encoded)

        # The order is undetermined
        if transfer1.sender == address:
            sender = transfer1
            partner = transfer2
        else:
            sender = transfer2
            partner = transfer1

        self._check_increasing(sender)
        self._check_increasing(partner)

        is_thirdparty = ctx['msg.sender'] != address
        if is_thirdparty:
            self._aquired_update(partner)  # check that TRANSFER_FROM_SELF was the latest
            self._aquired_update(sender)  # the third-party did not make the message
        else:
            # participant overwriting a third-party or the participant's call is first
            self._aquired_update(partner)  # check that TRANSFER_FROM_SELF was the latest
            self._participant_update(sender)  # check that TRANSFER_FROM_PARTNER was the latest

    def unlock(self, ctx, locked_encoded, merkleproof_encoded, secret):
        # pylint: disable=too-many-arguments,too-many-locals,too-many-branches
        # if len(transfers_encoded):
        #     raise ValueError('transfers_encoded needs at least 1 item.')

        if self.settled:
            raise RuntimeError('Contract is settled.')

        if not self.closed:
            raise RuntimeError('Contract is open.')

        if ctx['msg.sender'] not in self.participants:
            raise ValueError('Unknow address.')

        partner = self.partner(ctx['msg.sender'])
        state = self.participants[partner]
        transfer = state.transfer

        if not transfer:
            return

        merkle_proof = tuple32(merkleproof_encoded)
        lock = Lock.from_bytes(locked_encoded)

        hashlock = lock.hashlock
        if hashlock != sha3(secret):
            raise ValueError('invalid secret')

        # the partner might not have made a transfer
        is_valid_proof = check_proof(
            merkle_proof,
            transfer.locksroot,
            sha3(transfer.lock.as_bytes),
        )

        if not is_valid_proof:
            raise ValueError('Invalid merkle proof')

        transfer.append(lock)

    def settle(self, ctx):
        """
        Todo:
            if challenged, keep track of who provided the last valid answer,
            punish the wrongdoer here, check that participants only updates
            their own balance are counted, because they could sign something
            for the other party to blame it.
        """
        assert not self.settled
        # during testing closed can be 0 and it is falsy
        assert self.closed is not None
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
