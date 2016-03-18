# -*- coding: utf8 -*-
"""
A pure python implementation of a contract responsable to open a channel.

From the perspective of the blockchain this contract is responsable to store or
lock the balance that is being exchanged in the channel, it's also
responsability of this contract to cleanly close the channel, meaning that the
users should receive the "right amount" of coins back.

In the context of a channel the "right amount" is not as straight forward, from
the point of view of the contract the right amount is equivalent to the latest
valid transaction that a peer notified the contract, in the good scenario these
transactions will also be the right ones but in a dispute scenario one party
might be trying to close the channel with an older transaction were it's own
netted value is higher, for this reason the contract has mechanisms to penalize
the wrong doer given that the losing party presents a newer transaction.
"""
import rlp
from ethereum import slogging

from raiden.utils import sha3
from raiden.mtree import check_proof
from raiden import messages

log = slogging.getLogger('raiden.blockchain.net_contract')  # pylint: disable=invalid-name


# Blockspam attack mitigation:
#     - Oracles, certifying, that previous blocks were full.
#     - Direct access to gasused of previous blocks.
#     - Heuristic, no settlements in the previous blocks.
# Todos:
#     Compatible Asset/Token/Coin Contract
#     Channel Opening sequence
#     Channel Fees (i.e. Accounts w/ higher reputation could charge a fee/deposit).
#     use channel.opened to collect reputation of an account (long lasting channels == good)


class NettingChannelContract(object):
    """ Contract code for a channel.

    Note:
        This is a mock implementation.
    """

    locked_time = 10  # number of blocks

    def __init__(self, asset_address, address_A, address_B):
        log.debug(
            'creating nettingchannelcontract',
            a=address_A.encode('hex'),
            b=address_B.encode('hex'),
        )

        self.asset_address = asset_address
        self.participants = {
            address_A: dict(deposit=0, last_sent_transfer=None, unlocked=[]),
            address_B: dict(deposit=0, last_sent_transfer=None, unlocked=[]),
        }
        self.hashlocks = dict()
        self.opened = None  # block number
        self.closed = None  # block number
        self.settled = False

    @property
    def isopen(self):
        """ The contract is open after both participants have deposited, and if
        it has not being closed.

        Returns:
            bool: True if the contract is open, False otherwise
        """
        lowest_deposit = min(
            state['deposit']
            for state in self.participants.values()
        )

        all_deposited = lowest_deposit > 0

        return not self.closed and all_deposited

    def deposit(self, address, amount, ctx):
        """ Deposit `amount` coins for the address `address`. """

        if address not in self.participants:
            msg = 'The address {address} is not a participant of this contract'.format(
                address=address,
            )

            raise ValueError(msg)

        if amount < 0:
            raise ValueError('amount cannot be negative')

        self.participants[address]['deposit'] += amount

        if self.isopen and self.opened is None:
            # track the block were the contract was openned
            self.opened = ctx['block_number']

    def partner(self, address):
        """ Returns the address of the other participant in the contract. """

        if address not in self.participants:
            msg = 'The address {address} is not a participant of this contract'.format(
                address=address,
            )
            raise ValueError(msg)

        all_participants = list(self.participants.keys())
        all_participants.remove(address)
        return all_participants[0]

    def close(self, sender, last_sent_transfers, ctx, *unlocked):
        """" Request the closing of the channel. Can be called multiple times.
        lock period starts with first valid call.

        Args:
            sender (address):
                The sender address.

            last_sent_transfers (List[transfer]):
                Maximum length of 2, may be empty.

            ctx:
                Block chain state used for mocking.

            *unlocked (List[(merkle_proff, locked_rlp, secret)]):

        Todo:
            if challenged, keep track of who provided the last valid answer,
            punish the wrongdoer here, check that participants only updates
            their own balance are counted, because they could sign something
            for the other party to blame it.
        """

        def is_newer_transfer(transfer, sender_state):
            """ Helper to check if `transfer` is from a newer block than
            sender_state's lastest transfer.
            """

            last_transfer = sender_state.get('last_sent_transfer')

            if last_transfer is None:
                return True

            return last_transfer.nonce < transfer.nonce

        if sender not in self.participants:
            raise ValueError(
                'Sender is not a participant of this contract, he cannot close '
                'the channel.'
            )

        if len(last_sent_transfers) > 2:
            raise ValueError('last_sent_transfers cannot have more than 2 items.')

        # keep the latest claim
        for transfer in last_sent_transfers:  # fixme rlp encoded
            if transfer.sender not in self.participants:
                raise ValueError('Invalid tansfer, sender is not a participant')

            sender_state = self.participants[transfer.sender]

            if is_newer_transfer(transfer, sender_state):
                sender_state['last_sent_transfer'] = transfer

        partner = self.partner(sender)
        partner_state = self.participants[partner]

        transfer = last_sent_transfers[-1]  # XXX: check me

        # register un-locked
        for merkle_proof, locked_rlp, secret in unlocked:
            locked = rlp.decode(locked_rlp, messages.Lock)  # FIXME: wont work with fixed length
            hashlock = locked.hashlock  # pylint: disable=no-member

            assert hashlock == sha3(secret)
            assert check_proof(
                merkle_proof,
                partner_state['last_sent_transfer'].locksroot,
                sha3(locked_rlp),
            )

            partner_state['unlocked'].append(locked)

        if self.closed is None:
            self.closed = ctx['block_number']

    def settle(self, ctx):
        assert not self.settled
        assert self.closed
        assert self.closed + self.locked_time <= ctx['block_number']

        for address, state in self.participants.items():
            other = self.participants[self.partner(address)]
            state['netted'] = state['deposit']

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
