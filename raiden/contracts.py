from utils import isaddress, sha3
"""
Note, these are Mocks.
We assume, that they represent up to date information.

Blockspam attack mitigation:
    - Oracles, certifying, that previous blocks were full.
    - Direct access to gasused of previous blocks.
    - Heuristic, no settlements in the previous blocks.

Note:
    NettingChannelContract should be merged with ChannelManagerContract
Todos:
    Compatible Asset/Token/Coin Contract
    Channel Opening sequence
    Channel Fees (i.e. Accounts w/ higher reputation could charge a fee/deposit).
    use channel.opened to collect reputation of an account (long lasting channels == good)
"""
from mtree import check_proof
import rlp
import messages
__all__ = (
    'BlockChain',
    'NettingChannelContract',
    'ChannelManagerContract',
)


class BlockChain(object):

    def __init__(self):
        self.block_number = 0
        self.channelmanagercontracts = dict()

    def next_block(self):
        self.block_number += 1

    def add_asset(self, asset_address):
        assert isaddress(asset_address)
        assert asset_address not in self.channelmanagercontracts
        self.channelmanagercontracts[asset_address] = ChannelManagerContract(self, asset_address)

    @property
    def asset_addresses(self):
        return self.channelmanagercontracts.keys()

    def channelmanager_by_asset(self, asset_address):
        return self.channelmanagercontracts[asset_address]


class NettingChannelContract(object):

    locked_time = 10  # num blocks

    def __init__(self, chain, asset_address, address_A, address_B):
        self.chain = chain
        self.asset_address = asset_address
        self.participants = {address_A: dict(deposit=0, last_sent_transfer=None, unlocked=[]),
                             address_B: dict(deposit=0, last_sent_transfer=None, unlocked=[])}
        self.hashlocks = dict()
        self.opened = False  # block number
        self.closed = False  # block number
        self.settled = False

    def deposit(self, address, amount):
        assert address in self.participants
        self.participants[address]['deposit'] += amount
        if self.isopen and not self.opened:
            self.opened = self.chain.block_number

    def partner(self, address):
        assert address in self.participants
        return [p for p in self.participants if p != address][0]

    @property
    def isopen(self):
        return not self.closed and \
            min(p['deposit'] for p in self.participants.values()) > 0

    def close(self, sender, last_sent_transfers, *unlocked):
        """"
        can be called multiple times. lock period starts with first valid call.

        todo:
            if challenged, keep track of who provided the last valid answer, punish the wrongdoer
                here, check that participants only updates their own balance are counted,
                    because they could sign something for the other party to blame it.

        last_sent_transfers: [rlp(transfer), ] max 2
        unlocked: [(merkle_proof, locked_rlp, secret)), ...]

        """
        assert sender in self.participants
        assert 0 <= len(last_sent_transfers) <= 2

        # register / update claims
        for t in last_sent_transfers:  # fixme rlp encoded
            # check transfer signature
            assert t.sender in self.participants

            # update valid claims
            if not self.participants[t.sender]['last_sent_transfer'] or \
                    self.participants[t.sender]['last_sent_transfer'].nonce < t.nonce:
                self.participants[t.sender]['last_sent_transfer'] = t

        # register un-locked
        last_sent = self.participants[self.partner(sender)]['last_sent_transfer']
        for merkle_proof, locked_rlp, secret in unlocked:
            locked = rlp.decode(locked_rlp, messages.Lock)
            assert locked.hashlock == sha3(secret)
            assert check_proof(merkle_proof, last_sent.locksroot, sha3(locked_rlp))
            self.participants[self.partner(t.sender)]['unlocked'].append(locked)

        # mark closed
        if not self.closed:
            self.closed = self.chain.block_number

    def settle(self):
        assert not self.settled
        assert self.closed
        assert self.closed + self.locked_time <= self.chain.block_number

        for address, d in self.participants.items():
            other = self.participants[self.partner(address)]
            d['netted'] = d['deposit']
            if d.get('last_sent_transfer'):
                d['netted'] = d['last_sent_transfer'].balance
            if other.get('last_sent_transfer'):
                d['netted'] = other['last_sent_transfer'].balance

        # add locked
        for address, d in self.participants.items():
            other = self.participants[self.partner(address)]
            for locked in d['unlocked']:
                d['netted'] += locked.amount
                other['netted'] -= locked.amount

        assert sum(d['netted'] for d in self.participants.values()) <= \
            sum(d['deposit'] for d in self.participants.values())

        # call asset contracts and add assets
        self.settled = self.chain.block_number

        return dict((a, d['netted']) for a, d in self.participants.items())


class ChannelManagerContract(object):

    def __init__(self, chain, asset_address):
        self.chain = chain
        assert isaddress(asset_address)
        self.asset_address = asset_address
        self.nettingcontracts = dict()  # address_A + addressB : NettingChannelContract

    def nettingcontracts_by_address(self, address):
        return [c for c in self.nettingcontracts.values() if address in c.participants]

    def _key(self, a, b):
        return ''.join(sorted((a, b)))  # fixme replace by sha3

    def add(self, channel):
        assert isinstance(channel, NettingChannelContract)
        k = self._key(*channel.participants.keys())
        assert k not in self.nettingcontracts
        self.nettingcontracts[k] = channel

    def get(self, a, b):
        k = self._key(a, b)
        return self.nettingcontracts[k]

    def new(self, a, b):
        c = NettingChannelContract(self.chain, self.asset_address, a, b)
        self.add(c)
        return c

    def check_statelock(self, data, gaslimit):
        "not yet implemented, see `messages.StateLock`"
        contract_address = data[:20]  # noqa  (FIXME)
        calldata = data[20:]  # noqa  (FIXME)
        # FIXME: call contract and return success
