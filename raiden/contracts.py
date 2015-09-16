from ethereum.utils import sha3
from utils import isaddress


"""
Note, these are Mocks.
We assume, that they represent up to date information.
"""


class BlockChain(object):

    def __init__(self):
        self.block_number = 0
        self.channels_by_asset = dict()

    def next_block(self):
        self.block_number += 1

    def add_asset(self, asset_address):
        assert isaddress(asset_address)
        self.channels_by_asset[asset_address] = SettlementChannels(self, asset_address)

    @property
    def asset_addresses(self):
        return self.channels_by_asset.keys()

    def get_channels(self, asset_address):
        return self.channels_by_asset[asset_address]


class SettlementChannel(object):

    locked_time = 10  # num blocks

    def __init__(self, chain, asset, address_A, address_B):
        self.chain = chain
        self.asset = asset
        self.participants = {address_A: dict(deposit=0, last_sent_transfer=None),
                             address_B: dict(deposit=0, last_sent_transfer=None)}
        self.hashlocks = dict()
        self.opened = False  # block number
        self.closed = False  # block number
        self.settled = False

    def deposit(self, address, deposit):
        assert address in self.participants
        self.participants[address]['deposit'] += deposit
        if self.isopen and not self.opened:
            self.opened = self.chain.block_number

    @property
    def isopen(self):
        return not self.closed and \
            min(p['deposit'] for p in self.participants.values()) > 0

    def close(self, sender, *last_sent_transfers, **hashlocks):
        """"
        can be called multiple times. lock period starts with first valid call
        """
        assert sender in self.participants
        assert 0 <= len(last_sent_transfers) <= 2

        # register hashlocks
        for hashlock, secret in hashlocks.items():
            if hashlock == sha3(secret):
                self.hashlocks[hashlock] = secret

        # register / update claims
        for t in last_sent_transfers:
            # check transfer signature
            assert t.sender in self.participants

            # check hashlocks
            if t.hashlock and t.hashlock not in self.hashlocks:
                return
            # update valid claims
            if not self.participants[t.sender]['last_sent_transfers'] or \
                    self.participants[t.sender]['last_sent_transfers'].nonce < t.nonce:
                self.participants[t.sender]['last_sent_transfers'] = t

        # mark closed
        if not self.closed:
            self.closed = self.chain.block_number

    def settle(self):
        assert not self.settled
        assert self.closed and self.closed + self.locked_time <= self.chain.block_number

        for address, d in self.participants.items():
            other = [o for o in self.participants.values() if o != d][0]
            d['netted'] = d['deposit']
            if 'last_sent_transfer' in d:
                d['netted'] -= d['last_sent_transfer']['balance']
            if 'last_sent_transfer' in other:
                d['netted'] += other['last_sent_transfer']['balance']

        assert sum(d['netted'] for d in self.participants.values()) == \
            sum(d['deposit'] for d in self.participants.values())

        # call asset contracts and add assets

        self.settled = self.chain.block_number


class SettlementChannels(object):

    def __init__(self, chain, asset_address):
        self.chain = chain
        assert isaddress(asset_address)
        self.asset_address = asset_address
        self.channels = dict()

    def channels_by_address(self, address):
        return [c for c in self.channels.values() if address in c.participants]

    def _key(self, a, b):
        return ''.join(sorted((a, b)))

    def add(self, channel):
        k = self._key(*channel.participants.keys())
        assert k not in self.channels
        self.channels[k] = channel

    def get(self, a, b):
        k = self._key(a, b)
        return self.channels[k]

    def new(self, a, b):
        c = SettlementChannel(self.chain, self.asset_address, a, b)
        self.add(c)
        return c
