from raiden_service import RaidenService
from transport import Transport, Discovery
from contracts import BlockChain
from utils import sha3
import copy


class App(object):

    default_config = dict(host='', port=40000, privkey='')

    def __init__(self, privkey, port, chain, discovery, transport):
        self.config = copy.deepcopy(self.default_config)
        self.config['port'] = port
        self.raiden = RaidenService(chain, privkey, transport, discovery)
        discovery.register(self.raiden.address, self.config['host'], self.config['port'])
        transport.register(self.raiden.protocol, self.config['host'], self.config['port'])
        self.transport = transport
        self.discovery = discovery


def mk_app(num, chain, discovery, transport):
    privkey = sha3(str(num))
    port = App.default_config['port'] + num
    return App(privkey, port, chain, discovery, transport)


def create_network(num_nodes=8, num_assets=1, channels_per_node=3):
    import random
    random.seed(42)

    # globals
    transport = Transport()
    discovery = Discovery()
    chain = BlockChain()

    # create apps
    apps = [mk_app(i, chain, discovery, transport) for i in range(num_nodes)]

    # create assets
    for i in range(num_assets):
        chain.add_asset(asset_address=sha3('asset:%d' % i)[:20])
    assert len(chain.asset_addresses) == num_assets

    # create channel contracts
    for asset_address in chain.asset_addresses:
        asset_channel_contracts = chain.get_channel_contracts(asset_address)
        for app in apps:
            capps = list(apps)  # copy
            netting_channels = asset_channel_contracts.channels_by_address(app.raiden.address)
            while len(netting_channels) < channels_per_node and capps:
                a = random.choice(capps)
                capps.remove(a)
                a_channels = asset_channel_contracts.channels_by_address(a.raiden.address)
                if not set(netting_channels).intersection(set(a_channels)) \
                        and len(a_channels) < channels_per_node:
                    c = asset_channel_contracts.new(a.raiden.address, app.raiden.address)
                    netting_channels.append(c)

                    # add deposit of asset
                    for address in (app.raiden.address, a.raiden.address):
                        c.deposit(address, amount=10**6)

    for app in apps:
        app.raiden.setup_assets()

    return apps
