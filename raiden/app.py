from raiden_service import RaidenService
from transport import Transport, Discovery
from contracts import BlockChain
from utils import sha3
import copy

# globals
transport = Transport()
discovery = Discovery()
blockchain = BlockChain()


class App(object):

    default_config = dict(host='', port=40000, privkey='')

    def __init__(self, privkey, port):
        self.config = copy.deepcopy(self.default_config)
        self.config['port'] = port
        self.raiden = RaidenService(blockchain, privkey, transport, discovery)
        discovery.register(self.raiden.address, self.config['host'], self.config['port'])
        transport.register(self.raiden.protocol, self.config['host'], self.config['port'])


def mk_app(num):
    return App(privkey=sha3(str(num)), port=App.default_config['port'] + num)


def create_network(num_nodes=8, num_assets=1, channels_per_node=3):
    import random
    random.seed(42)

    # create apps
    apps = [mk_app(i) for i in range(num_nodes)]

    # create assets
    for i in range(num_assets):
        blockchain.add_asset(asset_address=sha3('asset:%d' % i))

    # create channels
    for asset_address in blockchain.asset_addresses:
        asset_channels = blockchain.get_channels(asset_address)
        for app in apps:
            capps = list(apps)  # copy
            app_channels = asset_channels.channels_by_address(app.raiden.address)
            while len(app_channels) < channels_per_node and capps:
                a = random.choice(capps)
                capps.remove(a)
                a_channels = asset_channels.channels_by_address(a.raiden.address)
                if not set(app_channels).intersection(set(a_channels)) \
                        and len(a_channels) < channels_per_node:
                    c = asset_channels.new(a.raiden.address, app.raiden.address)
                    app_channels.append(c)

    return apps
