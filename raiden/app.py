from raiden_service import RaidenService
from transport import DummyTransport, UDPTransport, PredictiveDiscovery
import blockchain
import contracts
from utils import sha3
import copy


class App(object):

    default_config = dict(host='', port=40001, privkey='')

    def __init__(self, config, chain, discovery, transport_class=DummyTransport):
        self.config = config
        self.transport = transport_class(config['host'], config['port'])
        self.raiden = RaidenService(chain, config['privkey'], self.transport, discovery)
        discovery.register(self.raiden.address, self.transport.host, self.transport.port)
        self.discovery = discovery


def mk_app(num, chain, discovery, transport_class, host="127.0.0.1", **kwargs):
    config = copy.deepcopy(App.default_config)
    config['port'] += num
    config['host'] = host
    config['privkey'] = sha3("{}:{}".format(host, config['port']))
    return App(config, chain, discovery, transport_class)


def create_network(num_nodes=8, num_assets=1, channels_per_node=3, transport_class=UDPTransport):
    import random
    random.seed(1337)

    # globals
    discovery = PredictiveDiscovery((
        ("127.0.0.10", num_nodes / 2),
        ("127.0.0.11", num_nodes - num_nodes / 2),
        ))
    init_chain = blockchain.NetBlockChain("127.0.0.11", 7777)
    # init_chain = blockchain.BlockChain()

    # create apps
    ## create virtual interfaces: ifconfig lo:0 127.0.0.10; ifconfig lo:1 127.0.0.11
    apps = [mk_app(i, blockchain.NetBlockChain("127.0.0.11", 7777), discovery, transport_class, host="127.0.0.10", privkey="predictive") for i in range(num_nodes / 2)]
    apps.extend([mk_app(i, blockchain.NetBlockChain("127.0.0.11", 7777), discovery, transport_class, host="127.0.0.11", privkey="predictive") for i in range(num_nodes - num_nodes / 2)])
    # apps = [mk_app(i, init_chain, discovery, transport_class, host="127.0.0.10", privkey="predictive") for i in range(num_nodes / 2)]
    # apps.extend([mk_app(i, init_chain, discovery, transport_class, host="127.0.0.11", privkey="predictive") for i in range(num_nodes - num_nodes / 2)])

    # create assets
    for i in range(num_assets):
        init_chain.add_asset(asset_address=sha3('asset:%d' % i)[:20])
    assert len(init_chain.asset_addresses) == num_assets

    # create channel contracts
    for asset_address in init_chain.asset_addresses:
        channelmanager = init_chain.channelmanager_by_asset(asset_address)
        assert isinstance(channelmanager, contracts.ChannelManagerContract)
        assert channels_per_node < len(apps)
        for app in apps:
            capps = list(apps)  # copy
            capps.remove(app)
            netting_contracts = channelmanager.nettingcontracts_by_address(app.raiden.address)
            while len(netting_contracts) < channels_per_node and capps:
                peer = random.choice(capps)
                assert peer != app
                capps.remove(peer)
                peer_nettting_contracts = channelmanager.nettingcontracts_by_address(peer.raiden.address)
                if not set(netting_contracts).intersection(set(peer_nettting_contracts)) \
                        and len(peer_nettting_contracts) < channels_per_node:
                    # print pex(a.raiden.address), pex(app.raiden.address)
                    c = channelmanager.new(peer.raiden.address, app.raiden.address)
                    netting_contracts.append(c)

                    # add deposit of asset
                    for address in (app.raiden.address, peer.raiden.address):
                        c.deposit(address, amount=2 ** 240, ctx=dict(block_number=init_chain.block_number))

            print netting_contracts

    for app in apps:
        app.raiden.setup_assets()
        # assert len(app.raiden.assetmanagers)

    return apps
