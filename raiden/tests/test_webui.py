from raiden.app import create_network
from raiden.tests.utils import setup_messages_cb
from raiden.web_ui import WebUI, UIHandler

""" Start:
1) `python test_webui.py`
2) interact in browser on 'localhost:8080'
3) copy availabe addresses from terminal to browser for interaction
4) it is not guaranteed that a channel to a specific address exists
"""


apps = create_network(num_nodes=10, num_assets=3, channels_per_node=2)
a0 = apps[0]
a0_raiden = a0.raiden
addresses = [app.raiden.address.encode('hex') for app in apps if app != apps[0]]
print '\nCreated nodes: \n',
for node in addresses:
    print node

am0 = a0.raiden.assetmanagers.values()[0]
setup_messages_cb()

num_hops = 2
source = a0.raiden.address
paths = am0.channelgraph.get_paths_of_length(source, num_hops)

assert len(paths)
for p in paths:
    assert len(p) == num_hops + 1
    assert p[0] == source
path = paths[0]
target = path[-1]
assert path in am0.channelgraph.get_paths(source, target)
assert min(len(p) for p in am0.channelgraph.get_paths(source, target)) == num_hops + 1

ams_by_address = dict((a.raiden.address, a.raiden.assetmanagers) for a in apps)

# addresses
a, b, c = path

# asset
asset_address = am0.asset_address

# # channels
# c_ab = ams_by_address[a][asset_address].channels[b]
# c_ba = ams_by_address[b][asset_address].channels[a]
# c_bc = ams_by_address[b][asset_address].channels[c]
# c_cb = ams_by_address[c][asset_address].channels[b]
#
# # initial channel balances
# b_ab = c_ab.balance
# b_ba = c_ba.balance
# b_bc = c_bc.balance
# b_cb = c_cb.balance


a0_assets = getattr(a0_raiden.api, 'assets')
print '\nAvailable assets:'
for asset in a0_assets:
    print asset.encode('hex')
print '\n'

handler = UIHandler(a0_raiden)
ui = WebUI(handler)
ui.run()
