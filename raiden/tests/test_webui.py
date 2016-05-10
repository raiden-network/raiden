from raiden.tests.utils.network import create_network
from raiden.tests.utils.messages import setup_messages_cb
from raiden.web_ui import WebUI, UIHandler

""" Start:
1) `python test_webui.py`
2) interact in browser on 'localhost:8080'
3) copy availabe addresses from terminal to browser for interaction
4) it is not guaranteed that a channel to a specific address exists
"""

app_list = create_network(num_nodes=10, num_assets=3, channels_per_node=2)
app0 = app_list[0]
addresses = [app.raiden.address.encode('hex') for app in app_list if app != app_list[0]]
print '\nCreated nodes: \n',
for node in addresses:
    print node
setup_messages_cb()

am0 = app0.raiden.assetmanagers.values()[0]

# search for a path of length=2 A > B > C
num_hops = 2
source = app0.raiden.address

path_list = am0.channelgraph.get_paths_of_length(source, num_hops)
assert len(path_list)

for path in path_list:
    assert len(path) == num_hops + 1
    assert path[0] == source

path = path_list[0]
target = path[-1]
assert path in am0.channelgraph.get_shortest_paths(source, target)
assert min(len(p) for p in am0.channelgraph.get_shortest_paths(source, target)) == num_hops + 1

ams_by_address = dict(
    (app.raiden.address, app.raiden.assetmanagers)
    for app in app_list
)

# addresses
hop1, hop2, hop3 = path

# asset
asset_address = am0.asset_address

app0_assets = getattr(app0.raiden.api, 'assets')
print '\nAvailable assets:'
for asset in app0_assets:
    print asset.encode('hex')
print '\n'

handler = UIHandler(app0.raiden)
ui = WebUI(handler)
ui.run()
