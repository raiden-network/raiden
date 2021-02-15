Connection Manager Preventing Fast Sync
=======================================

What Does the Connection Manager Do?
------------------------------------

The connection manager (CM) allows “joining” a token network. This means
that the CM will open channels to other nodes that already take part in
channels in the same token network. If not enough other nodes have
joined the network, it will wait for them to do so and then open
channels. It also deposits tokens into channels which are opened to the
node, but that part is not particularly relevant for this document.

Why Does That Make Things Slow?
-------------------------------

Fetching large amounts of historic events on Ethereum is slow. The light
client gets around this problem by only fetching events for channels in
which the node participates. We want to do the same in the python client
to solve the known extreme slowness on mainnet syncs.

But without fetching events about all channels, the node does not know
which other nodes are in the token network. Therefore, the CM can’t
connect to other nodes the way it used to.

Why Now?
--------

We see this rear its ugly head on the Raiden mainnet where Raiden nodes
won’t start within two hours unless Infura is used.

Solutions
---------

Get Information From PFS
~~~~~~~~~~~~~~~~~~~~~~~~

The PFS has an endpoint with suggestions for nodes to which to connect.
The CM could use that information for initial connections. If not enough
suggestions are returned, it could either stop its work at that point or
regularly re-query the PFS for suggestions until it connected to the
desired amount of nodes.

Provide History Events From a Different Source
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Instead of querying Ethereum nodes, we could fetch the events from a
different source. This could be `a JSON file we create and host
somewhere <https://github.com/raiden-network/raiden/issues/62090>`__ or
a service like Anyblock Analytics. However, this would run counter to
our decentralization efforts and could open up attack vectors if we
trust these event sources too much.

Remove Connection Manager
~~~~~~~~~~~~~~~~~~~~~~~~~

The CM is not easy to understand for both users and developers. There
are code paths in the Raiden code base that are only required by the CM
that caused bugs in the past. It is not clear if the CM in its current
form helps us to achieve our goals and its behavior of doing
transactions at times after joining a TN can make Raiden look bad at
times of high gas costs. In other words, the user is not made explicitly
aware that these channels incur gas costs and this problem is even more
pronounced during times of high gas costs.

Removing the CM and delegating the task of opening the right channels to
a layer above Raiden would simplify the Raiden core and would be a
better fit for many use cases.

See https://github.com/raiden-network/raiden/issues/4730 for previous
discussion of this idea.

Final Decision by the Team
--------------------------

Providing a functionality similar to the CM is valuable, but it does not
need to be part of the Raiden client’s core. Removing it from the client
will reduce the likelihood of complicated bugs. Adding a simplified
replacement to the WebUI will allow us to use the PFS’s partner
suggestion endpoint and will make it easier to provide user feedback for
the process of joining a token network. It might even be possible to
share code for this between the python and light client.
