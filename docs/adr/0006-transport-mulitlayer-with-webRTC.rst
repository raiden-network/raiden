Transport: Using Multilayer Transport with WebRTC
=================

**Status**: Under investigation
**Deciders**: 
**Date**: 2019-07-03

Context and Problem Statement
=============================

Matrix is likely to become the bottleneck for payment speed as well as throughput with a reasonable number of users and payments per second.
Out of a Tech Deep Dive Session the raiden team considered different alternatives to the problem. The current implemented transport based on Matrix meets
all of the necessary requirements Raiden has from a transport. Also the solution is working but with downsides regarding throughput and payment speed (message delivery speed).

Considered Options
==================

* **Option 1**: Multi Layer Transport. A Multi layer transport has a robust base transport layer which meets all requirements. Raiden must work on this transport layer
although with performance issues possible. Different Requirements can be outsourced to different other protocols which scale with the number of users
in order to A) improve performance and B) take of load from base layer. If anything goes wrong in the outsourced layers, the base serves as a fallback.
The Downside lies in increased complexity of implementing and maintaining multiple protocols.
* **Option 2**: go-libp2p-daemon. Libp2p is a very promising alternative p2p communication framework. It is configurable on multiple layers of transmission protocols.
In the current stage it is still in a very experimental state. It probably does not fullfill all requirements for being a full transport layer for Raiden.
* **Option 3**: Custom Websocket Solution. Another alternative is an inhouse built solution. Since the current Matrix transport is designed for its purpose being a chat protocol for humans
there has been work done to abstract it to Raiden's needs. A customized solution can be "tailored" to adapt perfectly to raiden's use case and would probably be
more lightweight than the current Matrix. A self-built transport of course requires additional maintainance capacity.



Decision
========

Option 1 was decided to be a short term solution to improve performance and scalability. Matrix already facilitates easy connection establishment of
WebRTC through special evetns which can be send via rooms. It seems to be a reasonable amount of effort to implement in comparison
to the gains in performance and speed. Examples have shown that subsecond payments are possible with webRTC. 
Matrix as the base layer provides a complete functionality and serves as a fallback. Whereas payments are communicated via
p2p webRTC channels between the participants.

After a longer period (6+ months) the performance and throughput will be reevaluated. This also gives other protocols the chance to mature.


Examples of Option 1
====================


- Alice's opens a matrix room with Bob
- Bob receives the invite and joins
- Alice as well as Bob use a signalling server to receive webRTC
- Both use the room and the special events to exchange canditates
- Once they negotiated, they gonna open webRTC data channels outside of Matrix.
- If the connection breaks, the private room between Alice and Bob still exists as a fallback and will be used immediately.


Why webRTC as the above layer solution
=====================================================

WebRTC is usually already built-in into any browser and very easy to use. As a matter of fact, the light client already implemented a 
proof of concept. Additionaly, as mentioned above, Matrix already provides a supported channel negotiation for their VoIP.
In some examples, WebRTC proved to realize subsecond mediated payments. Ideally with this solution, Matrix only serves for discovery and presence and can therefore accept a
much higher number of users until it becomes the bottleneck.


Current Status
===============
The implementation for the light client is almost merged.
The implementation for the python client is still under investigation. It needs to be solved how and which framework to use for handling
webRTC data channels.

