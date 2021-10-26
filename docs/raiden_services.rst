Raiden Services
###############

.. toctree::
  :maxdepth: 3

Introduction
============

The Raiden network includes auxiliary services, that enhance the overall user
experience. These services include

- finding short or cheap routes through the network and
- allowing users to go offline safely by monitoring open payment channels.


.. _services-pathfinding:

Pathfinding Services
====================

Pathfinding services have a global view on a token network and can provide
suitable payment paths for Raiden nodes.

The service will keep its view on the token network updated by listening to
blockchain events and messages send from individual nodes in which current
capacities and fees are being published. Nodes can voluntarily publish this
information in order to advertise their channels and mediate payments.


Choosing a Pathfinding Service
------------------------------

By default the Raiden client will chose a suitable Pathfinding service for you.
As all PFSs are registered in the service registry, it will iterate over all of
them and choose one that has a fee which is lower then a given threshold.

This threshold can be changed with the ``--pathfinding-max-fee`` command line
flag and is set to 0.05 RDN by default.

If you want to use a certain PFS, then you can set it by using the
``--pathfinding-service-address`` command line flag.


Sent information
----------------

The PFS relies on information from the individual Raiden nodes to keep its
network representation up-to-date. Therefore the Raiden clients will send
information about channel capacities and fees to the PFS by default.

This can be disabled by using the ``private`` routing mode, where no such
updates are broadcasted. However, this also means that the PFS has no
information about the channels of that node and will **never** mediate payments
over these channels.


.. _services-monitoring:

Monitoring Services
===================

Monitoring services can watch open payment channels when the user is not online.
In case one channel partner closes a channel while the counterparty is offline
(or doesn’t react for 80% of the settlement timeout after close has been
called), the Monitoring service sends the latest balance proof to the channel
smart contract and thus ensures correct settlement of the channel.

Monitoring for channels is **disabled** by default. To enable it, the
``--enable-monitoring`` command line flag is used. This will enable monitoring
for all open channels.

.. note::

  It is currently not possible to enable monitoring for selected channels, but
  this will be possible in future version. This feature is tracked in `this
  issue. <https://github.com/raiden-network/raiden/issues/4951>`_


Sent information
----------------

In order to update the channel state the monitoring services need information
about the channel state. For that reason, when monitoring is enabled, the client
will send the latest received balance proof with additional information
necessary for the payment of the monitoring services (see `the spec for more
information
<https://raiden-network-specification.readthedocs.io/en/latest/monitoring_service.html#monitor-request>`_)
to the monitoring services.


Monitoring rewards
------------------

The Monitoring Service expects a reward when it updates a channel on the user's
behalf. This reward is only paid out when the user did not update the channel
state itself (this is handled by the Raiden client automatically). The reward is
not configurable and has a value of 5 RDN.
