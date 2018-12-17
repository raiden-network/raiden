Raiden Guide on State Machines
##############################
.. toctree::
   :maxdepth: 2

Introduction
============

The current Raiden prototype chose to use hierarchical state machines to represent the internal state of the node. The state of the whole node is a tree that can be serialized on and recovered from the disk. Moreover, whenever the state changes, the change is triggered by a state change object, which can also be serialized on the disk. A snapshot of the state and the subsequent state change objects are enough to compute the current state of the node. That's how a node recovers from crashes.

Kinds of State Machines
=======================

The state of the whole node is represented as a ``ChainState`` object. The ``ChainState`` object contains many other different kinds of objects. This section describes them in a bottom-to-top manner.

This section is very early in construction with the simplest state machines.

HashTimeLockState
*****************

A ``HashTimeLockState`` represents a hash time lock.

Attributes of a HashTimeLockState
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* ``amount`` is the amount of tokens locked in the hash time lock.
* ``expiration`` is the block number when the hash time lock expires.
* ``secrethash`` is the hash value of the secret that can unlock the hash time lock.
* ``encoded`` is the serialization of the above fields.
* ``lockhash`` is the hash of ``encoded``, which is useful for the Merkle tree formation.

State Changes on a HashTimeLockState
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

No state changes operate on a ``HashTimeLockState``. A ``HashTimeLockState`` is just added to and removed from :ref:`netting-channel-end-state`.

Other State Machines that Contain a HashTimeLockState
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* A :ref:`netting-channel-end-state` contains zero-to-many ``HashTimeLockState``.

.. _netting-channel-end-state:

NettingChannelEndState
**********************

(TODO: describe)

Other State Machines to be Added
********************************

* ``NettingChannelEndState``
* ``NettingChannelState``
* ...
* ``TokenNetworkState``
* ``PaymentMappingState``
* ``PaymentNetworkState``
* ``ChainState``
