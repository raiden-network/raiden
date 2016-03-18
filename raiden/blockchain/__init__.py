# -*- coding: utf8 -*-
"""
This module contains a mock implementation of a block chain that is suficient
to simulate it's expected behavior for testing purposes.

Raiden is an offchain trasaction system, that means that the state of the
current transactions are not commited into the distributed ledger unless one of
the parties explicitelly required the channel closure either.

As a consequence raiden nodes do not need to have a blockchain implementation
built-in, we can build a client that is completely independent from the
blockchain by just using ethereum's full node JSON RPC APIs.

Note:
    These are Mocks.

    We assume, that they represent up to date information.
"""
