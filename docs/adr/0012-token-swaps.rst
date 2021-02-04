Token Swaps in Raiden
=====================

Use Cases
---------

Pay Target in Token Not Held by Initiator
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A merchant wants to be paid in DAI to avoid exchange rate risks for
crypto currencies. The buyer only has WETH in his wallet. The buyer can
use his WETH to pay, a mediator will swap the WETH to DAI and the
merchant will receive DAI.

Exchange Tokens Held by User
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A user has WETH and wants to buy RDN without going onchain. He already
has a channel for both WETH and RDN. He can use Raiden token swaps to do
this. This might be the same operation as above, since he could pay
himself in a different token.

Increased Liquidity by Combining Networks
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Even if no suitable route to a target can be found within a token
network, there might be a route between initiator and target when funds
are allowed to move through a different token network for a subset of
the path. This will only be useful if the swaps are very cheap.

Earn Fees by Providing Token Swaps
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In addition to providing normal mediation, mediators can also choose to
act as an exchange between different token networks. The mediator will
have to excplitly accept the legal risks and choose reasonable exchange
rates.

Migrate Between Contract Versions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Raiden does not provide upgradable contracts. When deploying new
contract versions, the only way to move the liquidity in the old
contracts to the new ones is to close the existing channels and open new
ones in the updated contracts. Doing that will incur high gas costs once
the Raiden Network has many users.

This can be mitigated by having some mediators open channels in the new
contracts while keeping their old channels open. Then these mediators
can mediate payments between the old and new networks.

This will require support for multiple token network registries in the
the client. As a consequence, multiple token networks for the same token
also have to be supported.

Transfer Tokens Between Different Blockchains
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

As long as the HTLs are compatible, a payment can work across any number
of different blockchains. A Raiden payment can be used to swap between
BTC, tokens on Ethereum, tokens on sidechains or other blockchains.

Compared to the other use cases, this brings additional problems, since
the PFS will not be able to find routes outside of Ethereum and we will
have to coordinate with non-Raiden clients. As a consquence, this should
be left out of the initial implementation. But we should keep it in
mind, so that we don’t accidentally make it harder to add support for
this in a later step.

Problems
--------

Choosing Exchange Rates
~~~~~~~~~~~~~~~~~~~~~~~

For many token pairs, the exchange rates will change too frequently to
allow manual rate updates.

Possible approaches: \* Provide an API where exchange rates can be
updated \* Include code to fetch exchange rates from external sources in
Raiden

As a safety measure, we should save the timestamp of the last exchange
rate update and not allow swaps when the rate is too old.

Communicating Exchange Rates
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Users expect the PFS not only to return a working route, but also to
return a cheap route. To do this, the PFS needs to know about exchange
rates when planning a route.

Possible approaches: \* Push: Mediators broadcast exchange rates, like
they do with fees (high traffic) \* Pull: Mediators broadcast the
supported tokens (or token pairs?). Exchange rates are requested by the
PFS as needed. This increases the path finding latency. \* Relative
rates: Mediators broadcast rates relative to a well respected source of
exchange rates (e.g. Uniswap + 3%)

An additional problem is the handling of slippage. When exchanging large
amounts of tokens, the exchange rates should get worse. To a certain
degree, this is taken care of by increasing imbalance fees, but that
might not be sufficient.

After a mediator made a token swap, the payment should be forced to
succeed or fail quickly. Otherwise a considerable free option problem
will arise.

Finding Routes Through Multiple Networks
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Currently, the PFS handles each token network seperately, which prevents
it from finding routes across different token networks. Implementing
support for cross-TN-routes requires some changes to the data structures
used in the PFS. Doing this naively will result in slow pathfinding,
since the combined graph of all token networks grows large quickly.

Supporting Multiple TokenNetworks Within a Single Payment
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Raiden currently expects payments to stay within one token network. To
make this work we need:

-  Changes to the REST API (prefixing a payment with the TN address does
   not work, anymore)
-  For migration between contract versions: support for multiple TN
   registries and multiple TNs for same token
-  Definition of the payment route has to include additional information
   (like token network contract for each hop, assumed exchange rate per
   mediator…)
-  … (Please add more here!)

Modular vs. In-protocol Approach
--------------------------------

As of the last discussion nearly all of the features above can be
implemented in two different design approaches:

-  Modular Approach - using existing functionalities and combining them
-  In-Protocol Approach - the protocol can natively handle new features

In the following the two design approaches are described on the example
of multi token network payments.

Modular Approach
~~~~~~~~~~~~~~~~

The modular approach aims to keep the Raiden core protocol lean and
simple. This should keep the Raiden protocol robust. Less features
introduce less edge cases which would have to be taken into account.
This all would lead to less potential exploits in the core codebase.
Depending on the feature to be implemented proxy smart contracts and
off-chain controlling modules would have to be implemented to compound
the Raiden core functionalities to a more powerful feature. These
proxies and modules communicate with each other and control a classic
Raiden node.

Modular Multi Token Network Payments
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If the Raiden protocol were only be able to handle single token payments
another idea is to assemble a multi token payment by initiating multiple
payments. This would require the mediator who exchanges into a different
token to accept a payment and forwarding it by initiating a next payment
as defined by the PFS. A controlling module must understand that for the
incoming payment the mediator is not the payee rather than a mediator.
This results in two conditions:

-  The mediator must not trigger a secret request (or at least will not
   receive an answer)
-  The next payment must be initiated with the same secret hash as the
   incoming payment

The control module is responsible for forwarding the payments and
contains the logic of handling and accepting mediation. A user can
easily place his desired exchange rate. The module coordinates between
the PFS and verifies that the current payment is acceptable to the
user’s desired exchange rate.

In-Protocol Approach
~~~~~~~~~~~~~~~~~~~~

The opposite approach implements this feature directly into the protocol
such as payments can be forward to channels from a different token
network.
