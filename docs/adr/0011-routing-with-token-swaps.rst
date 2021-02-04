Routing With Built-In Token Swaps
=================================

Use Case
--------

Buyer’s and sellers usually each have a preferred currency/token. When
both parties prefer different tokens, one party has to accept dealing
with a non-preferred token. In addition to being inconvenient, this can
also require open a new channel, this making the payment slow and
expensive. Dealing with a different token might not even be possible for
some parties (e.g. due to bookkeeping restrictions). If the Raiden
Network provided a way to swap tokens while doing the payment, both
parties could deal with their preferred token and transaction would be
quick, cheap and convenient.

Concept
-------

Node A wants to pay node B an amount of 10 T2 tokens, but A only has T1
tokens. A requests a route from the PFS:

::

   source: A
   target: B
   target_amount: 10 T2
   source_token: T1

The PFS looks for a route that minimizes the amount of T1 tokens that A
has to spend in order for B to receive 10 T2, taking into account both
mediation fees and the required token swap. The returned route might
look like

::

     T1     T1     T2
   A --> M1 --> M2 --> B

meaning that mediator M2 accepts T1 and sends T2, thereby providing both
mediation and token conversion. Despite using different token networks,
the payment will still be atomic by using the same hash time lock across
the whole path.

Problems
--------

-  Nodes willing to do token swaps have to tell the PFS their exchange
   rate. Broadcasting could be much traffic, polling would slow down
   routing.
-  The PFS has to be able to route through multiple token networks at
   the same time.
-  Behavior not clear for non-strict routing
-  The route can fail due to changes in conversion rate. This can be
   mitigated by adding some safety margin, but the increases the price
   for the sender.
