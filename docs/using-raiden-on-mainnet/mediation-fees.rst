Mediation Fees
==============

What are Mediation Fees?
------------------------

Raiden lets users pay anyone in the network by using a path of connected
payment channels to mediate the payment. Mediating nodes, which are the
nodes between the initiator and target on the selected payment path, can
earn mediation fees.

Mediation fees are paid by the initiator by slightly increasing the
amount of tokens above the amount intended for the target. This also
means that mediation fees are always paid in tokens of the kind that is
being transferred.

Benefits of Mediation Fees
--------------------------

Mediation fees increase the health of the payment network by:

-  incentivizing users to run mediating nodes
-  choosing lower fees for routes that balance the involved payment
   channels

A healthy payment network allows cheap and reliable payments for users.
So even though users have to pay mediation fees when initiating
payments, these fees are ultimately to their own benefit.

Calculation of Mediation Fees
-----------------------------

Each mediator can choose a fee schedule for mediating payments. This fee
schedule consists of three parts:

-  a flat fee per mediation
-  a fee proportional to the mediated amount of tokens
-  an imbalance fee that increases when the payment exhausts channel
   capacity, which might prevent the channel from being used in future
   payments

The sum of these fee components represents the fee for a single
mediator. Summing the fees for all mediators in the payment route yields
the total amount of mediation fees for a payment.

Since the fees can change between the time of fee calculation by the
initiator (or the pathfinding service on his behalf) and the time of
mediation, a safety margin is added on top of the mediation fee. Without
this, a mediator might drop the payment because its imbalance fee has
increased due to another payment taking place within this time span.

For more details on the calculation of fees, see the `blog
post <https://medium.com/raiden-network/dynamic-mediation-fees-in-raiden-explained-dbc29f032e4b>`__
and the `architecture decision
record <https://github.com/raiden-network/raiden-services/blob/master/adr/003-mediation-fees.md>`__.

Default Fee Schedule
--------------------

You don't need to configure the fee schedule yourself if you don't want
to, since Raiden comes with a default fee schedule. The default values
are

-  flat fee

   -  DAI: 10^-6 DAI
   -  W-ETH: 10^-8 W-ETH

-  proportional: 0.4% of the mediated tokens
-  imbalance: up to 0.3% of the mediated tokens (usually much less)

and apply to all transferred tokens, unless specified differently by the
user.

Changing Your Fee Schedule
--------------------------

As with all Raiden settings, you can get a short summary of the
available options by running ``raiden --help``:

.. code:: text

   $ raiden --help

   ...

   Mediation Fee Options:
     --flat-fee <ADDRESS INTEGER RANGE>...
           Sets the flat fee required for every mediation in wei of the mediated token
           for a certain token address. Must be bigger or equal to 0.
     --proportional-fee <ADDRESS INTEGER RANGE>...
           Mediation fee as ratio of mediated amount in parts-per-million (10^-6) for a
           certain token address. Must be in [0, 1000000].
     --proportional-imbalance-fee <ADDRESS INTEGER RANGE>...
           Set the worst-case imbalance fee relative to the channels capacity in
           parts-per-million (10^-6) for a certain token address. Must be in [0, 50000].
     --cap-mediation-fees / --no-cap-mediation-fees
           Cap the mediation fees to never get negative.  [default: True]

The first three parameters each set one of the three fee components.
Each parameter takes two values: a token address and a fee value. When
mediating a payment for the given token, the corresponding fee value
will be used. Here are some examples of fee parameters that could be
used for the DAI token:

``--flat-fee 0x6B175474E89094C44Da98b954EedeAC495271d0F 1000000000000000``

Ask for 1000000000000000/10^18 = 0.001 DAI per mediation

``--proportional-fee 0x6B175474E89094C44Da98b954EedeAC495271d0F 1000``

Ask for 1000/10^6 = 0.1% of the mediated tokens

``--proportional-imbalance-fee 0x6B175474E89094C44Da98b954EedeAC495271d0F 10000``

Apply *up to* 10000/10^6 = 1% of the mediated tokens as imbalance fee.
This fee will be positive when increasing imbalance and negative when
decreasing imbalance. It will usually stay far below this maximum value,
because the maximum applies only when the channel goes from perfectly
balanced to completely imbalanced due to a single payment.

Since imbalance fees can be negative to incentivize payments that
balance your channels, the sum of all three mediation fee components
could go negative, too. This can make sense, but it is counter-intuitive
for the mediating user and it might open up certain classes of attacks
against mediators. For these reasons, the total mediation fee per
mediator is capped to not go below zero by default. If you want to allow
the fee total to be negative, use the ``--no-cap-mediation-fees`` flag.

Frequently Asked Questions
--------------------------

Why Does the Target Receive More Tokens Than Expected?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

As noted in the "Calculation of Mediation Fees" section above, a small
safety margin is added on top of the mediation fees when initiating a
payment. This safety margin is only used by the mediators when the
channel balances change to the initiator's disadvantage immediately
before initiating the payment. So usually this margin is not or only
partially used up before reaching the payment target. The remainder
reaches the target along with the intended payment amount itself,
thereby slightly increasing the amount received by the target.

What does "Payment exceeded the maximum fee limit" mean?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Currently the Raiden client cancels payments that would require more
than 20% of the transferred amount in fee costs. This is the *maximum
fee limit.* As noted in "Default Fee Schedule", there are fees for both
the DAI and W-ETH token networks by default.

This means that the transferred amount has to be big enough, so that the
fees do not surpass 20% of the transferred amount. This results in the
following minimum amounts for the token networks when mediation is used:

-  DAI: Min. 0.00001 DAI (10^-5)
-  W-ETH: Min 0.0000001 W-ETH (10^-7)

As direct payments do not need mediation fees, this does not apply for
direct transfers.
