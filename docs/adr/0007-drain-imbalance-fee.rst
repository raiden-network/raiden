Risk of draining funds through imbalance fees
=============================================

Summary
-------

When a channel is opened, it is imbalanced according to the default
imbalance fee settings. This means that when two channels are freshly
opened and I mediate a payment through those, I will pay for the
improved state of those channels. If the other participants collude,
they can keep the negative fees and close the channel afterwards, so
that I paid without actually being able to benefit from the new channel
state.

Prerequisites
-------------

-  Imbalance fees are turned on for the mediator
-  The mediator must have opened (and deposited to) a channel.
   Otherwise, there would not be sufficient capacity to mediate.
-  Channel partners must be willing to close the channel when it is in a
   balanced state. Otherwise it is not an attack, but the intended
   result of incentivizing channel balancing.

Value at risk
-------------

When the mediator deposited :math:`d` and has the proportional imbalance
fee setting of :math:`i_p` the channel partner can collude with an
attacker who opens a channel to the mediator and initiates a payment
with the amount :math:`a`. To receive the highest negative fee, he would
choose :math:`a=\frac{d}{2}`. In that case the mediator pays

.. math::

   i_{abs} = -2d \cdot i_p

as imbalance fees, because fees apply for both channels. If flat or
proportional are set, the paid amount will be lower

.. math::

   \begin{split}
   \mathit{fees} &= f + pa - 2d \cdot i_p \\
   &= f + \frac{pd}{2} - 2d \cdot i_p \\
   &= f + d\left(\frac{p}{2} - 2i_p\right)
   \end{split}

Costs for the attacker
----------------------

An attacker has to pay for at least four transactions:

-  open channel to the mediator
-  deposit
-  close the new channel
-  settle channel

These have a total gas cost of

.. math::

   97745 + 92392 + 124114 + 108518 = 422769

which at the current gas costs amounts to

.. math::


   422769 \,gas \cdot 1 \,gwei \cdot = 0.0004228 \,ETH = $0.07272

If these exceed the earned fees, the attack is not profitable. If the
mediator has high proportional fees, lowering the payment amount might
make sense to only act on the steepest part of the IP curve.

Results for default settings
----------------------------

The default settings are :math:`i_p = 0.3%` and :math:`p = 0.4%` and
flat fees are turned off. For :math:`a = \frac{d}{2}` this results in
mediation fees of

.. math::


   d\left(\frac{0.4\%}{2} - 2 \cdot 0.3\right) = d \cdot -0.4\%

The worst case will happen with lower amounts (due to decreased
proportional fees and the flatness of the IP function near the middle)
and is between :math:`0.04\%` and :math:`0.06\%`.

Possible conclusions
--------------------

Working as intended
~~~~~~~~~~~~~~~~~~~

If I don’t mediate (e.g. light clients) or don’t open channels myself,
I’m not at risk at all. If I open a channel to another node that is
interested in mediating, that node won’t close the channel and
everything is working as intended. If a node closes a channel after it
is balanced, I can avoid being scammed again by not depositing into any
channels to the same node.

However, it is very hard to judge what kind of similar attacks can be
done when balances change through mediation and deposits/withdraws.

Disable negative total fees (chosen solution)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

An obvious way to avoid all such problems would be to not do negative
fees. The imbalance fee component could still be negative and cancel out
other fee components, but the total will not go below zero. This could
be done as a config setting, so that people willing to mediate with
negative fees could still do that and gather real world experience on
it.

Skip negative imbalance fees on new channels
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When another party opens a channel to me, I could refuse to pay any
balancing incentives until the channel has been balanced once. This
would mitigate the problem while not impacting balancing on long lived
channels. The details should be a bit more sophisticated and play well
with deposits/withdraws.
