Raiden Glossary
===============

.. glossary::
   :sorted:

   payer
       In a channel relationship between two raiden nodes the payer is the participant who sends a transfer.

   payee
       In a channel relationship between two raiden nodes the payee is the participant who receives a transfer

   initiator
       In a mediated transfer the initiator of the transfer is the raiden node which starts the transfer

   target
       In a mediated transfer the target is the raiden node for which the transfer sent by the initiator is intended

   DirectTransfer
       A direct transfer is a non-locked transfer, which means a transfer that does not rely on a lock to complete. Once they are sent they should be considered as completed.

   MediatedTransfer
       A mediated transfer is a hashlocked transfer between an initiator and a target propagated through nodes in the network.

   RefundTransfer
       A refund transfer is a special type of MediatedTransfer that is used when a node can no longer propagate a transfer and a routing backtrack needs to be done.

   reveal_timeout
       The number of blocks in a channel allowed for learning about a secret being reveal through the blockchain and acting on it.
       
