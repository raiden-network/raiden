Raiden Glossary
===============

Payments and Transfers
----------------------

.. glossary::
    :sorted:

    MediatedTransfer
        A mediated transfer is a hashlocked transfer between an initiator and a target propagated through nodes in the network.

    Reveal timeout
        The number of blocks in a channel allowed for learning about a secret being revealed through the blockchain and acting on it.

    Payment channel
        The on-chain payment channel between two Raiden nodes.

    Settlement timeout
    Settlement window
        The number of blocks after the closing of a channel within which the :term:`counterparty` is able to call ``updateNonClosingBalanceProof`` with the latest :term:`balance proof` they received.

    Merkletree root
    Locksroot
        The root of the ``merkle tree`` which holds the hashes of all the locks in the channel.

    Transfer
        A transfer in Raiden happens each time tokens are sent inside a :term:`payment channel`.

    Payment
        A payment in Raiden is the process of sending tokens from one account to another. Each payment has an :term:`initiator` and a :term:`target` and can be composed of multiple transfers.

    Transferred amount
        The transferred amount is the total amount of tokens sent from a participant's account to the account of a :term:`counterparty`.

    Locked amount
        The locked amount is the total amount of tokens one participant of a payment channel has locked in pending transfers towards his :term:`counterparty`

    Channel capacity
        The channel capacity determines how many tokens a channel holds. You can calculate the capacity by either:

        * Taking the total amount of tokens deposited and subtracting the total amount of tokens withdrawn by both participants that have a channel open with each other.
        * Taking the sum of both channel participants' :term:`balance`.

    Balance
        The balance determines how many tokens one specific channel participant holds.

        You can calculate the balance by taking the total amount of tokens deposited, adding the total amount of tokens received and subtracting the total amount of tokens sent for a participant.

        :math:`B_{participant} = P_{total\ token\ deposit} + P_{total\ tokens\ received} - P_{total\ tokens\ sent}`

    Locked balance
        The locked balance of a channel participant is the sum of the locked amount for all pending transfers :math:`T_{pending}`.

        :math:`B_{locked} = \sum_{k=0}^{N-1} T_{pending}` where :math:`N` is the number of pending transfers

    Available balance
        The available balance of a channel participant is:

        :math:`B_{available} = B_{participant} - B_{locked}`

    Balance proof
        Balance proof is any kind of message used in order to cryptographically prove on the blockchain what the latest :term:`transferred amount` and :term:`locked amount` received from a counterparty is.

    Hashlock
        A hashlock is the hashed secret that accompanies a locked message: ``sha3(secret)``.

    Lock expiration
        The lock expiration is the highest ``block_number`` until which the transfer can be settled.

    SecretRequest
        The secret request message is sent by the target of a mediated transfer to its initiator in order to request the secret to unlock the transfer.

    RevealSecret
        The reveal secret message is sent to a node that is known to have an interest to learn the secret.

    Secret message
        The secret message is a message containing the secret and used for synchronization between mediated transfer participants.

    Preimage
    Secret
        The preimage, what we call the secret in Raiden, is 32 bytes of random cryptographically secure data whose keccak hash ends up being the :term:`hashlock`.


Participants
------------

Overview of a payment with one mediator:

.. code:: text

                 Transfer1               Transfer2
    [Initiator] -----------> [Mediator] -----------> [Target]
                Payer  Payee            Payer  Payee

.. glossary::
    :sorted:

    Counterparty
        The counterparty of a channel is the other channel participant with whom you have opened a channel.

    Initiator
        The initiator is the Raiden node which initiates (starts) a :term:`payment`.

    Payer
        The payer is the participant who sends a :term:`transfer`.

    Payee
        The payee is the participant who receives a :term:`transfer`.

    Target
        The target is the Raiden node which receives a payment from the :term:`initiator`.

Services
--------

.. glossary::
    :sorted:

    User Deposit
        The Raiden services will ask for payment in RDN. The Monitoring Service and the Pathfinding Service require deposits to be made in advance of service usage. These deposits are handled by the User Deposit Contract.
