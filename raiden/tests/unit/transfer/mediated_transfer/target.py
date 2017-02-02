# -*- coding: utf-8 -*-


def test_transfer_succesful_after_secret_learned():
    # TransferCompleted event must be used only after the secret is learned and
    # there is enough time to unlock the lock on chain.
    #
    # A mediated transfer might be received during the settlement period of the
    # current channel, the secret request is sent to the initiator and at time
    # the secret is revealed there might not be enough time to safely unlock
    # the asset on-chain.
    pass
