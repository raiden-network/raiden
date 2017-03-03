# -*- coding: utf-8 -*-
from raiden.transfer.mediated_transfer.state_change import (
    ContractReceiveWithdraw,
)


class withdraw_statechange(netting_channel_address, event):
    """ Convert a ChannelSecretRevealed event to a ContractReceiveWithdraw
    state change.
    """
    state_change = ContractReceiveWithdraw(
        event['secret'],
        event['receiver'],
        netting_channel_address,
    )

    return state_change
