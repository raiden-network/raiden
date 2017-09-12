# -*- coding: utf8 -*-
from raiden.api.python import RaidenAPI


def get_channel_events_for_token(app, token_address, start_block=0):
    """ Collect all events from all channels for a given `token_address` and `app` """
    result = list()
    api = RaidenAPI(app.raiden)
    channels = api.get_channel_list(token_address=token_address)
    for channel in channels:
        events = api.get_channel_events(channel.channel_address, start_block)
        result.extend(events)
    return result
