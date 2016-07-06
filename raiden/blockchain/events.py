# -*- coding: utf8 -*-
from ethereum import slogging
from pyethapp.jsonrpc import address_decoder, data_decoder

log = slogging.getLogger(__name__)  # pylint: disable=invalid-name


def decode_topic(topic):
    return int(topic[2:], 16)


def channelnew_filter(channel_manager_address_bin, node_address_bin, event_id, jsonrpc_client):
    """ Create a filter for new channels.

    Args:
        channel_manager_address_bin (bin): The deployed channel manager contract address.
        node_address_bin (bin): The node's address that we are listening for new channels.
        event_id (int): The event id.
        jsonrpc_client (pyethapp.rpc_client.JSONRPCClient): json rpc client.

    Return:
        int: The new filter id.
    """
    # node_address_hex = node_address_bin.encode('hex')
    # topics = [
    #     event_id, [node_address_hex, None], [None, node_address_hex],
    # ]
    topics = [event_id]

    filter_id = jsonrpc_client.new_filter(
        address=channel_manager_address_bin,
        topics=topics,
    )
    return filter_id


def channel_events_filter(netting_contract_address_bin, event_id, jsonrpc_client):
    """ Create a filter for all the netting contract events.

    Args:
        netting_contract_address_bin (bin): The deployed netting contract address.
        event_id (int): The event id.
        jsonrpc_client (pyethapp.rpc_client.JSONRPCClient): json rpc client.

    Return:
        int: The new filter id.
    """
    topics = []

    filter_id = jsonrpc_client.new_filter(
        address=netting_contract_address_bin,
        topics=topics,
    )
    return filter_id


class EventListener(object):  # pylint: disable=too-few-public-methods
    def __init__(self, contract_translator, callback, filter_id):
        """ Listener for ChannelNew events.

        Decodes the raw event data and calls `callback`.

        Args:
            contract_translator (ethereum.abi.ContractTranslator): A contract
                translator that can decode a ChannelNew event.
            callback (Function[(address, address)]): Callback function that
                will the parsed event.
            filter_id (int): The installed filter id.
        """
        self.callback = callback
        self.filter_id = filter_id
        self.contract_translator = contract_translator

    def listen(self, event_raw):
        topics = [
            decode_topic(topic)
            for topic in event_raw['topics']
        ]
        data = data_decoder(event_raw['data'])

        originating_contract = address_decoder(event_raw['address'])
        event = self.contract_translator.decode_event(topics, data)

        if event is not None:
            self.callback(originating_contract, event)


class ContractEventListener(EventListener):  # pylint: disable=too-few-public-methods
    def listen(self, event_raw):
        topics = [
            decode_topic(topic)
            for topic in event_raw['topics']
        ]
        data = data_decoder(event_raw['data'])

        event = self.contract_translator.decode_event(topics, data)

        if event is not None:
            if event['_event_type'] == 'ChannelOpened':
                pass

            if event['_event_type'] == 'ChannelClosed':
                pass

            if event['_event_type'] == 'ChannelSettled':
                pass

            if event['_event_type'] == 'ChannelSecretRevealed':
                pass

            self.callback(
                event['participant1'].decode('hex'),
                event['participant2'].decode('hex'),
            )
