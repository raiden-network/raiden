# -*- coding: utf8 -*-
from ethereum import slogging
from ethereum.abi import event_id, normalize_name

log = slogging.getLogger(__name__)  # pylint: disable=invalid-name


def get_event(full_abi, event_name):
    for description in full_abi:
        normalized_name = normalize_name(description['name'])

        if normalized_name == event_name:
            return description


def get_eventname_types(event_description):
    name = normalize_name(event_description['name'])
    encode_types = [
        element['type']
        for element in event_description['inputs']
    ]
    return name, encode_types


def new_filter(jsonrpc_client, contract_address_bin, topics):
    filter_ = {
        'fromBlock': 'latest',
        'toBlock': 'latest',
        'address': contract_address_bin.encode('hex'),
        'topics': topics,
    }

    filter_id = jsonrpc_client.call('eth_newFilter', filter_)
    return filter_id


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

    node_address_hex = node_address_bin.encode('hex')
    topics = [
        [eventid, node_address_hex, None],
        [eventid, None, node_address_hex],
    ]

    filter_id = new_filter(jsonrpc_client, channel_manager_address_bin, topics)
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
    filter_id = new_filter(jsonrpc_client, netting_contract_address_bin, topics)
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
        if filter_id not in contract_translator.event_data:
            raise ValueError('`contract_translator` cannot decode the given `event_id`')

        self.callback = callback
        self.filter_id = filter_id
        self.contract_translator = contract_translator

    def listen(self, event_raw):

        topics = event_raw['topics']
        data = event_raw['data'].decode('hex')

        originating_contract = event_raw['address'].decode('hex')
        event = self.contract_translator.decode_event(topics, data)

        if event is not None:
            self.callback(originating_contract, event)


class ContractEventListen(EventListener):  # pylint: disable=too-few-public-methods
    def listen(self, event_raw):
        topics = event_raw['topics']
        data = event_raw['data'].decode('hex')

        event = self.contract_translator.decode_event(topics, data)

        if event is not None:
            if event['_event_name'] == 'ChannelOpened':
                pass

            if event['_event_name'] == 'ChannelClosed':
                pass

            if event['_event_name'] == 'ChannelSettled':
                pass

            if event['_event_name'] == 'ChannelSecretRevealed':
                pass

            self.callback(
                event['participant1'].decode('hex'),
                event['participant2'].decode('hex'),
            )
