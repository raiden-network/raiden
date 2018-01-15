# -*- coding: utf-8 -*-
from ethereum.utils import normalize_address

from raiden.utils import (
    address_decoder,
    address_encoder,
    data_decoder,
    topic_decoder,
    topic_encoder,
)


def new_filter(jsonrpc_client, contract_address, topics, from_block=None, to_block=None):
    """ Custom new filter implementation to handle bad encoding from geth rpc. """
    if isinstance(from_block, int):
        from_block = hex(from_block)

    if isinstance(to_block, int):
        to_block = hex(to_block)

    json_data = {
        'fromBlock': from_block or hex(0),
        'toBlock': to_block or 'latest',
        'address': address_encoder(normalize_address(contract_address)),
    }

    if topics is not None:
        json_data['topics'] = [
            topic_encoder(topic)
            for topic in topics
        ]

    return jsonrpc_client.call('eth_newFilter', json_data)


def get_filter_events(jsonrpc_client, contract_address, topics, from_block=None, to_block=None):
    """ Get filter.

    This handles bad encoding from geth rpc.
    """
    if isinstance(from_block, int):
        from_block = hex(from_block)

    if isinstance(to_block, int):
        to_block = hex(to_block)

    json_data = {
        'fromBlock': from_block or hex(0),
        'toBlock': to_block or 'latest',
        'address': address_encoder(normalize_address(contract_address)),
    }

    if topics is not None:
        json_data['topics'] = [
            topic_encoder(topic)
            for topic in topics
        ]

    filter_changes = jsonrpc_client.call('eth_getLogs', json_data)

    # geth could return None
    if filter_changes is None:
        return []

    result = []
    for log_event in filter_changes:
        address = address_decoder(log_event['address'])
        data = data_decoder(log_event['data'])
        topics = [
            topic_decoder(topic)
            for topic in log_event['topics']
        ]
        block_number = log_event.get('blockNumber')
        if not block_number:
            block_number = 0
        else:
            block_number = int(block_number, 0)

        result.append({
            'topics': topics,
            'data': data,
            'address': address,
            'block_number': block_number,
        })

    return result


class Filter:
    def __init__(self, jsonrpc_client, filter_id_raw):
        self.filter_id_raw = filter_id_raw
        self.client = jsonrpc_client

    def _query_filter(self, function):
        filter_changes = self.client.call(function, self.filter_id_raw)

        # geth could return None
        if filter_changes is None:
            return []

        result = list()
        for log_event in filter_changes:
            address = address_decoder(log_event['address'])
            data = data_decoder(log_event['data'])
            topics = [
                topic_decoder(topic)
                for topic in log_event['topics']
            ]
            block_number = log_event.get('blockNumber')
            if not block_number:
                block_number = 0
            else:
                block_number = int(block_number, 0)

            result.append({
                'topics': topics,
                'data': data,
                'address': address,
                'block_number': block_number,
            })

        return result

    def changes(self):
        return self._query_filter('eth_getFilterChanges')

    def getall(self):
        return self._query_filter('eth_getFilterLogs')

    def uninstall(self):
        self.client.call('eth_uninstallFilter', self.filter_id_raw)
