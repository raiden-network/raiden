# -*- coding: utf-8 -*-
from typing import List, Dict, Union, Optional

from eth_utils import to_canonical_address, add_0x_prefix

from raiden.network.rpc.client import JSONRPCClient
from raiden.utils import (
    address_decoder,
    address_encoder,
    data_decoder,
    topic_decoder,
    topic_encoder,
    encode_hex,
)
from raiden.utils.typing import Address


def new_filter(
        jsonrpc_client: JSONRPCClient,
        contract_address: Address,
        topics: Optional[List[int]],
        from_block: Union[str, int] = 0,
        to_block: Union[str, int] = 'latest'):
    """ Custom new filter implementation to handle bad encoding from geth rpc. """
    json_data = {
        'fromBlock': from_block,
        'toBlock': to_block,
        'address': address_encoder(to_canonical_address(contract_address)),
    }

    if topics is not None:
        json_data['topics'] = [
            topic_encoder(topic)
            for topic in topics
        ]

    new_filter = jsonrpc_client.web3.eth.filter(json_data)
    return new_filter.filter_id


def get_filter_events(
        jsonrpc_client: JSONRPCClient,
        contract_address: Address,
        topics: Optional[List[int]],
        from_block: Union[str, int] = 0,
        to_block: Union[str, int] = 'latest') -> List[Dict]:
    """ Get filter.

    This handles bad encoding from geth rpc.
    """
    json_data = {
        'fromBlock': from_block,
        'toBlock': to_block,
        'address': address_encoder(to_canonical_address(contract_address)),
    }

    if topics is not None:
        json_data['topics'] = [
            topic_encoder(topic)
            for topic in topics
        ]

    filter_changes = jsonrpc_client.web3.eth.getLogs(json_data)

    # geth could return None
    if filter_changes is None:
        return []

    result = []
    for log_event in filter_changes:
        address = address_decoder(log_event['address'])
        data = data_decoder(log_event['data'])
        topics = [
            topic_decoder(add_0x_prefix(encode_hex(topic)))
            for topic in log_event['topics']
        ]
        block_number = log_event.get('blockNumber', 0)

        result.append({
            'topics': topics,
            'data': data,
            'address': address,
            'block_number': block_number,
            'event_data': log_event
        })

    return result


class Filter:
    def __init__(self, jsonrpc_client: JSONRPCClient, filter_id_raw: int):
        self.filter_id_raw = filter_id_raw
        self.client = jsonrpc_client

    def _process_filter_results(self, filter_changes: List) -> List[Dict]:
        # geth could return None
        if filter_changes is None:
            return []

        result = list()
        for log_event in filter_changes:
            address = address_decoder(log_event['address'])
            data = data_decoder(log_event['data'])
            topics = [
                topic_decoder(add_0x_prefix(encode_hex(topic)))
                for topic in log_event['topics']
            ]
            block_number = log_event.get('blockNumber')

            result.append({
                'topics': topics,
                'data': data,
                'address': address,
                'block_number': block_number,
                'event_data': log_event
            })

        return result

    def changes(self) -> List[Dict]:
        changes = self.client.web3.eth.getFilterChanges(self.filter_id_raw)
        return self._process_filter_results(changes)

    def getall(self) -> List[Dict]:
        changes = self.client.web3.eth.getFilterChanges(self.filter_id_raw)
        return self._process_filter_results(changes)

    def uninstall(self):
        self.client.web3.eth.uninstallFilter(self.filter_id_raw)
