# -*- coding: utf-8 -*-
from typing import List, Dict, Union, Optional

from eth_utils import to_normalized_address, add_0x_prefix

from raiden.network.rpc.client import JSONRPCClient
from raiden.utils import (
    address_decoder,
    data_decoder,
    topic_decoder,
    topic_encoder,
    encode_hex,
)
from raiden.utils.typing import Address


class Filter:
    def __init__(self, jsonrpc_client: JSONRPCClient, filter_id_raw: int):
        self.filter_id_raw = filter_id_raw
        self.client = jsonrpc_client

    def changes(self) -> List[Dict]:
        changes = self.client.web3.eth.getFilterChanges(self.filter_id_raw)
        return decode_event_list(changes)

    def getall(self) -> List[Dict]:
        changes = self.client.web3.eth.getFilterLogs(self.filter_id_raw)
        return decode_event_list(changes)

    def uninstall(self):
        self.client.web3.eth.uninstallFilter(self.filter_id_raw)


def new_filter(
        jsonrpc_client: JSONRPCClient,
        contract_address: Address,
        topics: Optional[List[int]],
        from_block: Union[str, int] = 0,
        to_block: Union[str, int] = 'latest'
) -> Filter:
    """ Custom new filter implementation to handle bad encoding from geth rpc. """
    json_data = {
        'fromBlock': from_block,
        'toBlock': to_block,
        'address': to_normalized_address(contract_address),
    }

    if topics is not None:
        json_data['topics'] = [
            topic_encoder(topic)
            for topic in topics
        ]

    new_filter = jsonrpc_client.web3.eth.filter(json_data)
    return Filter(jsonrpc_client, new_filter.filter_id)


def decode_event(event: Dict) -> Dict:
    address = address_decoder(event['address'])
    data = data_decoder(event['data'])
    topics = [
        topic_decoder(add_0x_prefix(encode_hex(topic)))
        for topic in event['topics']
    ]
    block_number = event.get('blockNumber', 0)

    return dict(
        topics=topics,
        data=data,
        address=address,
        block_number=block_number,
        event_data=event
    )


def decode_event_list(events: List[Dict]) -> List[Dict]:
    if not events:
        return list()
    else:
        result = [
            decode_event(event) for event in events
        ]
        return result


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
        'address': to_normalized_address(contract_address),
    }

    if topics is not None:
        json_data['topics'] = [
            topic_encoder(topic)
            for topic in topics
        ]

    filter_changes = jsonrpc_client.web3.eth.getLogs(json_data)
    return decode_event_list(filter_changes)
