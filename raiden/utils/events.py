"""Helpers for events and event-debugging.
"""
from typing import List, Dict, Union

from ethereum.abi import ContractTranslator
from ethereum.utils import normalize_address

from raiden.blockchain.abi import (
    CONTRACT_MANAGER,
    CONTRACT_NETTING_CHANNEL,
)
from raiden.utils import address_encoder, data_decoder, topic_decoder
from raiden.network.rpc.client import JSONRPCClient
from raiden.network.proxies.netting_channel import NettingChannel


def all_contract_events_raw(
        rpc: JSONRPCClient,
        contract_address: str,
        start_block: Union[str, int] = 0,
        end_block: Union[str, int] = 'latest') -> List[Dict]:
    """Find all events for a deployed contract given its `contract_address`.

    Args:
        rpc: client instance.
        contract_address: hex encoded contract address.
        start_block: read event-logs starting from this block number (default: 0).
        end_block: read event-logs up to this block number (default: 'latest').
    Returns:
        events
    """
    return rpc.call('eth_getLogs', {
        'fromBlock': str(start_block),
        'toBlock': str(end_block),
        'address': address_encoder(normalize_address(contract_address)),
        'topics': [],
    })


def all_contract_events(
        rpc: JSONRPCClient,
        contract_address: str,
        abi,
        start_block: Union[str, int] = 0,
        end_block: Union[str, int] = 'latest') -> List[Dict]:
    """Find and decode all events for a deployed contract given its `contract_address` and `abi`.

    Args:
        rpc: client instance.
        contract_address: hex encoded contract address.
        abi: the contract's ABI.
        start_block: read event-logs starting from this block number (default: 0).
        end_block: read event-logs up to this block number (default: 'latest').
    Returns:
        A list of all events from the given contract.
    """

    translator = ContractTranslator(abi)

    events_raw = all_contract_events_raw(
        rpc,
        contract_address,
        start_block=start_block,
        end_block=end_block
    )

    events = list()
    for event_encoded in events_raw:
        topics_ids = [
            topic_decoder(topic)
            for topic in event_encoded['topics']
        ]
        event_data = data_decoder(event_encoded['data'])

        event = translator.decode_event(topics_ids, event_data)
        events.append(event)
    return events


def netting_channel_events(
        rpc: JSONRPCClient,
        netting_channel: NettingChannel,
        end_block: Union[str, int] = 'latest') -> List[Dict]:
    """Get all events for a netting_channel starting from its `opened()` block.
    Args:
        rpc: client instance.
        netting_channel: the NettingChannel instance.
        end_block: read event-logs up to this block number (default: 'latest').
    """
    return all_contract_events(
        rpc,
        netting_channel.address,
        CONTRACT_MANAGER.get_translator(CONTRACT_NETTING_CHANNEL),
        start_block=netting_channel.opened(),
        end_block=end_block
    )
