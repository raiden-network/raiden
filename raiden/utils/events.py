"""Helpers for events and event-debugging.
"""
from typing import List, Dict, Union

from eth_utils import to_canonical_address, to_checksum_address

from raiden.blockchain.abi import (
    CONTRACT_MANAGER,
    CONTRACT_NETTING_CHANNEL,
)
from raiden.utils import address_encoder, data_decoder, topic_decoder
from raiden.network.rpc.client import JSONRPCClient
from raiden.network.proxies.netting_channel import NettingChannel
from raiden.network.rpc.smartcontract_proxy import ContractProxy


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
    return rpc.web3.eth.getLogs({
        'fromBlock': start_block,
        'toBlock': end_block,
        'address': to_checksum_address(contract_address),
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

    events_raw = all_contract_events_raw(
        rpc,
        contract_address,
        start_block=start_block,
        end_block=end_block
    )

    events = list()
    for event_encoded in events_raw:
        event = ContractProxy.decode_event(abi, event_encoded)
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
