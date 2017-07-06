"""Helpers for events and event-debugging.
"""
from ethereum.abi import ContractTranslator
from ethereum.utils import normalize_address
from pyethapp.jsonrpc import address_encoder, data_decoder
from pyethapp.rpc_client import ContractProxy

from raiden.network.rpc.client import decode_topic

__all__ = (
    "all_contract_events_raw",
    "all_contract_events",
    "proxy_contract_events",
    "netting_channel_events",
)


def all_contract_events_raw(rpc, contract_address, start_block=None, end_block=None):
    """Find all events for a deployed contract given its `contract_address`.

    Args:
        rpc (pyethapp.rpc_client.JSONRPCClient): client instance.
        contract_address (string): hex encoded contract address.
        start_block (int): read event-logs starting from this block number.
        end_block (int): read event-logs up to this block number.
    Returns:
        events (list)
    """
    return rpc.call('eth_getLogs', {
        'fromBlock': str(start_block or 0),
        'toBlock': str(end_block or 'latest'),
        'address': address_encoder(normalize_address(contract_address)),
        'topics': [],
    })


def all_contract_events(rpc, contract_address, abi, start_block=None, end_block=None):
    """Find and decode all events for a deployed contract given its `contract_address` and `abi`.

    Args:
        rpc (pyethapp.rpc_client.JSONRPCClient): client instance.
        contract_address (string): hex encoded contract address.
        abi (list(dict)): the contract's ABI.
        start_block (int): read event-logs starting from this block number.
        end_block (int): read event-logs up to this block number.
    Returns:
        events (list)
    """

    translator = ContractTranslator(abi)

    events_raw = all_contract_events_raw(
        rpc,
        contract_address,
        start_block=start_block,
        end_block=end_block,
    )

    events = list()
    for event_encoded in events_raw:
        topics_ids = [
            decode_topic(topic)
            for topic in event_encoded['topics']
        ]
        event_data = data_decoder(event_encoded['data'])

        event = translator.decode_event(topics_ids, event_data)
        events.append(event)
    return events


def proxy_contract_events(rpc, proxy, start_block=None, end_block=None):
    """Find and decode all events for a deployed contract given its ContractProxy.

    Args:
        rpc (pyethapp.rpc_client.JSONRPCClient): client instance.
        proxy (pyethapp.rpc_client.ContractProxy): the contract proxy instance.
        start_block (int): read event-logs starting from this block number.
        end_block (int): read event-logs up to this block number.
    Returns:
        events (list)
    """
    assert isinstance(proxy, ContractProxy), "can only process pyethapp.rpc_client.ContractProxy"
    return all_contract_events(
        rpc,
        proxy.address.encode('hex'),
        proxy.abi,
        start_block=start_block,
        end_block=end_block,
    )


def netting_channel_events(rpc, netting_channel, end_block=None):
    """Get all events for a netting_channel starting from its `opened()` block.
    Args:
        rpc (pyethapp.rpc_client.JSONRPCClient): client instance.
        netting_channel (raiden.network.rpc.client.NettingChannel): the NettingChannel instance.
        end_block (int): read event-logs up to this block number (default: 'latest').
    """
    return proxy_contract_events(
        rpc,
        netting_channel.proxy,
        start_block=netting_channel.opened(),
        end_block=end_block or 'latest',
    )
