#!/usr/bin/env python

"""
This script is meant to be used as a template to step through a provided DB file
for debugging a specific issue.
It constructs the chain_state through the state_manager and uses the WAL
to replay all state changes through the state machines until all state changes are consumed.
The parameters (token_network_address and partner_address) will help filter out all
state changes until a channel is found with the provided token network address and partner.
The ignored state changes will still be applied, but they will just not be printed out.
"""
import json
import os
import re
from contextlib import closing
from itertools import chain

import click
from eth_utils import encode_hex, is_checksum_address, to_canonical_address

from raiden.storage.serialization import JSONSerializer
from raiden.storage.sqlite import RANGE_ALL_STATE_CHANGES, SerializedSQLiteStorage
from raiden.storage.wal import WriteAheadLog
from raiden.transfer import channel, node, views
from raiden.transfer.architecture import Event, StateChange, StateManager
from raiden.transfer.state import NetworkState
from raiden.utils import pex, to_checksum_address
from raiden.utils.typing import (
    Address,
    Any,
    ChannelID,
    Dict,
    Iterable,
    List,
    Nonce,
    Optional,
    SecretHash,
    TokenNetworkAddress,
    Tuple,
)


class Translator(dict):
    """ Dictionary class with re substitution capabilities. """

    def __init__(self, *args, **kwargs):
        kwargs = dict((k.lower(), v) for k, v in args[0].items())
        super().__init__(kwargs)
        self._extra_keys: Dict[str, str] = dict()
        self._regex = None
        self._make_regex()

    def _address_rxp(self, addr):
        """ Create a regex string for addresses, that matches several representations:
            - with(out) '0x' prefix
            - `pex` version
            This function takes care of maintaining additional lookup keys for substring matches.
            In case the given string is no address, it returns the original string.
        """
        try:
            addr = str(to_checksum_address(addr))
            rxp = "(?:0x)?" + pex(to_canonical_address(addr)) + f"(?:{addr.lower()[10:]})?"
            self._extra_keys[pex(to_canonical_address(addr))] = addr.lower()
            self._extra_keys[addr[2:].lower()] = addr.lower()
        except ValueError:
            rxp = addr
        return rxp

    def _make_regex(self):
        """ Compile rxp with all keys concatenated. """
        rxp = "|".join(map(self._address_rxp, self.keys()))
        self._regex = re.compile(rxp, re.IGNORECASE)

    def __setitem__(self, key, value):
        raise NotImplementedError(f"{self.__class__} must not dynamically modified")

    def __pop__(self, key):
        raise NotImplementedError(f"{self.__class__} must not dynamically modified")

    def __getitem__(self, key):
        try:
            return dict.__getitem__(self, key)
        except KeyError as e:
            alt = self._extra_keys.get(key)
            try:
                return dict.__getitem__(self, alt)
            except KeyError:
                # breakpoint()
                raise e

    def __call__(self, match):
        """ Lookup for each rxp match. """
        return "[{}]".format(self[match.group(0).lower()])

    def translate(self, text):
        """ Translate text. """
        return self._regex.sub(self, text)


def state_change_contains_secrethash(obj: Any, secrethash: SecretHash) -> bool:
    return (hasattr(obj, "secrethash") and obj.secrethash == secrethash) or (
        hasattr(obj, "transfer")
        and (
            (hasattr(obj.transfer, "secrethash") and obj.transfer.secrethash == secrethash)
            or (hasattr(obj.transfer, "lock") and obj.transfer.lock.secrethash == secrethash)
        )
    )


def state_change_with_nonce(
    obj: Any, nonce: Nonce, channel_identifier: ChannelID, sender: Address
) -> bool:
    return (
        hasattr(obj, "balance_proof")
        and obj.balance_proof.nonce == nonce
        and obj.balance_proof.channel_identifier == channel_identifier
        and obj.balance_proof.sender == to_canonical_address(sender)
    )


def print_attributes(data: Dict, translator: Optional[Translator] = None) -> None:
    if translator is None:
        trans = lambda s: s
    else:
        trans = translator.translate
    for key, value in data.items():
        if isinstance(value, bytes):
            value = encode_hex(value)

        click.echo("\t", nl=False)
        click.echo(click.style(key, fg="blue"), nl=False)
        click.echo(click.style("="), nl=False)
        click.echo(click.style(trans(repr(value)), fg="yellow"))


def print_state_change(state_change: StateChange, translator: Optional[Translator] = None) -> None:
    click.echo(click.style(f"> {state_change.__class__.__name__}", fg="red", bold=True))
    print_attributes(state_change.__dict__, translator=translator)


def print_events(events: Iterable[Event], translator: Optional[Translator] = None) -> None:
    for event in events:
        click.echo(click.style(f"< {event.__class__.__name__}", fg="green", bold=True))
        print_attributes(event.__dict__, translator=translator)


def print_presence_view(chain_state, translator: Optional[Translator] = None):
    if translator is None:
        trans = lambda s: s
    else:
        trans = translator.translate

    def network_state_to_color(network_state: NetworkState):
        if network_state == NetworkState.REACHABLE:
            return "green"
        if network_state == NetworkState.UNREACHABLE:
            return "red"
        if network_state == NetworkState.UNKNOWN:
            return "white"
        return None

    click.secho("Presence:", nl=False, fg="white")
    for k, v in chain_state.nodeaddresses_to_networkstates.items():
        click.secho(f" {trans(pex(k))}", fg=network_state_to_color(v), nl=False)
    click.echo("", nl=True)


def get_node_balances(chain_state, token_network_address: TokenNetworkAddress) -> List[Tuple[Any]]:
    channels = views.list_all_channelstate(chain_state)
    channels = [
        channel
        for channel in channels
        if channel.canonical_identifier.token_network_address
        == to_canonical_address(token_network_address)
    ]
    balances = [
        (
            channel_state.partner_state.address,
            channel.get_balance(channel_state.our_state, channel_state.partner_state),
            channel.get_balance(channel_state.partner_state, channel_state.our_state),
        )
        for channel_state in channels
    ]
    return balances


def print_node_balances(
    chain_state,
    token_network_address: TokenNetworkAddress,
    translator: Optional[Translator] = None,
):
    if translator is None:
        trans = lambda s: s
    else:
        trans = translator.translate
    balances = get_node_balances(chain_state, token_network_address)
    for balance in balances:
        click.secho(f"{trans(pex(balance[0]))} ->{balance[1]} <-{balance[2]}", fg="blue")
    click.secho(f"Sum {trans(pex(chain_state.our_address))}: {sum(b[1] for b in balances)}")


def print_nl():
    click.echo("-" * os.get_terminal_size()[0], nl=True)


def replay_wal(
    storage: SerializedSQLiteStorage,
    token_network_address: TokenNetworkAddress,
    partner_address: Address,
    translator: Optional[Translator] = None,
) -> None:
    all_state_changes = storage.get_statechanges_by_range(RANGE_ALL_STATE_CHANGES)

    state_manager = StateManager(state_transition=node.state_transition, current_state=None)
    wal = WriteAheadLog(state_manager, storage)

    for _, state_change in enumerate(all_state_changes):
        # Dispatching the state changes one-by-one to easy debugging
        _, events = wal.state_manager.dispatch([state_change])

        chain_state = wal.state_manager.current_state
        msg = "Chain state must never be cleared up."
        assert chain_state, msg

        channel_state = views.get_channelstate_by_token_network_and_partner(
            chain_state,
            to_canonical_address(token_network_address),
            to_canonical_address(partner_address),
        )

        if channel_state is None:
            continue

        ###
        # Customize this to filter things further somewhere around here.
        # An example would be to add `import pdb; pdb.set_trace()`
        # and inspect the state.
        ###
        print_state_change(state_change, translator=translator)
        print_events(chain.from_iterable(events), translator=translator)

        # Enable to print color coded presence state of channel partners
        # print_presence_view(chain_state, translator)

        # Enable to print balances & balance sum with all channel partners
        # print_node_balances(chain_state, token_network_address, translator)

        print_nl()


@click.command(help=__doc__)
@click.argument("db-file", type=click.Path(exists=True))
@click.argument("token-network-address")
@click.argument("partner-address")
@click.option(
    "-x",
    "--names-translator",
    type=click.File(),
    help="A JSON file with replacement rules, e.g.:  "
    '\'{ "0xb4f44cd22a84DE0774B802e422D4c26A73Dd68d7": "Bob", '
    '"identifier": "XXX" }\' would replace all instances of the address (pex\'ed, lowercase, '
    'checksummed) with "[Bob]" and all mentions of "identifier" with "[XXX]. '
    'It also allows you to use "Bob" as parameter value for "-n" and "-p" switches.',
)
def main(db_file, token_network_address, partner_address, names_translator):
    translator: Optional[Translator]

    if names_translator:
        translator = Translator(json.load(names_translator))
        lookup = {v: k for k, v in translator.items()}
        token_network_address = lookup.get(token_network_address, token_network_address)
        partner_address = lookup.get(partner_address, partner_address)
    else:
        translator = None

    assert is_checksum_address(token_network_address), "token_network_address must be provided"
    assert is_checksum_address(partner_address), "partner_address must be provided"

    with closing(SerializedSQLiteStorage(db_file, JSONSerializer())) as storage:
        replay_wal(
            storage=storage,
            token_network_address=token_network_address,
            partner_address=partner_address,
            translator=translator,
        )


if __name__ == "__main__":
    main()  # pylint: disable=no-value-for-parameter
