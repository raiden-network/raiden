"""
This script is meant to be used as a template to step through a provided DB file
for debugging a specific issue.
It constructs the chain_state through the state_manager and uses the WAL
to replay all state changes through the state machines until all state changes are consumed.
The parameters (token_network_identifier and partner_address) will help filter out all
state changes until a channel is found with the provided token network address and partner.
The ignored state changes will still be applied, but they will just not be printed out.
"""
import json
import re

import click
from eth_utils import encode_hex, to_canonical_address

from raiden.storage import serialize, sqlite
from raiden.storage.wal import WriteAheadLog
from raiden.transfer import node, views
from raiden.transfer.architecture import StateManager
from raiden.utils import address_checksum_and_decode, pex, to_checksum_address


def state_change_contains_secrethash(obj, secrethash):
    return (
        (hasattr(obj, 'secrethash') and obj.secrethash == secrethash) or
        (hasattr(obj, 'transfer') and (
            (
                hasattr(obj.transfer, 'secrethash') and obj.transfer.secrethash == secrethash
            ) or (
                hasattr(obj.transfer, 'lock') and obj.transfer.lock.secrethash == secrethash
            )
        ))
    )


def state_change_with_nonce(obj, nonce, channel_identifier, sender):
    return (
        hasattr(obj, 'balance_proof') and
        obj.balance_proof.nonce == nonce and
        obj.balance_proof.channel_identifier == channel_identifier and
        obj.balance_proof.sender == to_canonical_address(sender)
    )


def print_attributes(data, translator=None):
    if translator is None:
        trans = lambda s: s
    else:
        trans = translator.translate
    for key, value in data.items():
        if isinstance(value, bytes):
            value = encode_hex(value)

        click.echo('\t', nl=False)
        click.echo(click.style(key, fg='blue'), nl=False)
        click.echo(click.style('='), nl=False)
        click.echo(click.style(trans(repr(value)), fg='yellow'))


def print_state_change(state_change, translator=None):
    click.echo(click.style(f'> {state_change.__class__.__name__}', fg='red', bold=True))
    print_attributes(state_change.__dict__, translator=translator)


def print_events(events, translator=None):
    for event in events:
        click.echo(click.style(f'< {event.__class__.__name__}', fg='green', bold=True))
        print_attributes(event.__dict__, translator=translator)


class Translator(dict):
    """ Dictionary class with re substitution capabilities. """

    def __init__(self, *args, **kwargs):
        kwargs = dict((k.lower(), v) for k, v in args[0].items())
        super().__init__(kwargs)
        self._extra_keys = dict()
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
            addr = to_checksum_address(addr)
            rxp = '(?:0x)?' + pex(address_checksum_and_decode(addr)) + f'(?:{addr.lower()[10:]})?'
            self._extra_keys[pex(address_checksum_and_decode(addr))] = addr.lower()
            self._extra_keys[addr[2:].lower()] = addr.lower()
        except ValueError:
            rxp = addr
        return rxp

    def _make_regex(self):
        """ Compile rxp with all keys concatenated. """
        rxp = "|".join(
            map(self._address_rxp, self.keys()),
        )
        self._regex = re.compile(
            rxp,
            re.IGNORECASE,
        )

    def __setitem__(self, key, value):
        raise NotImplementedError(f'{self.__class__} must not dynamically modified')

    def __pop__(self, key):
        raise NotImplementedError(f'{self.__class__} must not dynamically modified')

    def __getitem__(self, key):
        try:
            return dict.__getitem__(self, key)
        except KeyError as e:
            alt = self._extra_keys.get(key)
            try:
                return dict.__getitem__(self, alt)
            except KeyError:
                import pdb
                pdb.set_trace()
                raise e

    def __call__(self, match):
        """ Lookup for each rxp match. """
        return '[{}]'.format(self[match.group(0).lower()])

    def translate(self, text):
        """ Translate text. """
        return self._regex.sub(self, text)


def replay_wal(storage, token_network_identifier, partner_address, translator=None):
    all_state_changes = storage.get_statechanges_by_identifier(
        from_identifier=0,
        to_identifier='latest',
    )

    state_manager = StateManager(state_transition=node.state_transition, current_state=None)
    wal = WriteAheadLog(state_manager, storage)

    for _, state_change in enumerate(all_state_changes):
        events = wal.state_manager.dispatch(state_change)

        chain_state = wal.state_manager.current_state

        channel_state = views.get_channelstate_by_token_network_and_partner(
            chain_state,
            to_canonical_address(token_network_identifier),
            to_canonical_address(partner_address),
        )

        if not channel_state:
            continue

        ###
        # Customize this to filter things further somewhere around here.
        # An example would be to add `import pdb; pdb.set_trace()`
        # and inspect the state.
        ###

        print_state_change(state_change, translator=translator)
        print_events(events, translator=translator)


@click.command(help=__doc__)
@click.argument(
    'db-file',
    type=click.Path(exists=True),
)
@click.argument(
    'token-network-identifier',
)
@click.argument(
    'partner-address',
)
@click.option(
    '-x',
    '--names-translator',
    type=click.File(),
    help='A JSON file with replacement rules, e.g.:  '
    '\'{ "0xb4f44cd22a84DE0774B802e422D4c26A73Dd68d7": "Bob", '
    '"identifier": "XXX" }\' would replace all instances of the address (pex\'ed, lowercase, '
    'checksummed) with "[Bob]" and all mentions of "identifier" with "[XXX]. '
    'It also allows you to use "Bob" as parameter value for "-n" and "-p" switches.',
)
def main(db_file, token_network_identifier, partner_address, names_translator):
    if names_translator:
        translator = Translator(json.load(names_translator))
        lookup = {v: k for k, v in translator.items()}
        token_network_identifier = lookup.get(
            token_network_identifier,
            token_network_identifier,
        )
        partner_address = lookup.get(
            partner_address,
            partner_address,
        )
    else:
        translator = None

    replay_wal(
        storage=sqlite.SerializedSQLiteStorage(db_file, serialize.JSONSerializer()),
        token_network_identifier=token_network_identifier,
        partner_address=partner_address,
        translator=translator,
    )


if __name__ == "__main__":
    main()
