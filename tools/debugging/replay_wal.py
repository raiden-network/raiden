"""
This script is meant to be used as a template to step through a provided DB file
for debugging a specific issue.
It constructs the chain_state through the state_manager and uses the WAL
to replay all state changes through the state machines until all state changes are consumed.
The parameters (token_network_identifier and partner_address) will help filter out all
state changes until a channel is found with the provided token network address and partner.
The ignored state changes will still be applied, but they will just not be printed out.
"""
import click
from eth_utils import encode_hex, to_canonical_address

from raiden.storage import serialize, sqlite
from raiden.storage.wal import WriteAheadLog
from raiden.transfer import node, views
from raiden.transfer.architecture import StateManager


def print_attributes(data):
    for key, value in data.items():
        if isinstance(value, bytes):
            value = encode_hex(value)

        click.echo('\t', nl=False)
        click.echo(click.style(key, fg='blue'), nl=False)
        click.echo(click.style('='), nl=False)
        click.echo(click.style(repr(value), fg='yellow'))


def print_state_change(state_change):
    click.echo(click.style(f'> {state_change.__class__.__name__}', fg='red', bold=True))
    print_attributes(state_change.__dict__)


def print_events(events):
    for event in events:
        click.echo(click.style(f'< {event.__class__.__name__}', fg='green', bold=True))
        print_attributes(event.__dict__)


def replay_wal(storage, token_network_identifier, partner_address):
    all_state_changes = storage.get_statechanges_by_identifier(
        from_identifier=0,
        to_identifier='latest',
    )

    state_manager = StateManager(state_transition=node.state_transition, current_state=None)
    wal = WriteAheadLog(state_manager, storage)

    for _, state_change in enumerate(all_state_changes):
        wal = WriteAheadLog(state_manager, storage)

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

        print_state_change(state_change)
        print_events(events)


@click.command(help=__doc__)
@click.argument('db-file')
@click.option(
    '-n',
    '--token-network-identifier',
)
@click.option(
    '-p',
    '--partner-address',
)
def main(db_file, token_network_identifier, partner_address):
    replay_wal(
        storage=sqlite.SQLiteStorage(db_file, serialize.JSONSerializer()),
        token_network_identifier=token_network_identifier,
        partner_address=partner_address,
    )


if __name__ == "__main__":
    main()
