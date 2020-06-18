import json

import click
import gevent.monkey
import structlog
from eth_account import Account
from eth_utils import decode_hex

from raiden.utils.signer import LocalSigner

gevent.monkey.patch_all()  # isort:skip # noqa

import asyncio  # isort:skip # noqa
from raiden.network.transport.matrix.rtc import aiogevent  # isort:skip # noqa

asyncio.set_event_loop_policy(aiogevent.EventLoopPolicy())  # isort:skip # noqa


log = structlog.get_logger(__name__)

if True:
    import sys
    from raiden.network.transport.matrix.client import GMatrixClient
    from raiden.network.transport.matrix.utils import login


def callback(event):
    print(event)


def get_private_key(keystore_file, password):
    with open(keystore_file, "r") as keystore:
        try:
            private_key = Account.decrypt(
                keyfile_json=json.load(keystore), password=password
            ).hex()
            return private_key
        except ValueError as error:
            print("Could not decode keyfile with given password. Please try again.", str(error))
            sys.exit(1)


@click.command()
@click.option(
    "--keystore-file",
    required=True,
    type=click.Path(exists=True, dir_okay=False, readable=True),
    help="Path to a keystore file.",
)
@click.password_option(
    "--password", confirmation_prompt=False, help="Password to unlock the keystore file."
)
@click.option("--host", required=True, type=str)
@click.option(
    "--room-id",
    required=True,
    default="#raiden_goerli_discovery:transport01.raiden.network",
    type=str,
)
@click.option(
    "--other-user-id", required=True, default="@xxx:transport01.raiden.network", type=str
)
def main(keystore_file: str, password: str, host: str, room_id: str, other_user_id: str):
    private_key = get_private_key(keystore_file, password)
    client = GMatrixClient(host)

    user = login(client=client, signer=LocalSigner(private_key=decode_hex(private_key)))

    log.info("Logged in", user=user, server=host, room_id=room_id)
    # print("TKN: \n" + client.token)

    client.add_presence_listener(callback)
    client.start_listener_thread()

    # try:
    client.join_room(room_id)
    # except MatrixRequestError:
    #     client.create_room(alias="raiden_goerli_discovery", is_public=True)

    while True:
        current_presence = client.get_user_presence(other_user_id)
        log.warning("User presence", other_user=other_user_id, presence=current_presence)

        gevent.sleep(1)


if __name__ == "__main__":
    main()
