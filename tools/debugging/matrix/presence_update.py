import gevent.monkey

gevent.monkey.patch_all()

# isort: split

from typing import Optional

import gevent


from raiden.network.transport.matrix.rtc.utils import setup_asyncio_event_loop


setup_asyncio_event_loop()

if True:
    import sys
    from raiden.network.transport.matrix.client import GMatrixClient
    from raiden.network.transport.matrix.utils import UserPresence

USER_ID = "@xxx:server1"
ACCESS_TOKEN = "REDACTED"
ROOM_ALIAS = "#room_name:server1"


def main() -> None:
    host = sys.argv[1]

    client = GMatrixClient(
        lambda x: False, lambda x: None, host, user_id=USER_ID, token=ACCESS_TOKEN
    )
    client.join_room(ROOM_ALIAS)

    current_presence: Optional[str] = "offline"
    while True:
        if current_presence == "offline":
            client.set_presence_state(UserPresence.ONLINE.value)
        else:
            client.set_presence_state(UserPresence.OFFLINE.value)

        # Confirm user presence
        current_presence = client.get_user_presence(USER_ID)

        print("Change status to: ", current_presence)

        gevent.sleep(5)


if __name__ == "__main__":
    main()
