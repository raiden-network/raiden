import gevent
import gevent.monkey

gevent.monkey.patch_all()

if True:
    import sys
    from raiden.network.transport.matrix.client import GMatrixClient
    from raiden.network.transport.matrix.utils import UserPresence

USER_ID = "@xxx:server1"
ACCESS_TOKEN = "REDACTED"
ROOM_ALIAS = '#room_name:server1'


def main():
    host = sys.argv[1]

    client = GMatrixClient(
        host,
        user_id=USER_ID,
        token=ACCESS_TOKEN
    )
    client.join_room(ROOM_ALIAS)

    current_presence = 'offline'
    while True:
        if current_presence == 'offline':
            client.set_presence_state(UserPresence.ONLINE.value)
        else:
            client.set_presence_state(UserPresence.OFFLINE.value)

        # Confirm user presence
        current_presence = client.get_user_presence(USER_ID)

        print('Change status to: ', current_presence)

        gevent.sleep(5)


if __name__ == '__main__':
    main()
