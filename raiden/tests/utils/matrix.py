from itertools import count

from raiden.transfer.state import NODE_NETWORK_UNKNOWN


class MockMatrixUser:
    _user_ids_to_display_names = dict()

    def __init__(self, user_id=None):
        self.user_id = user_id

    def get_display_name(self):
        return self._user_ids_to_display_names.get(self.user_id, None)

    def set_display_name(self, display_name):
        self._user_ids_to_display_names[self.user_id] = display_name


class MockMatrixClient:
    _token_count = count(0)

    def __init__(self, server_name):
        self.hs = server_name
        self.presence_state = NODE_NETWORK_UNKNOWN
        self.rooms = dict()
        self.token = None
        self.user_id = None
        self.user = None
        self.sync_thread = None

        self.listener_thread_running = False
        self.invite_listeners = set()
        self.presence_list = set()
        self.presence_listeners = set()

    def _matrix_name(self, user_id=None):
        return '@{}:{}'.format(user_id or self.user_id, self.hs)

    def _next_token(self):
        return 'token%s' % next(self._token_count)

    def _presence_event(self, user_id, presence):
        for listener in self.presence_listeners:
            listener(dict(
                type='m.presence',
                sender=user_id,
                content=dict(presence=presence)
            ))

    def add_invite_listener(self, listener):
        self.invite_listeners.add(listener)

    def add_presence_listener(self, listener):
        self.presence_listeners.add(listener)

    def get_presence_list(self):
        return [{
            'last_active_ago': 1000,
            'accepted': {
                self._matrix_name(user_id): True
            },
            'currently_active': True,
            'user_id': self._matrix_name(user_id),
            'presence': 'online'
        } for user_id in self.presence_list]

    def get_rooms(self):
        return self.rooms

    def get_user(self, user_id):
        assert user_id == self.user_id
        return self.user

    def login_with_password(self, username, password):
        self.user_id = username
        self.user = MockMatrixUser(username)
        self.token = self._next_token()
        return self.token

    def logout(self):
        pass

    def modify_presence_list(self, add_user_ids=(), remove_user_ids=()):
        for user_id in add_user_ids:
            self.presence_list.add(user_id)
            self._presence_event(user_id, 'online')
        for user_id in remove_user_ids:
            try:
                self.presence_list.remove(user_id)
                self._presence_event(user_id, 'offline')
            except KeyError:
                pass

    def start_listener_thread(self, exception_handler):
        self.listener_thread_running = True

    def search_user_directory(self, term):
        user = MockMatrixUser(term)
        if user.get_display_name() is None:
            return []
        return [user]

    def set_presence_state(self, new_state):
        self.presence_state = new_state

    def stop_listener_thread(self):
        self.listener_thread_running = False
