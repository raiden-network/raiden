from matrix_client.client import MatrixClient, CACHE
from matrix_client.user import User
from matrix_client.errors import MatrixRequestError

import gevent
import logging
from typing import List

from raiden.network.matrix.room import Room
from raiden.network.matrix.utils import _geventify_callback, Fix429HTTPAdapter


try:
    from urllib import quote
except ImportError:
    from urllib.parse import quote

logger = logging.getLogger(__name__)


class GMatrixClient(MatrixClient):
    """Gevent-compliant MatrixClient child class"""

    def __init__(self, base_url, token=None, user_id=None, valid_cert_check=True,
                 sync_filter_limit=20, cache_level=CACHE.ALL):
        super().__init__(base_url, token, user_id, valid_cert_check, sync_filter_limit,
                         cache_level)
        # TODO: Remove once https://github.com/matrix-org/matrix-python-sdk/issues/193 is fixed
        self.api.session.mount('https://', Fix429HTTPAdapter())
        self.api.session.mount('http://', Fix429HTTPAdapter())

    def listen_forever(self, timeout_ms=30000, exception_handler=None, bad_sync_timeout=5):
        """ Keep listening for events forever.
        Args:
            timeout_ms (int): How long to poll the Home Server for before
               retrying.
            exception_handler (func(exception)): Optional exception handler
               function which can be used to handle exceptions in the caller
               thread.
            bad_sync_timeout (int): Base time to wait after an error before
                retrying. Will be increased according to exponential backoff.
        """
        _bad_sync_timeout = bad_sync_timeout
        self.should_listen = True
        while self.should_listen:
            try:
                self._sync(timeout_ms)
                _bad_sync_timeout = bad_sync_timeout
            except MatrixRequestError as e:
                logger.warning("A MatrixRequestError occured during sync.")
                if e.code >= 500:
                    logger.warning("Problem occured serverside. Waiting %i seconds",
                                   _bad_sync_timeout)
                    gevent.sleep(_bad_sync_timeout)
                    _bad_sync_timeout = min(_bad_sync_timeout * 2,
                                            self.bad_sync_timeout_limit)
                else:
                    raise
            except Exception as e:
                logger.exception("Exception thrown during sync")
                if exception_handler is not None:
                    exception_handler(e)
                else:
                    raise

    def start_listener_thread(self, timeout_ms=30000, exception_handler=None):
        """ Start a listener greenlet to listen for events in the background.
        Args:
            timeout (int): How long to poll the Home Server for before
               retrying.
            exception_handler (func(exception)): Optional exception handler
               function which can be used to handle exceptions in the caller
               thread.
        """
        self.should_listen = True
        self.sync_thread = gevent.spawn(self.listen_forever, timeout_ms, exception_handler)

    def search_user_directory(self, term: str) -> List[User]:
        """ Search user directory for a given term, returning a list of users
        Args:
            term (str): term to be searched for
        Returns: list of users returned by server-side search
        """
        response = self.api._send(
            'POST',
            '/user_directory/search',
            {
                'search_term': term
            }
        )
        try:
            return [
                User(self.api, _user['user_id'], _user['display_name'])
                for _user in response['results']
            ]
        except KeyError:
            return []

    def modify_presence_list(self, add_user_ids: list = (), remove_user_ids: list = ()):
        return self.api._send(
            'POST',
            f'/presence/list/{self.user_id}',
            {
                'invite': add_user_ids,
                'drop': remove_user_ids
            }
        )

    def get_presence_list(self):
        return self.api._send(
            'GET',
            f'/presence/list/{self.user_id}',
        )

    def set_presence_state(self, state):
        return self.api._send(
            'PUT',
            f'/presence/{self.user_id}/status',
            {
                'presence': state
            }
        )

    def typing(self, room: Room, timeout: int=5000):
        """Send typing event directly to api

        Args:
            room (Room): room to send typing event to
            timeout (int): timeout for the event, in ms
        """
        path = '/rooms/%s/typing/%s' % (
            quote(room.room_id), quote(self.user_id),
        )
        return self.api._send('PUT', path, {'typing': True, 'timeout': timeout})

    def add_invite_listener(self, callback):
        super().add_invite_listener(_geventify_callback(callback))

    def add_leave_listener(self, callback):
        super().add_leave_listener(_geventify_callback(callback))

    def add_presence_listener(self, callback):
        return super().add_presence_listener(_geventify_callback(callback))

    def add_listener(self, callback, event_type=None):
        return super().add_listener(_geventify_callback(callback), event_type)

    def add_ephemeral_listener(self, callback, event_type=None):
        return super().add_ephemeral_listener(_geventify_callback(callback), event_type)

    def _mkroom(self, room_id):
        """ Uses a geventified Room subclass """
        self.rooms[room_id] = Room(self, room_id)
        return self.rooms[room_id]
