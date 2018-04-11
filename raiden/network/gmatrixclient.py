from matrix_client.client import MatrixClient
from matrix_client.user import User
from matrix_client.room import Room
from matrix_client.errors import MatrixRequestError

import gevent
import logging
from typing import List
try:
    from urllib import quote
except ImportError:
    from urllib.parse import quote

logger = logging.getLogger(__name__)


class GMatrixClient(MatrixClient):
    """Gevent-compliant MatrixClient child class"""

    def listen_forever(self, timeout_ms=30000, exception_handler=None):
        """ Keep listening for events forever.
        Args:
            timeout_ms (int): How long to poll the Home Server for before
               retrying.
            exception_handler (func(exception)): Optional exception handler
               function which can be used to handle exceptions in the caller
               thread.
        """
        bad_sync_timeout = 5000
        self.should_listen = True
        while self.should_listen:
            try:
                self._sync(timeout_ms)
                bad_sync_timeout = 5
            except MatrixRequestError as e:
                logger.warning("A MatrixRequestError occured during sync.")
                if e.code >= 500:
                    logger.warning("Problem occured serverside. Waiting %i seconds",
                                   bad_sync_timeout)
                    gevent.sleep(bad_sync_timeout)
                    bad_sync_timeout = min(bad_sync_timeout * 2,
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
        self.sync_thread = gevent.spawn(self.listen_forever, timeout_ms, exception_handler)
        self.should_listen = True

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
