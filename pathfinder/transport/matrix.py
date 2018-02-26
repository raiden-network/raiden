# -*- coding: utf-8 -*-
import json
import logging

import gevent
import gevent.event
import requests
from matrix_client.client import MatrixClient
from matrix_client.errors import MatrixHttpLibError

from pathfinder.transport import Transport

log = logging.getLogger(__name__)


class MatrixTransport(Transport):
    def __init__(self, homeserver, username, password, matrix_room):
        super().__init__()
        self.homeserver = homeserver
        self.username = username
        self.password = password
        self.room_name = matrix_room
        self.is_running = gevent.event.Event()
        self.retry_timeout = 5
        self.synced = False
        self.connected = False

    def matrix_exception_handler(self, e):
        """Called whenever an exception occurs in matrix client thread.

            Any exception other than MatrixHttpLibError will be sent to parent hub,
             terminating the program.
        """
        if isinstance(e, MatrixHttpLibError):
            log.warning(str(e))
            gevent.sleep(1)
            return
        gevent.get_hub().parent.throw(e)

    def connect(self):
        self.client = MatrixClient(self.homeserver)
        self.client.login_with_password(self.username, self.password)
        self.client.start_listener_thread(
            exception_handler=lambda e: self.matrix_exception_handler(e)
        )

        self.room = self.client.join_room(self.room_name)
        self.room.add_listener(lambda room, event: self.dispatch(room, event))
        self.connected = True

    def get_room_events(self, limit=100):
        f = {"room": {"timeline": {"limit": 100}}}
        result = self.client.api.sync(filter=json.dumps(f))
        room_id = self.room.room_id
        room = result['rooms']['join'][room_id]
        return room['timeline']['events']

    def sync_history(self):
        events = self.get_room_events()
        for event in events:
            self.push_event(event)
        self.synced = True

    def push_event(self, event):
        for listener in self.room.listeners:
            if listener['event_type'] is None or listener['event_type'] == event['type']:
                listener['callback'](self.room, event)

    def dispatch(self, room, event):
        if event['type'] == "m.room.message":
            if event['content']['msgtype'] == "m.text":
                self.run_message_callbacks(event)
                log.debug("{0}: {1}".format(event['sender'], event['content']['body']))

    def _run(self):
        self.is_running.set()
        while self.is_running.is_set():
            try:
                if not self.connected:
                    self.connect()
                if not self.synced:
                    self.sync_history()
            except (requests.exceptions.ConnectionError, MatrixHttpLibError) as e:
                log.warn("Connection to %s failed. Retrying in %d seconds (%s)" %
                         (self.homeserver,
                          self.retry_timeout,
                          str(e)
                          ))
            gevent.sleep(self.retry_timeout)
