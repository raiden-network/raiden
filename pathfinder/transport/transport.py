# -*- coding: utf-8 -*-
import json

import gevent


class Transport(gevent.Greenlet):
    """A generic transport class.

    Should be reimplemented to run registered callbacks whenever a message arrives.
    """
    def __init__(self):
        super().__init__()
        self.message_callbacks = list()

    def add_message_callback(self, callback):
        self.message_callbacks.append(callback)

    def run_message_callbacks(self, data):
        """Called whenever a message is received"""

        for callback in self.message_callbacks:
            callback(data)

    def _run(self):
        """Message receiving loop itself

        Implement this - a simple gevent Event sync will do"""
        raise NotImplementedError
