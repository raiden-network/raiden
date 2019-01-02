from typing import Callable, Dict


class BlockchainListenerMock:
    """ A class to test Blockchain listener integration. """

    def __init__(self, **kwargs):
        self.confirmed_callbacks: Dict[str, Callable] = {}
        self.unconfirmed_callbacks: Dict[str, Callable] = {}

    def start(self):
        pass

    def add_confirmed_listener(self, event_name: str, callback: Callable):
        """ Add a callback to listen for confirmed events. """
        self.confirmed_callbacks[tuple(event_name)] = callback

    def add_unconfirmed_listener(self, event_name: str, callback: Callable):
        """ Add a callback to listen for unconfirmed events. """
        self.unconfirmed_callbacks[tuple(event_name)] = callback

    # mocking functions
    def emit_event(self, event: Dict, confirmed: bool = True):
        """ Emit a mocked event.

        Args:
            event: A dict containing the event information. This need to contain a key
                'event' which is used to dispatch the event to the right listener.
            confirmed: Whether or not the event is confirmed. """
        assert 'event' in event

        if confirmed:
            for callback in self.confirmed_callbacks.values():
                callback(event)
        else:
            for callback in self.unconfirmed_callbacks.values():
                callback(event)
