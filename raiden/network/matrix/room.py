from matrix_client.room import Room as MatrixRoom

from raiden.network.matrix.utils import _geventify_callback


class Room(MatrixRoom):
    def add_listener(self, callback, event_type=None):
        return super().add_listener(_geventify_callback(callback), event_type)

    def add_ephemeral_listener(self, callback, event_type=None):
        return super().add_ephemeral_listener(_geventify_callback(callback), event_type)

    def add_state_listener(self, callback, event_type=None):
        super().add_state_listener(_geventify_callback(callback), event_type)
