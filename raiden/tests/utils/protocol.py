from unittest.mock import patch

from raiden.transfer.architecture import TransitionResult


def dont_handle_lock_expired_mock(app):
    """Takes in a raiden app and returns a mock context where lock_expired is not processed
    """

    def do_nothing(raiden, message):  # pylint: disable=unused-argument
        pass

    return patch.object(
        app.raiden.message_handler, "handle_message_lockexpired", side_effect=do_nothing
    )


def dont_handle_node_change_network_state():
    """Returns a mock context where ActionChangeNodeNetworkState is not processed
    """

    def empty_state_transition(chain_state, state_change):  # pylint: disable=unused-argument
        return TransitionResult(chain_state, list())

    return patch("raiden.transfer.node.handle_node_change_network_state", empty_state_transition)
