from raiden.tests.utils.factories import UNIT_SECRETHASH
from raiden.transfer.views import get_transfer_task


def test_get_transfer_task(chain_state):
    subtask = object()
    chain_state.payment_mapping.secrethashes_to_task[UNIT_SECRETHASH] = subtask
    assert get_transfer_task(chain_state=chain_state, secrethash=UNIT_SECRETHASH) == subtask
