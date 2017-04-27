# -*- coding: utf-8 -*-
import pytest
from ethereum.tester import TransactionFailed
from coincurve import PrivateKey

from raiden.messages import DirectTransfer
from raiden.utils import privatekey_to_address
from raiden.tests.utils.transfer import make_direct_transfer_from_channel


def test_transfer_update_event(tester_state, tester_channels, tester_events):
    """ The event TransferUpdated is emitted after a successful call to
    updateTransfer.
    """

    pkey0, pkey1, nettingchannel, channel0, channel1 = tester_channels[0]
    address1 = privatekey_to_address(pkey1)

    direct0 = make_direct_transfer_from_channel(channel0, channel1, amount=90, pkey=pkey0)
    direct0_data = str(direct0.packed().data)

    nettingchannel.close('', sender=pkey0)

    previous_events = list(tester_events)
    nettingchannel.updateTransfer(direct0_data, sender=pkey1)
    assert len(previous_events) + 1 == len(tester_events)

    assert tester_events[-1] == {
        '_event_type': 'TransferUpdated',
        'node_address': address1.encode('hex'),
        'block_number': tester_state.block.number,
    }


def test_update_fails_on_open_channel(tester_channels):
    """ Cannot call updateTransfer on a open channel. """
    pkey0, _, nettingchannel, channel0, channel1 = tester_channels[0]

    transfer0 = make_direct_transfer_from_channel(channel0, channel1, amount=10, pkey=pkey0)
    transfer0_data = str(transfer0.packed().data)

    with pytest.raises(TransactionFailed):
        nettingchannel.updateTransfer(transfer0_data, sender=pkey0)


def test_update_not_allowed_after_settlement_period(settle_timeout, tester_channels, tester_state):
    """ updateTransfer cannot be called after the settlement period. """
    pkey0, pkey1, nettingchannel, channel0, channel1 = tester_channels[0]

    direct0 = make_direct_transfer_from_channel(channel0, channel1, amount=70, pkey=pkey0)
    direct0_data = str(direct0.packed().data)

    nettingchannel.close('', sender=pkey0)
    tester_state.mine(number_of_blocks=settle_timeout + 1)

    with pytest.raises(TransactionFailed):
        nettingchannel.updateTransfer(direct0_data, sender=pkey1)


def test_update_not_allowed_for_the_closing_address(tester_channels):
    """ Closing address cannot call updateTransfer. """
    pkey0, pkey1, nettingchannel, channel0, channel1 = tester_channels[0]

    transfer0 = make_direct_transfer_from_channel(channel0, channel1, amount=10, pkey=pkey0)
    transfer0_data = str(transfer0.packed().data)

    transfer1 = make_direct_transfer_from_channel(channel1, channel0, amount=10, pkey=pkey1)
    transfer1_data = str(transfer1.packed().data)

    nettingchannel.close('', sender=pkey0)

    # do not accept a transfer from the party that closed
    with pytest.raises(TransactionFailed):
        nettingchannel.updateTransfer(transfer0_data, sender=pkey0)

    # nor a transfer from the partner
    with pytest.raises(TransactionFailed):
        nettingchannel.updateTransfer(transfer1_data, sender=pkey0)


@pytest.mark.parametrize('number_of_nodes', [3])
def test_update_must_fail_with_a_nonparticipant_transfer(tester_channels, private_keys):
    """ updateTransfer must not accept a transfer from a non participant. """
    pkey0, pkey1, nettingchannel, channel0, channel1 = tester_channels[0]
    nonparticipant_key = private_keys[2]

    # make a transfer where pkey1 is the target
    transfer_nonparticipant = DirectTransfer(
        identifier=1,
        nonce=1,
        token=channel0.token_address,
        transferred_amount=10,
        recipient=channel1.our_address,
        locksroot='',
    )

    nonparticipant_address = privatekey_to_address(nonparticipant_key)
    nonparticipant_sign_key = PrivateKey(nonparticipant_key)

    transfer_nonparticipant.sign(nonparticipant_sign_key, nonparticipant_address)
    transfer_nonparticipant_data = str(transfer_nonparticipant.packed().data)

    nettingchannel.close('', sender=pkey0)

    with pytest.raises(TransactionFailed):
        nettingchannel.updateTransfer(transfer_nonparticipant_data, sender=pkey1)


def test_update_called_multiple_times_same_transfer(tester_channels):
    """ updateTransfer can be called only once. """
    pkey0, pkey1, nettingchannel, channel0, channel1 = tester_channels[0]

    transfer0 = make_direct_transfer_from_channel(channel0, channel1, amount=10, pkey=pkey0)
    transfer0_data = str(transfer0.packed().data)

    nettingchannel.close('', sender=pkey0)
    nettingchannel.updateTransfer(transfer0_data, sender=pkey1)

    with pytest.raises(TransactionFailed):
        nettingchannel.updateTransfer(transfer0_data, sender=pkey1)


def test_update_called_multiple_times_new_transfer(tester_channels):
    """ updateTransfer second call must fail even if there is a new transfer. """
    pkey0, pkey1, nettingchannel, channel0, channel1 = tester_channels[0]

    transfer0 = make_direct_transfer_from_channel(channel0, channel1, amount=10, pkey=pkey0)
    transfer0_data = str(transfer0.packed().data)

    transfer1 = make_direct_transfer_from_channel(channel0, channel1, amount=10, pkey=pkey0)
    transfer1_data = str(transfer1.packed().data)

    nettingchannel.close('', sender=pkey0)
    nettingchannel.updateTransfer(transfer0_data, sender=pkey1)

    with pytest.raises(TransactionFailed):
        nettingchannel.updateTransfer(transfer1_data, sender=pkey1)


def test_update_called_multiple_times_older_transfer(tester_channels):
    """ updateTransfer second call must fail even if called with an older transfer. """
    pkey0, pkey1, nettingchannel, channel0, channel1 = tester_channels[0]

    transfer0 = make_direct_transfer_from_channel(channel0, channel1, amount=10, pkey=pkey0)
    transfer0_data = str(transfer0.packed().data)

    transfer1 = make_direct_transfer_from_channel(channel0, channel1, amount=10, pkey=pkey0)
    transfer1_data = str(transfer1.packed().data)

    nettingchannel.close('', sender=pkey0)
    nettingchannel.updateTransfer(transfer1_data, sender=pkey1)

    with pytest.raises(TransactionFailed):
        nettingchannel.updateTransfer(transfer0_data, sender=pkey1)
