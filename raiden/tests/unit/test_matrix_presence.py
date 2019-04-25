from typing import Callable, Dict, Optional, Union
from unittest.mock import Mock

import pytest
from eth_utils import to_canonical_address
from matrix_client.user import User

from raiden.network.transport.matrix import AddressReachability, UserPresence
from raiden.network.transport.matrix.utils import USERID_RE, UserAddressManager
from raiden.utils import Address


class DummyUser:
    def __init__(self, user_id: str):
        self.user_id = user_id
        self.displayname = 'dummy'

    def __eq__(self, other):
        return isinstance(other, (DummyUser, User)) and self.user_id == other.user_id

    def __repr__(self):
        return f'<{self.__class__.__name__} user_id={self.user_id}>'

    def __hash__(self):
        return hash(self.user_id)


class DummyMatrixClient:
    def __init__(self, user_id: str):
        self._presence_callback = None
        self.user_id = user_id

    def add_presence_listener(self, callback: Callable):
        if self._presence_callback is not None:
            raise RuntimeError('Callback has already been registered')
        self._presence_callback = callback

    # Test helper
    def trigger_presence_callback(self, user_states: Dict[str, UserPresence]):
        """Trigger the registered presence listener with the given user presence"""
        if self._presence_callback is None:
            raise RuntimeError('No callback has been registered')

        for user_id, presence in user_states.items():
            event = {
                'sender': user_id,
                'type': 'm.presence',
                'content': {
                    'presence': presence.value,
                },
            }
            self._presence_callback(event)


class NonValidatingUserAddressManager(UserAddressManager):
    @staticmethod
    def _validate_userid_signature(user: User) -> Optional[Address]:
        match = USERID_RE.match(user.user_id)
        if not match:
            return None
        return to_canonical_address(match.group(1))


def dummy_get_user(user_or_id: Union[str, User]) -> User:
    if isinstance(user_or_id, User):
        return user_or_id
    return DummyUser(user_id=user_or_id)


ADDR1 = b'\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11'
ADDR2 = b'""""""""""""""""""""'
INVALID_USER_ID = 'bla:bla'
USER0_ID = '@0x0000000000000000000000000000000000000000:server1'
USER1_S1_ID = '@0x1111111111111111111111111111111111111111:server1'
USER1_S2_ID = '@0x1111111111111111111111111111111111111111:server2'
USER2_S1_ID = '@0x2222222222222222222222222222222222222222:server1'
USER2_S2_ID = '@0x2222222222222222222222222222222222222222:server2'
USER1_S1 = DummyUser(USER1_S1_ID)
USER1_S2 = DummyUser(USER1_S2_ID)
USER2_S1 = DummyUser(USER2_S1_ID)
USER2_S2 = DummyUser(USER2_S2_ID)


@pytest.fixture
def dummy_matrix_client():
    return DummyMatrixClient(USER0_ID)


@pytest.fixture
def user_presence():
    """Storage `user_presence_callback` will update. Useful to assert over in tests."""
    return {}


@pytest.fixture
def address_reachability():
    """Storage `address_reachability_callback` will update. Useful to assert over in tests."""
    return {}


@pytest.fixture
def user_presence_callback(user_presence):
    def _callback(user, presence):
        user_presence[user] = presence
    return _callback


@pytest.fixture
def address_reachability_callback(address_reachability):
    def _callback(address, reachability):
        address_reachability[address] = reachability
    return _callback


@pytest.fixture
def user_addr_mgr(dummy_matrix_client, address_reachability_callback, user_presence_callback):
    return NonValidatingUserAddressManager(
        client=dummy_matrix_client,
        get_user_callable=dummy_get_user,
        address_reachability_changed_callback=address_reachability_callback,
        user_presence_changed_callback=user_presence_callback,
        stop_event=None,
    )


def test_user_addr_mgr_basics(
        user_addr_mgr,
        dummy_matrix_client,
        address_reachability,
        user_presence,
):
    # This will do nothing since the address isn't known / whitelisted
    dummy_matrix_client.trigger_presence_callback({USER1_S1_ID: UserPresence.ONLINE})
    # This won't do anything either since the user has an invalid id format
    dummy_matrix_client.trigger_presence_callback({INVALID_USER_ID: UserPresence.ONLINE})
    # Nothing again, due to using our own user
    dummy_matrix_client.trigger_presence_callback({USER0_ID: UserPresence.ONLINE})

    assert user_addr_mgr.known_addresses == set()
    assert not user_addr_mgr.is_address_known(ADDR1)
    assert user_addr_mgr.get_userids_for_address(ADDR1) == set()
    assert user_addr_mgr.get_address_reachability(ADDR1) is AddressReachability.UNKNOWN
    assert len(address_reachability) == 0
    assert len(user_presence) == 0

    user_addr_mgr.add_address(ADDR1)
    dummy_matrix_client.trigger_presence_callback({USER1_S1_ID: UserPresence.ONLINE})

    assert user_addr_mgr.known_addresses == {ADDR1}
    assert user_addr_mgr.is_address_known(ADDR1)
    assert user_addr_mgr.get_userids_for_address(ADDR1) == {USER1_S1_ID}
    assert user_addr_mgr.get_address_reachability(ADDR1) is AddressReachability.REACHABLE
    assert len(address_reachability) == 1
    assert address_reachability[ADDR1] is AddressReachability.REACHABLE
    assert len(user_presence) == 1
    print(user_presence)
    assert user_presence[USER1_S1] is UserPresence.ONLINE


def test_user_addr_mgr_compound(
        user_addr_mgr,
        dummy_matrix_client,
        address_reachability,
        user_presence,
):
    user_addr_mgr.add_address(ADDR1)
    dummy_matrix_client.trigger_presence_callback({USER1_S1_ID: UserPresence.ONLINE})

    assert user_addr_mgr.get_address_reachability(ADDR1) == AddressReachability.REACHABLE
    assert address_reachability[ADDR1] is AddressReachability.REACHABLE
    assert user_addr_mgr.get_userid_presence(USER1_S1_ID) is UserPresence.ONLINE
    assert user_presence[USER1_S1] is UserPresence.ONLINE

    dummy_matrix_client.trigger_presence_callback({USER1_S1_ID: UserPresence.OFFLINE})

    assert user_addr_mgr.get_address_reachability(ADDR1) == AddressReachability.UNREACHABLE
    assert address_reachability[ADDR1] is AddressReachability.UNREACHABLE
    assert user_addr_mgr.get_userid_presence(USER1_S1_ID) is UserPresence.OFFLINE
    assert user_addr_mgr.get_userid_presence(USER1_S2_ID) is UserPresence.UNKNOWN
    assert user_presence[USER1_S1] is UserPresence.OFFLINE

    # The duplicate `ONLINE` item is intentional to test both sides of a branch
    for presence in [UserPresence.ONLINE, UserPresence.ONLINE, UserPresence.UNAVAILABLE]:
        dummy_matrix_client.trigger_presence_callback({USER1_S2_ID: presence})

        assert user_addr_mgr.get_address_reachability(ADDR1) == AddressReachability.REACHABLE
        assert address_reachability[ADDR1] is AddressReachability.REACHABLE
        assert user_addr_mgr.get_userid_presence(USER1_S1_ID) is UserPresence.OFFLINE
        assert user_addr_mgr.get_userid_presence(USER1_S2_ID) is presence
        assert user_presence[USER1_S1] is UserPresence.OFFLINE
        assert user_presence[USER1_S2] is presence

    dummy_matrix_client.trigger_presence_callback({USER1_S2_ID: UserPresence.OFFLINE})
    assert user_addr_mgr.get_address_reachability(ADDR1) == AddressReachability.UNREACHABLE
    assert address_reachability[ADDR1] is AddressReachability.UNREACHABLE

    assert user_addr_mgr.get_userid_presence(USER2_S1_ID) is UserPresence.UNKNOWN
    assert user_addr_mgr.get_userid_presence(USER2_S2_ID) is UserPresence.UNKNOWN
    assert user_addr_mgr.get_address_reachability(ADDR2) is AddressReachability.UNKNOWN


def test_user_addr_mgr_force(
        user_addr_mgr,
        address_reachability,
        user_presence,
):
    assert not user_addr_mgr.is_address_known(ADDR1)
    assert user_addr_mgr.known_addresses == set()

    user_addr_mgr.add_userid_for_address(ADDR1, USER1_S1_ID)
    # This only updates the internal user presense state, but calls no callbacks and also doesn't
    # update the address reachability
    user_addr_mgr.force_user_presence(USER1_S1, UserPresence.ONLINE)

    assert user_addr_mgr.get_userid_presence(USER1_S1_ID) is UserPresence.ONLINE
    assert user_addr_mgr.get_address_reachability(ADDR1) is AddressReachability.UNKNOWN
    assert len(user_presence) == 0
    assert len(address_reachability) == 0

    # Update address presence from previously forced user state
    user_addr_mgr.refresh_address_presence(ADDR1)

    assert user_addr_mgr.get_address_reachability(ADDR1) is AddressReachability.REACHABLE
    assert len(user_presence) == 0
    assert len(address_reachability) == 1
    assert address_reachability[ADDR1] is AddressReachability.REACHABLE


def test_user_addr_mgr_fetch_presence(
        user_addr_mgr,
        dummy_matrix_client,
        address_reachability,
        user_presence,
):
    dummy_matrix_client.get_user_presence = Mock(return_value=UserPresence.ONLINE.value)

    user_addr_mgr.add_userid_for_address(ADDR1, USER1_S1_ID)
    # We have not provided or forced any xplicit user presence,
    # therefore the client will be queried
    user_addr_mgr.refresh_address_presence(ADDR1)

    assert user_addr_mgr.get_address_reachability(ADDR1) is AddressReachability.REACHABLE
    assert len(user_presence) == 0
    assert len(address_reachability) == 1
    assert address_reachability[ADDR1] is AddressReachability.REACHABLE

    assert dummy_matrix_client.get_user_presence.called_with(USER1_S1_ID)


def test_user_addr_mgr_fetch_misc(
        user_addr_mgr,
        dummy_matrix_client,
        address_reachability,
        user_presence,
):
    user2s = {USER2_S1_ID, USER2_S2_ID}
    user_addr_mgr.add_userids_for_address(ADDR2, user2s)

    assert user_addr_mgr.is_address_known(ADDR2)
    assert user_addr_mgr.get_userids_for_address(ADDR2) == user2s

    # Set stop event, no more presence updates should be processed
    user_addr_mgr._stop_event.set()
    dummy_matrix_client.trigger_presence_callback({USER2_S2_ID: UserPresence.ONLINE})

    assert len(user_presence) == 0
    assert len(address_reachability) == 0
    assert user_addr_mgr.get_userid_presence(USER2_S2_ID) is UserPresence.UNKNOWN
