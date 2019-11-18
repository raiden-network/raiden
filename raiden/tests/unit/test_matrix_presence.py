import uuid
from typing import Callable, Dict, Iterator, List, Optional

import pytest
from eth_utils import to_canonical_address
from matrix_client.errors import MatrixRequestError
from matrix_client.user import User

from raiden.network.transport.matrix import AddressReachability, UserPresence
from raiden.network.transport.matrix.utils import USERID_RE, DisplayNameCache, UserAddressManager
from raiden.utils import Address


class DummyApi:
    def get_display_name(self, user_id):  # pylint: disable=no-self-use,unused-argument
        return None


class DummyMatrixClient:
    def __init__(self, user_id: str, user_directory_content: Optional[List[User]] = None):
        self.api = DummyApi()
        self.user_id = user_id
        self._presence_callback: Optional[Callable] = None
        self._user_directory_content = user_directory_content if user_directory_content else []
        # This is only used in `get_user_presence()`
        self._user_presence: Dict[str, str] = {}

    def add_presence_listener(self, callback: Callable) -> uuid.UUID:
        if self._presence_callback is not None:
            raise RuntimeError("Callback has already been registered")
        self._presence_callback = callback
        return uuid.uuid4()

    def remove_presence_listener(self, uid: uuid.UUID) -> None:  # pylint: disable=unused-argument
        self._presence_callback = None

    def search_user_directory(self, term: str) -> Iterator[User]:
        for user in self._user_directory_content:
            if term in user.user_id:
                yield user

    def get_user_presence(self, user_id: str) -> str:
        presence = self._user_presence.get(user_id)
        if presence is None:
            raise MatrixRequestError(404, "Unknown user")
        return presence

    # Test helper
    def trigger_presence_callback(self, user_states: Dict[str, UserPresence]):
        """Trigger the registered presence listener with the given user presence"""
        if self._presence_callback is None:
            raise RuntimeError("No callback has been registered")

        for user_id, presence in user_states.items():
            event = {
                "sender": user_id,
                "type": "m.presence",
                "content": {"presence": presence.value},
            }
            self._presence_callback(event)


class NonValidatingUserAddressManager(UserAddressManager):
    @staticmethod
    def _validate_userid_signature(user: User) -> Optional[Address]:
        match = USERID_RE.match(user.user_id)
        if not match:
            return None
        return to_canonical_address(match.group(1))


ADDR1 = Address(b"\x11" * 20)
ADDR2 = Address(b'""""""""""""""""""""')
INVALID_USER_ID = "bla:bla"
USER0_ID = "@0x0000000000000000000000000000000000000000:server1"
USER1_S1_ID = "@0x1111111111111111111111111111111111111111:server1"
USER1_S2_ID = "@0x1111111111111111111111111111111111111111:server2"
USER2_S1_ID = "@0x2222222222222222222222222222222222222222:server1"
USER2_S2_ID = "@0x2222222222222222222222222222222222222222:server2"
USER1_S1 = User(api=None, user_id=USER1_S1_ID)
USER1_S2 = User(api=None, user_id=USER1_S2_ID)
USER2_S1 = User(api=None, user_id=USER2_S1_ID)
USER2_S2 = User(api=None, user_id=USER2_S2_ID)


@pytest.fixture
def user_directory_content():
    return []


@pytest.fixture
def dummy_matrix_client(user_directory_content):
    return DummyMatrixClient(USER0_ID, user_directory_content)


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
        user_presence[user.user_id] = presence

    return _callback


@pytest.fixture
def address_reachability_callback(address_reachability):
    def _callback(address, reachability):
        address_reachability[address] = reachability

    return _callback


@pytest.fixture
def user_addr_mgr(dummy_matrix_client, address_reachability_callback, user_presence_callback):

    address_manager = NonValidatingUserAddressManager(
        client=dummy_matrix_client,
        displayname_cache=DisplayNameCache(),
        address_reachability_changed_callback=address_reachability_callback,
        user_presence_changed_callback=user_presence_callback,
    )

    def fetch_user_presence(user_id):
        if user_id in address_manager._userid_to_presence.keys():
            return address_manager.get_userid_presence(user_id)
        else:
            presence = UserPresence(dummy_matrix_client.get_user_presence(user_id))
            address_manager._userid_to_presence[user_id] = presence
            return address_manager._userid_to_presence[user_id]

    address_manager._fetch_user_presence = fetch_user_presence
    address_manager.start()

    yield address_manager

    address_manager.stop()


def test_user_addr_mgr_basics(
    user_addr_mgr, dummy_matrix_client, address_reachability, user_presence
):
    # This will do nothing since the address isn't known / whitelisted
    dummy_matrix_client.trigger_presence_callback({USER1_S1_ID: UserPresence.ONLINE})
    # This won't do anything either since the user has an invalid id format
    dummy_matrix_client.trigger_presence_callback({INVALID_USER_ID: UserPresence.ONLINE})
    # Nothing again, due to using our own user
    dummy_matrix_client.trigger_presence_callback({USER0_ID: UserPresence.ONLINE})

    assert not user_addr_mgr.known_addresses
    assert not user_addr_mgr.is_address_known(ADDR1)
    assert user_addr_mgr.get_userids_for_address(ADDR1) == set()
    assert user_addr_mgr.get_address_reachability(ADDR1) is AddressReachability.UNKNOWN
    assert len(address_reachability) == 0
    assert len(user_presence) == 0

    user_addr_mgr.add_address(ADDR1)
    dummy_matrix_client.trigger_presence_callback({USER1_S1_ID: UserPresence.ONLINE})

    assert list(user_addr_mgr.known_addresses) == [ADDR1]
    assert user_addr_mgr.is_address_known(ADDR1)
    assert user_addr_mgr.get_userids_for_address(ADDR1) == {USER1_S1_ID}
    assert user_addr_mgr.get_address_reachability(ADDR1) is AddressReachability.REACHABLE
    assert len(address_reachability) == 1
    assert address_reachability[ADDR1] is AddressReachability.REACHABLE
    assert len(user_presence) == 1
    assert user_presence[USER1_S1.user_id] is UserPresence.ONLINE


def test_user_addr_mgr_compound(
    user_addr_mgr, dummy_matrix_client, address_reachability, user_presence
):
    user_addr_mgr.add_address(ADDR1)
    dummy_matrix_client.trigger_presence_callback({USER1_S1_ID: UserPresence.ONLINE})

    assert user_addr_mgr.get_address_reachability(ADDR1) == AddressReachability.REACHABLE
    assert address_reachability[ADDR1] is AddressReachability.REACHABLE
    assert user_addr_mgr.get_userid_presence(USER1_S1_ID) is UserPresence.ONLINE
    assert user_presence[USER1_S1.user_id] is UserPresence.ONLINE

    dummy_matrix_client.trigger_presence_callback({USER1_S1_ID: UserPresence.OFFLINE})

    assert user_addr_mgr.get_address_reachability(ADDR1) == AddressReachability.UNREACHABLE
    assert address_reachability[ADDR1] is AddressReachability.UNREACHABLE
    assert user_addr_mgr.get_userid_presence(USER1_S1_ID) is UserPresence.OFFLINE
    assert user_addr_mgr.get_userid_presence(USER1_S2_ID) is UserPresence.UNKNOWN
    assert user_presence[USER1_S1.user_id] is UserPresence.OFFLINE

    # The duplicate `ONLINE` item is intentional to test both sides of a branch
    for presence in [UserPresence.ONLINE, UserPresence.ONLINE, UserPresence.UNAVAILABLE]:
        dummy_matrix_client.trigger_presence_callback({USER1_S2_ID: presence})

        assert user_addr_mgr.get_address_reachability(ADDR1) == AddressReachability.REACHABLE
        assert address_reachability[ADDR1] is AddressReachability.REACHABLE
        assert user_addr_mgr.get_userid_presence(USER1_S1_ID) is UserPresence.OFFLINE
        assert user_addr_mgr.get_userid_presence(USER1_S2_ID) is presence
        assert user_presence[USER1_S1.user_id] is UserPresence.OFFLINE
        assert user_presence[USER1_S2.user_id] is presence

    dummy_matrix_client.trigger_presence_callback({USER1_S2_ID: UserPresence.OFFLINE})
    assert user_addr_mgr.get_address_reachability(ADDR1) == AddressReachability.UNREACHABLE
    assert address_reachability[ADDR1] is AddressReachability.UNREACHABLE

    assert user_addr_mgr.get_userid_presence(USER2_S1_ID) is UserPresence.UNKNOWN
    assert user_addr_mgr.get_userid_presence(USER2_S2_ID) is UserPresence.UNKNOWN
    assert user_addr_mgr.get_address_reachability(ADDR2) is AddressReachability.UNKNOWN


def test_user_addr_mgr_force(user_addr_mgr, address_reachability, user_presence):
    assert not user_addr_mgr.is_address_known(ADDR1)
    assert not user_addr_mgr.known_addresses

    user_addr_mgr.add_userid_for_address(ADDR1, USER1_S1_ID)
    # This only updates the internal user presense state, but calls no callbacks and also doesn't
    # update the address reachability
    user_addr_mgr.force_user_presence(USER1_S1, UserPresence.ONLINE)

    assert user_addr_mgr.get_userid_presence(USER1_S1_ID) is UserPresence.ONLINE
    assert user_addr_mgr.get_address_reachability(ADDR1) is AddressReachability.UNKNOWN
    assert len(user_presence) == 0
    assert len(address_reachability) == 0

    # Update address presence from previously forced user state
    user_addr_mgr.track_address_presence(ADDR1, [USER1_S1_ID])

    assert user_addr_mgr.get_address_reachability(ADDR1) is AddressReachability.REACHABLE
    assert len(user_presence) == 0
    assert len(address_reachability) == 1
    assert address_reachability[ADDR1] is AddressReachability.REACHABLE


def test_user_addr_mgr_fetch_presence(
    user_addr_mgr, dummy_matrix_client, address_reachability, user_presence
):
    dummy_matrix_client._user_presence[USER1_S1_ID] = UserPresence.ONLINE.value

    user_addr_mgr.add_userid_for_address(ADDR1, USER1_S1_ID)
    # We have not provided or forced any explicit user presence,
    # therefore the client will be queried
    assert dummy_matrix_client._user_presence[USER1_S1_ID] == UserPresence.ONLINE.value
    assert dummy_matrix_client.get_user_presence(USER1_S1_ID) == UserPresence.ONLINE.value

    user_addr_mgr.track_address_presence(ADDR1, [USER1_S1_ID])

    assert user_addr_mgr._userid_to_presence[USER1_S1_ID] == UserPresence.ONLINE

    assert user_addr_mgr.get_address_reachability(ADDR1) is AddressReachability.REACHABLE
    assert len(user_presence) == 0
    assert len(address_reachability) == 1
    assert address_reachability[ADDR1] is AddressReachability.REACHABLE


def test_user_addr_mgr_fetch_presence_error(user_addr_mgr, address_reachability, user_presence):
    user_addr_mgr.add_userid_for_address(ADDR1, USER1_S1_ID)
    # We have not provided or forced any explicit user presence,
    # therefore the client will be queried and return a 404 since we haven't setup a presence
    with pytest.raises(MatrixRequestError):
        user_addr_mgr.track_address_presence(ADDR1, [USER1_S1_ID])

    assert user_addr_mgr.get_address_reachability(ADDR1) is AddressReachability.UNKNOWN
    assert len(user_presence) == 0
    assert len(address_reachability) == 0


def test_user_addr_mgr_fetch_misc(
    user_addr_mgr, dummy_matrix_client, address_reachability, user_presence
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


@pytest.mark.parametrize("user_directory_content", [[USER2_S1, USER2_S2]])
def test_user_addr_mgr_populate(user_addr_mgr, address_reachability, user_presence):
    user_addr_mgr.add_address(ADDR2)

    assert user_addr_mgr.get_userids_for_address(ADDR2) == set()

    user_addr_mgr.populate_userids_for_address(ADDR2)

    assert user_addr_mgr.get_userids_for_address(ADDR2) == {USER2_S1_ID, USER2_S2_ID}
    assert user_addr_mgr.get_address_reachability(ADDR2) is AddressReachability.UNKNOWN

    user_addr_mgr._set_user_presence(USER2_S1_ID, UserPresence.ONLINE)
    user_addr_mgr._set_user_presence(USER2_S2_ID, UserPresence.UNKNOWN)

    user_addr_mgr.track_address_presence(ADDR2, {USER2_S2_ID, USER2_S2_ID})

    assert len(address_reachability) == 1
    assert address_reachability[ADDR2] is AddressReachability.REACHABLE
    assert len(user_presence) == 2
    assert user_addr_mgr.get_userid_presence(USER2_S1_ID) is UserPresence.ONLINE
    assert user_addr_mgr.get_userid_presence(USER2_S2_ID) is UserPresence.UNKNOWN


@pytest.mark.parametrize(
    ("force", "result"), [(False, {USER2_S1_ID}), (True, {USER2_S1_ID, USER2_S2_ID})]
)
@pytest.mark.parametrize("user_directory_content", [[USER2_S1, USER2_S2]])
def test_user_addr_mgr_populate_force(user_addr_mgr, force, result):
    user_addr_mgr.add_userid_for_address(ADDR2, USER2_S1_ID)
    user_addr_mgr.populate_userids_for_address(ADDR2, force=force)

    assert user_addr_mgr.get_userids_for_address(ADDR2) == result
