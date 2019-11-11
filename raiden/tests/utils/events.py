from collections.abc import Mapping
from typing import Any, Iterable, List, Optional, Tuple, Type, TypeVar, cast

import gevent

from raiden.raiden_service import RaidenService
from raiden.storage.sqlite import RANGE_ALL_STATE_CHANGES
from raiden.transfer.architecture import Event, StateChange
from raiden.transfer.mediated_transfer.events import EventUnlockClaimFailed, EventUnlockFailed

NOVALUE = object()
T = TypeVar("T")
TE = TypeVar("TE", bound=Event)
SC = TypeVar("SC", bound=StateChange)
TM = TypeVar("TM", bound=Mapping)


def check_dict_nested_attrs(item: Mapping, dict_data: Mapping) -> bool:
    """ Checks the values from `dict_data` are contained in `item`

    >>> d = {'a': 1, 'b': {'c': 2}}
    >>> check_dict_nested_attrs(d, {'a': 1})
    True
    >>> check_dict_nested_attrs(d, {'b': {'c': 2}})
    True
    >>> check_dict_nested_attrs(d, {'d': []})
    False
    """
    for key, value in dict_data.items():
        if key not in item:
            return False

        item_value = item[key]

        if isinstance(item_value, Mapping):
            if not check_dict_nested_attrs(item_value, value):
                return False
        elif item_value != value:
            return False

    return True


def check_nested_attrs(item: Any, attributes: Mapping) -> bool:
    """ Checks the attributes from `item` match the values defined in `attributes`.

    >>> from collections import namedtuple
    >>> A = namedtuple('A', 'a')
    >>> B = namedtuple('B', 'b')
    >>> d = {'a': 1}
    >>> check_nested_attrs(A(1), {'a': 1})
    True
    >>> check_nested_attrs(A(B(1)), {'a': {'b': 1}})
    True
    >>> check_nested_attrs(A(1), {'a': 2})
    False
    >>> check_nested_attrs(A(1), {'b': 1})
    False
    """
    for name, value in attributes.items():
        item_value = getattr(item, name, NOVALUE)

        if isinstance(value, Mapping):
            if not check_nested_attrs(item_value, value):
                return False

        elif item_value != value:
            return False

    return True


def search_for_item(
    item_list: Iterable[T], item_type: Type[T], attributes: Mapping
) -> Optional[T]:
    """ Search for the first item of type `item_type` with `attributes` in
    `item_list`.

    `attributes` are compared using the utility `check_nested_attrs`.
    """
    for item in item_list:
        if isinstance(item, item_type) and check_nested_attrs(item, attributes):
            return item

    return None


def raiden_events_search_for_item(
    raiden: RaidenService, item_type: Type[TE], attributes: Mapping
) -> Optional[TE]:
    """ Search for the first event of type `item_type` with `attributes` in the
    `raiden` database.

    `attributes` are compared using the utility `check_nested_attrs`.
    """
    assert raiden.wal, "RaidenService must be started"
    event = search_for_item(raiden.wal.storage.get_events(), item_type, attributes)
    return cast(TE, event)


def raiden_state_changes_search_for_item(
    raiden: RaidenService, item_type: Type[SC], attributes: Mapping
) -> Optional[SC]:
    """ Search for the first event of type `item_type` with `attributes` in the
    `raiden` database.

    `attributes` are compared using the utility `check_nested_attrs`.
    """
    assert raiden.wal, "RaidenService must be started"

    for item in raiden.wal.storage.get_statechanges_by_range(RANGE_ALL_STATE_CHANGES):
        if isinstance(item, item_type) and check_nested_attrs(item, attributes):
            return item

    return None


def must_have_event(event_list: Iterable[TM], dict_data: TM) -> Optional[TM]:
    for item in event_list:
        if isinstance(item, Mapping) and check_dict_nested_attrs(item, dict_data):
            return item
    return None


def must_have_events(event_list: List[TM], *args) -> bool:
    for dict_data in args:
        item = must_have_event(event_list, dict_data)
        if not item:
            return False

    return True


def count_event_of_types(events: List[Event], event_types: Tuple[Type, ...]) -> int:
    event_count = 0
    for event in events:
        if any(isinstance(event, event_type) for event_type in event_types):
            event_count += 1
    return event_count


def count_unlock_failures(events: List[Event]) -> int:
    return count_event_of_types(events, (EventUnlockClaimFailed, EventUnlockFailed))


def has_unlock_failure(raiden: RaidenService, offset: int = 0) -> bool:
    return count_unlock_failures(raiden.wal.storage.get_events()) > offset  # type: ignore


def wait_for_raiden_event(
    raiden: RaidenService, item_type: Type[Event], attributes: Mapping, retry_timeout: float
) -> Optional[Event]:
    """Wait until an event is seen in the WAL events

    Note:
        This does not time out, use gevent.Timeout.
    """
    found = None
    while found is None:
        found = raiden_events_search_for_item(raiden, item_type, attributes)
        gevent.sleep(retry_timeout)
    return found


def wait_for_state_change(
    raiden: RaidenService, item_type: Type[SC], attributes: Mapping, retry_timeout: float
) -> SC:
    """Wait until a state change is seen in the WAL

    Note:
        This does not time out, use gevent.Timeout.
    """
    found = None
    while found is None:
        found = raiden_state_changes_search_for_item(raiden, item_type, attributes)
        gevent.sleep(retry_timeout)

    return found
