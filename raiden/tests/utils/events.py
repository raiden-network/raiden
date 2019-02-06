from collections import Mapping

import gevent

from raiden.raiden_service import RaidenService
from raiden.transfer.architecture import Event, StateChange
from raiden.utils.typing import Any, Dict, List, Optional

NOVALUE = object()


def check_dict_nested_attrs(item: Dict, dict_data: Dict) -> bool:
    """ Checks the values from `dict_data` are contained in `item`

    >>> d = {'a': 1, 'b': {'c': 2}}
    >>> check_dict_nested_attrs(d, {'a': 1)
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


def check_nested_attrs(item: Any, attributes: Dict) -> bool:
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
        item_list: List,
        item_type: Any,
        attributes: Dict,
) -> Optional[Any]:
    """ Search for the first item of type `item_type` with `attributes` in
    `item_list`.

    `attributes` are compared using the utility `check_nested_attrs`.
    """
    for item in item_list:
        if isinstance(item, item_type) and check_nested_attrs(item, attributes):
            return item

    return None


def raiden_events_search_for_item(
        raiden: RaidenService,
        item_type: Event,
        attributes: Dict,
) -> Optional[Event]:
    """ Search for the first event of type `item_type` with `attributes` in the
    `raiden` database.

    `attributes` are compared using the utility `check_nested_attrs`.
    """
    return search_for_item(raiden.wal.storage.get_events(), item_type, attributes)


def raiden_state_changes_search_for_item(
        raiden: RaidenService,
        item_type: StateChange,
        attributes: Dict,
) -> Optional[StateChange]:
    """ Search for the first event of type `item_type` with `attributes` in the
    `raiden` database.

    `attributes` are compared using the utility `check_nested_attrs`.
    """
    return search_for_item(
        raiden.wal.storage.get_statechanges_by_identifier(0, 'latest'),
        item_type,
        attributes,
    )


def must_have_event(event_list: List, dict_data: Dict):
    for item in event_list:
        if isinstance(item, Mapping) and check_dict_nested_attrs(item, dict_data):
            return item
    return None


def must_have_events(event_list: List, *args) -> bool:
    for dict_data in args:
        item = must_have_event(event_list, dict_data)
        if not item:
            return False

    return True


def wait_for_raiden_event(
        raiden: RaidenService,
        item_type: Event,
        attributes: Dict,
        retry_timeout: float,
) -> Event:
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
        raiden: RaidenService,
        item_type: StateChange,
        attributes: Dict,
        retry_timeout: float,
) -> StateChange:
    """Wait until a state change is seen in the WAL

    Note:
        This does not time out, use gevent.Timeout.
    """
    found = None
    while found is None:
        found = raiden_state_changes_search_for_item(raiden, item_type, attributes)
        gevent.sleep(retry_timeout)

    return found
