from web3.datastructures import AttributeDict

NOVALUE = object()


def check_nested_attrs(item, data):
    for name, value in data.items():
        item_value = getattr(item, name, NOVALUE)

        if isinstance(value, dict):
            if not check_nested_attrs(item_value, value):
                return False

        elif item_value != value:
            return False

    return True


def must_contain_entry(item_list, type_, data):
    """ A node might have duplicated state changes or code changes may change
    order / quantity of the events.

    The number of state changes is non-deterministic since it depends on the
    number of retries from the transport layer.

    This is completely non-deterministic since the transport retries depend on
    timeouts and the cooperative scheduling of the running greenlets.
    Additionally the order / quantity of greenlet switches will change as the
    code evolves.

    This utility checks the list of state changes for an entry of the correct
    type with the expected data, ignoring *new* fields, repeated entries, and
    unexpected entries.
    """
    # item_list may be composed of state changes or events
    for item in item_list:
        if isinstance(item, type_):
            if check_nested_attrs(item, data):
                return item
    return None


def raiden_events_must_contain_entry(raiden, type_, data):
    return must_contain_entry(
        raiden.wal.storage.get_events(),
        type_,
        data,
    )


def check_dict_nested_attrs(item, dict_data):
    for key, value in dict_data.items():
        if key not in item:
            return False

        item_value = item[key]

        if isinstance(item_value, (AttributeDict, dict)):
            if not check_dict_nested_attrs(item_value, value):
                return False
        elif item_value != value:
            return False

    return True


def must_have_event(event_list, dict_data):
    for item in event_list:
        if isinstance(item, dict) and check_dict_nested_attrs(item, dict_data):
            return item
    return None


def must_have_events(event_list, *args) -> bool:
    for dict_data in args:
        item = must_have_event(event_list, dict_data)
        if not item:
            return False

    return True
