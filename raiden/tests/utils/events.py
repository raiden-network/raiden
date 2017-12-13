# -*- coding: utf-8 -*-


def check_nested_attrs(item, data):
    for name, value in data.items():
        item_value = getattr(item, name)

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
    number of retries from the protocol layer.

    This is completely non-deterministic since the protocol retries depend on
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
                return True

    return False
