# -*- coding: utf-8 -*-
""" Utilities regarding the WAL and its DB used only in testing. """


def get_db_state_changes(storage, table):
    cursor = storage.conn.cursor()
    result = cursor.execute(
        'SELECT * from {}'.format(table)
    )
    return result.fetchall()


def get_all_state_changes(log):
    """ Returns a list of tuples of identifiers and state changes"""
    return [
        (res[0], log.serializer.deserialize(res[1]))
        for res in get_db_state_changes(log.storage, 'state_changes')
    ]


def get_all_state_events(log):
    """ Returns a list of tuples of event id, state_change_id and events"""
    return [
        (res[0], res[1], log.serializer.deserialize(res[2]))
        for res in get_db_state_changes(log.storage, 'state_events')
    ]
