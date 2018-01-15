# -*- coding: utf-8 -*-
import pickle
import sqlite3
import threading
from abc import ABCMeta, abstractmethod
from collections import namedtuple

InternalEvent = namedtuple(
    'InternalEvent',
    ('identifier', 'state_change_id', 'block_number', 'event_object'),
)


# TODO:
# - snapshots should be used to reduce the log file size

class StateChangeLogSerializer(object, metaclass=ABCMeta):
    """ StateChangeLogSerializer

        An abstract class defining the serialization interface for the
        Transaction log. Allows for pluggable serializer backends.
    """

    @abstractmethod
    def serialize(self, transaction):
        pass

    @abstractmethod
    def deserialize(self, data):
        pass


class PickleTransactionSerializer(StateChangeLogSerializer):
    """ PickleTransactionSerializer

        A simple transaction serializer using pickle
    """
    def serialize(self, transaction):
        # Some of our StateChange classes have __slots__ without having a __getstate__
        # As seen in the SO question below:
        # http://stackoverflow.com/questions/2204155/why-am-i-getting-an-error-about-my-class-defining-slots-when-trying-to-pickl#2204702
        # We can either add a __getstate__ to all of them or use the `-1` protocol and be
        # incompatible with ancient python version. Here I opt for the latter.
        return pickle.dumps(transaction, -1)

    def deserialize(self, data):
        return pickle.loads(data)


class StateChangeLogStorageBackend(object, metaclass=ABCMeta):
    """ StateChangeLogStorageBackend

        An abstract class defining the storage backend for the transaction log.
        Allows for pluggable storage backends.
    """

    @abstractmethod
    def write_state_change(self, data):
        pass

    @abstractmethod
    def write_state_snapshot(self, statechange_id, data):
        pass

    @abstractmethod
    def read(self):
        pass


class StateChangeLogSQLiteBackend(StateChangeLogStorageBackend):

    def __init__(self, database_path):
        self.conn = sqlite3.connect(database_path)
        self.conn.text_factory = str
        self.conn.execute('PRAGMA foreign_keys=ON')
        cursor = self.conn.cursor()
        cursor.execute(
            'CREATE TABLE IF NOT EXISTS state_changes ('
            '    id integer primary key autoincrement, data binary'
            ')'
        )
        cursor.execute(
            'CREATE TABLE IF NOT EXISTS state_snapshot ('
            'identifier integer primary key, statechange_id integer, data binary, '
            'FOREIGN KEY(statechange_id) REFERENCES state_changes(id)'
            ')'
        )
        cursor.execute(
            'CREATE TABLE IF NOT EXISTS state_events ('
            'identifier integer primary key, source_statechange_id integer NOT NULL, '
            'block_number integer NOT NULL, data binary, '
            'FOREIGN KEY(source_statechange_id) REFERENCES state_changes(id)'
            ')'
        )
        self.conn.commit()
        self.sanity_check()
        # When writting to a table where the primary key is the identifier and we want
        # to return said identifier we use cursor.lastrowid, which uses sqlite's last_insert_rowid
        # https://github.com/python/cpython/blob/2.7/Modules/_sqlite/cursor.c#L727-L732
        #
        # According to the documentation (http://www.sqlite.org/c3ref/last_insert_rowid.html)
        # if a different thread tries to use the same connection to write into the table
        # while we query the last_insert_rowid, the result is unpredictable. For that reason
        # we have this write lock here.
        #
        # TODO (If possible):
        # Improve on this and find a better way to protect against this potential race
        # condition.
        self.write_lock = threading.Lock()

    def sanity_check(self):
        """ Ensures that NUL character can be safely inserted and recovered
        from the database.

        http://bugs.python.org/issue13676
        """

        data = '\x00a'
        self.conn.execute(
            'INSERT INTO state_changes (id, data) VALUES (null,?)',
            (data, ),
        )

        result = next(self.conn.execute('SELECT data FROM state_changes ORDER BY id DESC'))

        if result[0] != data:
            raise RuntimeError(
                'Database cannot save NUL character, ensure python is at least 2.7.3'
            )

        self.conn.rollback()

    def write_state_change(self, data):
        with self.write_lock:
            cursor = self.conn.cursor()
            cursor.execute(
                'INSERT INTO state_changes(id, data) VALUES(null,?)',
                (data,)
            )
            last_id = cursor.lastrowid
            self.conn.commit()

        return last_id

    def write_state_snapshot(self, statechange_id, data):
        # TODO: Snapshotting is not yet implemented. This is just skeleton code
        # Issue: https://github.com/raiden-network/raiden/issues/593
        # This skeleton code assumes we only keep a single snapshot and overwrite it each time.

        with self.write_lock:
            cursor = self.conn.cursor()
            cursor.execute(
                'INSERT OR REPLACE INTO state_snapshot('
                'identifier, statechange_id, data) VALUES(?,?,?)',
                (1, statechange_id, data)
            )
            last_id = cursor.lastrowid
            self.conn.commit()

        return last_id

    def write_state_events(self, statechange_id, events_data):
        """Do an 'execute_many' write of state events. `events_data` should be a
        list of tuples of the form:
        (None, source_statechange_id, block_number, serialized_event_data)
        """
        cursor = self.conn.cursor()
        cursor.executemany(
            'INSERT INTO state_events('
            'identifier, source_statechange_id, block_number, data) VALUES(?,?,?,?)',
            events_data
        )
        self.conn.commit()

    def get_state_snapshot(self):
        """ Return the last state snapshot as a tuple of (state_change_id, data)"""
        cursor = self.conn.cursor()
        result = cursor.execute('SELECT * from state_snapshot')
        result = result.fetchall()
        if result == list():
            return None
        assert len(result) == 1
        return (result[0][1], result[0][2])

    def get_state_change_by_id(self, identifier):
        cursor = self.conn.cursor()
        result = cursor.execute(
            'SELECT data from state_changes where id=?', (identifier,)
        )
        result = result.fetchall()
        if result != list():
            assert len(result) == 1
            result = result[0][0]
        return result

    def get_events_in_range(self, from_block, to_block):
        cursor = self.conn.cursor()
        if from_block is None:
            from_block = 0
        if to_block is None:
            result = cursor.execute(
                'SELECT * from  state_events WHERE block_number >= ?',
                (from_block,)
            )
        else:
            result = cursor.execute(
                'SELECT * from  state_events WHERE block_number '
                'BETWEEN ? AND ?', (from_block, to_block)
            )
        result = result.fetchall()
        return result

    def read(self):
        pass

    def __del__(self):
        self.conn.close()


class StateChangeLog:

    def __init__(
            self,
            storage_instance,
            serializer_instance=PickleTransactionSerializer()):

        if not isinstance(serializer_instance, StateChangeLogSerializer):
            raise ValueError(
                'serializer_instance must follow the StateChangeLogSerializer interface'
            )
        self.serializer = serializer_instance

        if not isinstance(storage_instance, StateChangeLogStorageBackend):
            raise ValueError(
                'storage_instance must follow the StateChangeLogStorageBackend interface'
            )
        self.storage = storage_instance

    def log(self, state_change):
        """ Log a state change and return its identifier"""
        # TODO: Issue 587
        # Implement a queue of state changes for batch writting
        serialized_data = self.serializer.serialize(state_change)
        return self.storage.write_state_change(serialized_data)

    def log_events(self, state_change_id, events, current_block_number):
        """ Log the events that were generated by `state_change_id` into the write ahead Log
        """
        assert isinstance(events, list)
        self.storage.write_state_events(
            state_change_id,
            [(None, state_change_id, current_block_number, self.serializer.serialize(event))
             for event in events]
        )

    def get_events_in_block_range(self, from_block, to_block):
        """Get the raiden events in the period (inclusive) ranging from
        `from_block` to `to_block`.

        This function returns a list of tuples of the form:
        (identifier, generated_statechange_id, block_number, event_object)
        """
        results = self.storage.get_events_in_range(from_block, to_block)
        return [
            InternalEvent(res[0], res[1], res[2], self.serializer.deserialize(res[3]))
            for res in results
        ]

    def get_state_change_by_id(self, identifier):
        serialized_data = self.storage.get_state_change_by_id(identifier)
        return self.serializer.deserialize(serialized_data)

    def snapshot(self, state_change_id, state):
        serialized_data = self.serializer.serialize(state)
        self.storage.write_state_snapshot(state_change_id, serialized_data)
