# -*- coding: utf-8 -*-
import pickle
import sqlite3
from abc import ABCMeta, abstractmethod


# TODO:
# - snapshots should be used to reduce the log file size

class StateChangeLogSerializer(object):
    """ StateChangeLogSerializer

        An abstract class defining the serialization interface for the
        Transaction log. Allows for pluggable serializer backends.
    """
    __metaclass__ = ABCMeta

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


class StateChangeLogStorageBackend(object):
    """ StateChangeLogStorageBackend

        An abstract class defining the storage backend for the transaction log.
        Allows for pluggable storage backends.
    """
    __metaclass__ = ABCMeta

    @abstractmethod
    def write_transaction(self, identifier, data):
        pass

    @abstractmethod
    def write_state_snapshot(self, identifier, data):
        pass

    @abstractmethod
    def read(self):
        pass

    @abstractmethod
    def last_identifier(self):
        pass


class StateChangeLogSQLiteBackend(StateChangeLogStorageBackend):

    def __init__(self, database_path):
        self.conn = sqlite3.connect(database_path)
        self.conn.text_factory = str
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
        self.conn.commit()

    def write_transaction(self, data):
        cursor = self.conn.cursor()
        cursor.execute(
            'INSERT INTO state_changes(id, data) VALUES(null,?)',
            (data,)
        )
        self.conn.commit()

    def write_state_snapshot(self, statechange_id, data):
        # TODO: Snapshotting is not yet implemented. This is just skeleton code
        # Issue: https://github.com/raiden-network/raiden/issues/593
        # This skeleton code assumes we only keep a single snapshot and overwrite it each time.
        cursor = self.conn.cursor()
        cursor.execute(
            'INSERT OR REPLACE INTO state_snapshot('
            'identifier, statechange_id, data) VALUES(?,?,?)',
            (1, statechange_id, data)
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

    def get_transaction_by_id(self, identifier):
        cursor = self.conn.cursor()
        result = cursor.execute(
            'SELECT data from state_changes where id=?', (identifier,)
        )
        result = result.fetchall()
        if result != list():
            assert len(result) == 1
            result = result[0][0]
        return result

    def get_all_state_changes(self):
        cursor = self.conn.cursor()
        result = cursor.execute(
            'SELECT * from state_changes'
        )
        return result.fetchall()

    def read(self):
        pass

    def last_identifier(self):
        cursor = self.conn.cursor()
        result = cursor.execute(
            'SELECT seq FROM sqlite_sequence WHERE name="state_changes"'
        )
        result = result.fetchall()
        if result != list():
            assert len(result) == 1
            result = result[0][0]
        else:
            result = 0
        return result

    def __del__(self):
        self.conn.close()


class StateChangeLog(object):

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
        # TODO: Issue 587
        # Implement a queue of state changes for batch writting
        serialized_data = self.serializer.serialize(state_change)
        self.storage.write_transaction(serialized_data)

    def get_transaction_by_id(self, identifier):
        serialized_data = self.storage.get_transaction_by_id(identifier)
        return self.serializer.deserialize(serialized_data)

    def last_identifier(self):
        return self.storage.last_identifier()

    def get_all_state_changes(self):
        """ Returns a list of tuples of identifiers and state changes"""
        return [
            (res[0], self.serializer.deserialize(res[1]))
            for res in self.storage.get_all_state_changes()
        ]

    def snapshot(self, state):
        serialized_data = self.serializer.serialize(state)
        self.storage.write_state_snapshot(self.last_identifier(), serialized_data)
