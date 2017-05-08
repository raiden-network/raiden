# -*- coding: utf-8 -*-
import pickle
import sqlite3
from collections import namedtuple
from abc import ABCMeta, abstractmethod

from raiden.utils import create_file_iff_not_existing

DEFAULT_TRANSACTION_LOG_PATH = "transaction_log.db"
Transaction = namedtuple('Transaction', ('id', 'state_change'))


# TODO:
# - use advisory locks
# - snapshots should be used to reduce the log file size
# - add log rotation

class TransactionLogSerializer(object):
    """ TransactionLogSerializer

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


class PickleTransactionSerializer(TransactionLogSerializer):
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


class TransactionLogStorageBackend(object):
    """ TransactionLogStorageBackend

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


class TransactionLogSQLiteBackend(TransactionLogStorageBackend):

    def __init__(self, database_path=DEFAULT_TRANSACTION_LOG_PATH):
        self.conn = sqlite3.connect(database_path)
        self.conn.text_factory = str
        cursor = self.conn.cursor()
        cursor.execute(
            'CREATE TABLE IF NOT EXISTS transactions (id integer, data binary)'
        )
        cursor.execute(
            'CREATE TABLE IF NOT EXISTS state_snapshot (id integer, data binary)'
        )
        self.conn.commit()

    def write_transaction(self, identifier, data):
        cursor = self.conn.cursor()
        cursor.execute(
            'INSERT INTO transactions(id, data) VALUES(?,?)',
            (identifier, data)
        )
        self.conn.commit()

    def write_state_snapshot(self, identifier, data):
        cursor = self.conn.cursor()
        result = cursor.execute(
            'SELECT * from state_snapshot',
            (identifier, data)
        )
        result = result.fetchone()
        if result is None:
            cursor.execute(
                'INSERT INTO state_snapshot(id, data) VALUES(?,?)',
                (identifier, data)
            )
        else:
            cursor.execute(
                'UPDATE state_snapshot SET id=?, data=? WHERE id=?',
                (identifier, data, result[0])
            )
        self.conn.commit()

    def get_transaction_by_id(self, identifier):
        cursor = self.conn.cursor()
        result = cursor.execute(
            'SELECT data from transactions where id=?', (identifier,)
        )
        result = result.fetchall()
        assert len(result) == 1
        result = result[0][0]
        return result

    def read(self):
        pass

    def __del__(self):
        self.conn.close()


class TransactionLogFileBackend(TransactionLogStorageBackend):
    """This is just an example for having a file backend. Not actually implemented"""

    def __init__(self, filepath=DEFAULT_TRANSACTION_LOG_PATH):
        self.filepath = filepath
        self.file = create_file_iff_not_existing(
            self.filepath,
            return_it=True,
            mode='r+',
            buffering=False
        )
        self._synced = False  #: True when the existing log is read to the end

    def write_transaction(self, identifier, data):
        pass

    def write_state_snapshot(self, identifier, data):
        pass

    def read(self):
        pass

    def __del__(self):
        self.file.flush()
        self.file.close()


class TransactionLog(object):

    def __init__(
            self,
            storage_class=TransactionLogSQLiteBackend(),
            serializer_class=PickleTransactionSerializer()):

        if not issubclass(type(serializer_class), TransactionLogSerializer):
            raise ValueError('serializer_class must follow the TransactionLogSerializer interface')
        self.serializer = serializer_class

        if not issubclass(type(storage_class), TransactionLogStorageBackend):
            raise ValueError(
                'storage_class must follow the TransactionLogStorageBackend interface'
            )
        self.storage = storage_class

        # the currently used id (state_change ids start at 1)
        self.identifier = 0

    def log(self, state_change):
        self.identifier += 1
        serialized_data = self.serializer.serialize(state_change)
        self.storage.write_transaction(self.identifier, serialized_data)

    def get_transaction_by_id(self, identifier):
        serialized_data = self.storage.get_transaction_by_id(identifier)
        return self.serializer.deserialize(serialized_data)

    def snapshot(self, state):
        serialized_data = self.serializer.serialize(state)
        self.storage.write_state_snapshot(self.identifier, serialized_data)


def unapplied_state_changes(transaction_log, snapshot):
    """ Return a list of the operations that are in the log file but are not
    applied in the snapshot.
    """
    latest_identifier = snapshot.identifier
    previous_identifier = latest_identifier - 1

    # skip the operations from the log that are applied in the snapshot
    # this assumes the ides are serial
    if previous_identifier > 1:
        for transaction in transaction_log:
            if transaction.identifier >= previous_identifier:
                break

    return list(transaction_log)
