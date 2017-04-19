# -*- coding: utf-8 -*-
import pickle
from collections import namedtuple
from abc import ABCMeta, abstractmethod

from raiden.settings import DEFAULT_TRANSACTION_LOG_FILENAME
from raiden.utils import create_file_iff_not_existing

Transaction = namedtuple('Transaction', ('_id', 'state_change'))


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
        return pickle.dumps(transaction)

    def deserialize(self, data):
        return pickle.loads(data)


class TransactionLogStorageBackend(object):
    """ TransactionLogStorageBackend

        An abstract class defining the storage backend for the transaction log.
        Allows for pluggable storage backends.
    """
    __metaclass__ = ABCMeta

    @abstractmethod
    def write(self, data):
        pass

    @abstractmethod
    def read(self):
        pass


class TransactionLogSQLiteBackend(TransactionLogStorageBackend):

    def write(self, data):
        pass

    def read(self):
        pass


class TransactionLogFileBackend(TransactionLogStorageBackend):

    def __init__(self, filepath=DEFAULT_TRANSACTION_LOG_FILENAME):
        self.filepath = filepath
        self.file = create_file_iff_not_existing(
            self.filepath,
            return_it=True,
            mode='r+',
            buffering=False
        )
        self._synced = False  #: True when the existing log is read to the end

    def write(self, data):
        self.file.write(data)

    def read(self):
        pass

    def __del__(self):
        self.file.flush()
        self.file.close()


class TransactionLog(object):

    def __init__(
            self,
            serializer_type='pickle',
            storage_type='sqlite'):

        if serializer_type != 'pickle':
            raise ValueError('invalid value for serializer_type')
        self.serializer = PickleTransactionSerializer()

        if storage_type == 'sqlite':
            self.storage = TransactionLogSQLiteBackend()
        elif storage_type == 'file':
            self.storage = TransactionLogFileBackend()
        else:
            raise ValueError('invalid value for storage_type')

        self._id = 0  #: the currently used id (state_change ids start at 1)

    def log(self, state_change):
        self._id += 1

        transaction = Transaction(self._id, state_change)
        serialized_data = self.serializer.serialize(transaction)
        self.storage.write(serialized_data)

    def snapshot(self, state):
        raise NotImplementedError()
        self.snapshot_file.truncate(0)
        pickle.dump(state, self.snapshot_file)


def unapplied_state_changes(transaction_log, snapshot):
    """ Return a list of the operations that are in the log file but are not
    applied in the snapshot.
    """
    latest_id = snapshot._id
    previous_id = latest_id - 1

    # skip the operations from the log that are applied in the snapshot
    # this assumes the ides are serial
    if previous_id > 1:
        for transaction in transaction_log:
            if transaction._id >= previous_id:
                break

    return list(transaction_log)
