# -*- coding: utf-8 -*-
import os
import pickle
from collections import namedtuple

Transaction = namedtuple('Transaction', ('_id', 'state_change'))


# TODO:
# - use advisory locks
# - snapshots should be used to reduce the log file size
# - add log rotation


class TransactionLog(object):
    def __init__(self, transact_file, snapshot_file):
        self.transact_file = transact_file
        self.snapshot_file = snapshot_file

        self._id = 0  #: the currently used id (state_change ids start at 1)
        self._synced = False  #: True when the existing log is read to the end

    def __del__(self):
        self.transact_file.flush()
        self.transact_file.close()

    @classmethod
    def from_filename(self, filename):
        if os.path.exists(filename):
            mode = 'r+'
        else:
            mode = 'w+'
            self._synced = True

        file_handler = open(filename, mode, buffering=False)
        return TransactionLog(file_handler)

    def log(self, state_change):
        # make sure we are at the end of the whole file
        if not self._synced:
            list(self)

        self._id += 1

        transaction = Transaction(self._id, state_change)
        pickle.dump(transaction, self.transact_file)

    def snapshot(self, state):
        self.snapshot_file.truncate(0)
        pickle.dump(state, self.snapshot_file)

    def next(self):
        while not self._synced:
            try:
                transaction = pickle.load(self.transact_file)
                self._id = transaction._id
                yield transaction
            except EOFError:
                self._synced = True
                raise StopIteration()

    __next__ = next


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
