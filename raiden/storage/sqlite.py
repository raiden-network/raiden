import sqlite3
import threading
from raiden.exceptions import InvalidDBData
from typing import (
    Any,
    Optional,
    Tuple,
)


class SQLiteStorage:
    def __init__(self, database_path, serializer):
        conn = sqlite3.connect(database_path)
        conn.text_factory = str
        conn.execute('PRAGMA foreign_keys=ON')

        with conn:
            cursor = conn.cursor()
            cursor.execute(
                'CREATE TABLE IF NOT EXISTS state_changes ('
                '    identifier INTEGER PRIMARY KEY AUTOINCREMENT, '
                '    data BINARY'
                ')',
            )
            cursor.execute(
                'CREATE TABLE IF NOT EXISTS state_snapshot ('
                '    identifier INTEGER PRIMARY KEY, '
                '    statechange_id INTEGER, '
                '    data BINARY, '
                '    FOREIGN KEY(statechange_id) REFERENCES state_changes(identifier)'
                ')',
            )
            cursor.execute(
                'CREATE TABLE IF NOT EXISTS state_events ('
                '    identifier INTEGER PRIMARY KEY, '
                '    source_statechange_id INTEGER NOT NULL, '
                '    block_number INTEGER NOT NULL, '
                '    data BINARY, '
                '    FOREIGN KEY(source_statechange_id) REFERENCES state_changes(identifier)'
                ')',
            )

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
        self.conn = conn
        self.serializer = serializer

    def write_state_change(self, state_change):
        serialized_data = self.serializer.serialize(state_change)

        with self.write_lock, self.conn:
            cursor = self.conn.execute(
                'INSERT INTO state_changes(identifier, data) VALUES(null, ?)',
                (serialized_data,),
            )
            last_id = cursor.lastrowid

        return last_id

    def write_state_snapshot(self, statechange_id, snapshot):
        # TODO: Snapshotting is not yet implemented. This is just skeleton code
        # (Issue #682)
        #
        # This skeleton code assumes we only keep a single snapshot and
        # overwrite it each time.
        serialized_data = self.serializer.serialize(snapshot)

        with self.write_lock, self.conn:
            cursor = self.conn.execute(
                'INSERT OR REPLACE INTO state_snapshot('
                '    identifier, statechange_id, data'
                ') VALUES(?, ?, ?)',
                (1, statechange_id, serialized_data),
            )
            last_id = cursor.lastrowid

        return last_id

    def write_events(self, state_change_id, block_number, events):
        """ Save events.

        Args:
            state_change_id: Id of the state change that generate these events.
            block_number: Block number at which the state change was applied.
            events: List of Event objects.
        """
        events_data = [
            (None, state_change_id, block_number, self.serializer.serialize(event))
            for event in events
        ]

        with self.write_lock, self.conn:
            self.conn.executemany(
                'INSERT INTO state_events('
                '   identifier, source_statechange_id, block_number, data'
                ') VALUES(?, ?, ?, ?)',
                events_data,
            )

    def get_state_snapshot(self) -> Optional[Tuple[int, Any]]:
        """ Return the tuple of (last_applied_state_change_id, snapshot) or None"""
        cursor = self.conn.execute('SELECT statechange_id, data from state_snapshot')
        serialized = cursor.fetchall()

        result = None
        if serialized:
            assert len(serialized) == 1
            last_applied_state_change_id = serialized[0][0]
            snapshot_state = self.serializer.deserialize(serialized[0][1])
            return (last_applied_state_change_id, snapshot_state)

        return result

    def get_statechanges_by_identifier(self, from_identifier, to_identifier):
        if not (from_identifier == 'latest' or isinstance(from_identifier, int)):
            raise ValueError("from_identifier must be an integer or 'latest'")

        if not (to_identifier == 'latest' or isinstance(to_identifier, int)):
            raise ValueError("to_identifier must be an integer or 'latest'")

        cursor = self.conn.cursor()

        if from_identifier == 'latest':
            assert to_identifier is None

            cursor.execute(
                'SELECT identifier FROM state_changes ORDER BY identifier DESC LIMIT 1',
            )
            from_identifier = cursor.fetchone()

        if to_identifier == 'latest':
            cursor.execute(
                'SELECT data FROM state_changes WHERE identifier >= ?',
                (from_identifier,),
            )
        else:
            cursor.execute(
                'SELECT data FROM state_changes WHERE identifier '
                'BETWEEN ? AND ?', (from_identifier, to_identifier),
            )

        try:
            result = [
                self.serializer.deserialize(entry[0])
                for entry in cursor.fetchall()
            ]
        except AttributeError:
            raise InvalidDBData(
                'Your local database is corrupt. Bailing ...',
            )

        return result

    def get_events_by_identifier(self, from_identifier, to_identifier):
        if not (from_identifier == 'latest' or isinstance(from_identifier, int)):
            raise ValueError("from_identifier must be an integer or 'latest'")

        if not (to_identifier == 'latest' or isinstance(to_identifier, int)):
            raise ValueError("to_identifier must be an integer or 'latest'")

        cursor = self.conn.cursor()

        if from_identifier == 'latest':
            assert to_identifier is None

            cursor.execute(
                'SELECT identifier FROM state_events ORDER BY identifier DESC LIMIT 1',
            )
            from_identifier = cursor.fetchone()

        if to_identifier == 'latest':
            cursor.execute(
                'SELECT block_number, data FROM state_events WHERE identifier >= ?',
                (from_identifier,),
            )
        else:
            cursor.execute(
                'SELECT block_number, data FROM state_events WHERE identifier '
                'BETWEEN ? AND ?', (from_identifier, to_identifier),
            )

        result = [
            (entry[0], self.serializer.deserialize(entry[1]))
            for entry in cursor.fetchall()
        ]
        return result

    def get_events_by_block(self, from_block, to_block):
        if not (from_block == 'latest' or isinstance(from_block, int)):
            raise ValueError("from_block must be an integer or 'latest'")

        if not (to_block == 'latest' or isinstance(to_block, int)):
            raise ValueError("to_block must be an integer or 'latest'")

        cursor = self.conn.cursor()

        if from_block is None:
            from_block = 0

        if from_block == 'latest':
            assert to_block is None

            cursor.execute(
                'SELECT block_number FROM state_events ORDER BY block_number DESC LIMIT 1',
            )
            from_block = cursor.fetchone()

        if to_block == 'latest':
            cursor.execute(
                'SELECT block_number, data FROM state_events WHERE block_number >= ?',
                (from_block, ),
            )
        else:
            cursor.execute(
                'SELECT block_number, data FROM state_events WHERE block_number '
                'BETWEEN ? AND ?', (from_block, to_block),
            )

        result = [
            (entry[0], self.serializer.deserialize(entry[1]))
            for entry in cursor.fetchall()
        ]
        return result

    def __del__(self):
        self.conn.close()
