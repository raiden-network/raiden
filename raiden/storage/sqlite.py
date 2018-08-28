import sqlite3
import threading
from raiden.exceptions import InvalidDBData
from raiden.storage.utils import DB_SCRIPT_CREATE_TABLES
from typing import (
    Any,
    Optional,
    Tuple,
)

# The latest DB version
RAIDEN_DB_VERSION = 0


class SQLiteStorage:
    def __init__(self, database_path, serializer):
        conn = sqlite3.connect(database_path)
        conn.text_factory = str
        conn.execute('PRAGMA foreign_keys=ON')
        self.conn = conn

        with conn:
            try:
                conn.executescript(DB_SCRIPT_CREATE_TABLES)
            except sqlite3.DatabaseError:
                raise InvalidDBData(
                    'Existing DB {} was found to be corrupt at Raiden startup. '
                    'Manual user intervention required. Bailing ...'.format(database_path),
                )

        self._run_updates()

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
        self.serializer = serializer

    def _run_updates(self):
        # TODO: Here add upgrade mechanism depending on the version
        # current_version = self.get_version()

        # And finally at the end write the latest version in the DB
        cursor = self.conn.cursor()
        cursor.execute(
            'INSERT OR REPLACE INTO settings(name, value) VALUES(?, ?)',
            ('version', str(RAIDEN_DB_VERSION)),
        )
        self.conn.commit()

    def get_version(self) -> int:
        cursor = self.conn.cursor()
        query = cursor.execute(
            'SELECT value FROM settings WHERE name=?;', ('version',),
        )
        query = query.fetchall()
        # If setting is not set, it's the latest version
        if len(query) == 0:
            return RAIDEN_DB_VERSION

        return int(query[0][0])

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
        serialized_data = self.serializer.serialize(snapshot)

        with self.write_lock, self.conn:
            cursor = self.conn.execute(
                'INSERT INTO state_snapshot(statechange_id, data) VALUES(?, ?)',
                (statechange_id, serialized_data),
            )
            last_id = cursor.lastrowid

        return last_id

    def write_events(self, state_change_id, events):
        """ Save events.

        Args:
            state_change_id: Id of the state change that generate these events.
            events: List of Event objects.
        """
        events_data = [
            (None, state_change_id, self.serializer.serialize(event))
            for event in events
        ]

        with self.write_lock, self.conn:
            self.conn.executemany(
                'INSERT INTO state_events('
                '   identifier, source_statechange_id, data'
                ') VALUES(?, ?, ?)',
                events_data,
            )

    def get_latest_state_snapshot(self) -> Optional[Tuple[int, Any]]:
        """ Return the tuple of (last_applied_state_change_id, snapshot) or None"""
        cursor = self.conn.execute(
            'SELECT statechange_id, data from state_snapshot ORDER BY identifier DESC LIMIT 1',
        )
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

    def get_events(self, limit: int = None, offset: int = None):
        limit = -1 if limit is None else limit
        offset = 0 if offset is None else offset

        if not isinstance(limit, int):
            raise ValueError('limit must be an integer')

        if not isinstance(offset, int):
            raise ValueError('offset must be an integer')

        cursor = self.conn.cursor()

        cursor.execute(
            'SELECT data FROM state_events ORDER BY identifier ASC LIMIT ? OFFSET ?',
            (limit, offset),
        )

        result = [
            self.serializer.deserialize(entry[0])
            for entry in cursor.fetchall()
        ]
        return result

    def __del__(self):
        self.conn.close()
