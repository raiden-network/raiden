import sqlite3
import threading
from contextlib import contextmanager

from raiden.constants import RAIDEN_DB_VERSION, SQLITE_MIN_REQUIRED_VERSION
from raiden.exceptions import InvalidDBData, InvalidNumberInput
from raiden.storage.serialize import SerializationBase
from raiden.storage.utils import DB_SCRIPT_CREATE_TABLES, TimestampedEvent
from raiden.utils import get_system_spec
from raiden.utils.typing import Any, Dict, Iterator, List, NamedTuple, Optional, Tuple, Union


class EventRecord(NamedTuple):
    event_identifier: int
    state_change_identifier: int
    data: Any


class StateChangeRecord(NamedTuple):
    state_change_identifier: int
    data: Any


class SnapshotRecord(NamedTuple):
    identifier: int
    state_change_identifier: int
    data: Any


def assert_sqlite_version() -> bool:
    if sqlite3.sqlite_version_info < SQLITE_MIN_REQUIRED_VERSION:
        return False
    return True


def _sanitize_limit_and_offset(limit: int = None, offset: int = None) -> Tuple[int, int]:
    if limit is not None and (not isinstance(limit, int) or limit < 0):
        raise InvalidNumberInput("limit must be a positive integer")

    if offset is not None and (not isinstance(offset, int) or offset < 0):
        raise InvalidNumberInput("offset must be a positive integer")

    limit = -1 if limit is None else limit
    offset = 0 if offset is None else offset
    return limit, offset


def _filter_from_dict(current: Dict[str, Any]) -> Dict[str, Any]:
    """Takes in a nested dictionary as a filter and returns a flattened filter dictionary"""
    filter_ = dict()

    for k, v in current.items():
        if isinstance(v, dict):
            for sub, v2 in _filter_from_dict(v).items():
                filter_[f"{k}.{sub}"] = v2
        else:
            filter_[k] = v

    return filter_


class SQLiteStorage:
    def __init__(self, database_path):
        conn = sqlite3.connect(database_path, detect_types=sqlite3.PARSE_DECLTYPES)
        conn.text_factory = str
        conn.execute("PRAGMA foreign_keys=ON")

        # Skip the acquire/release cycle for the exclusive write lock.
        # References:
        # https://sqlite.org/atomiccommit.html#_exclusive_access_mode
        # https://sqlite.org/pragma.html#pragma_locking_mode
        conn.execute("PRAGMA locking_mode=EXCLUSIVE")

        # Keep the journal around and skip inode updates.
        # References:
        # https://sqlite.org/atomiccommit.html#_persistent_rollback_journals
        # https://sqlite.org/pragma.html#pragma_journal_mode
        try:
            conn.execute("PRAGMA journal_mode=PERSIST")
        except sqlite3.DatabaseError:
            raise InvalidDBData(
                f"Existing DB {database_path} was found to be corrupt at Raiden startup. "
                f"Manual user intervention required. Bailing."
            )

        with conn:
            conn.executescript(DB_SCRIPT_CREATE_TABLES)

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
        self.conn = conn
        self.write_lock = threading.Lock()
        self.in_transaction = False

    def update_version(self):
        cursor = self.conn.cursor()
        cursor.execute(
            'INSERT OR REPLACE INTO settings(name, value) VALUES("version", ?)',
            (str(RAIDEN_DB_VERSION),),
        )
        self.maybe_commit()

    def log_run(self):
        """ Log timestamp and raiden version to help with debugging """
        version = get_system_spec()["raiden"]
        cursor = self.conn.cursor()
        cursor.execute("INSERT INTO runs(raiden_version) VALUES (?)", [version])
        self.maybe_commit()

    def get_version(self) -> int:
        cursor = self.conn.cursor()
        query = cursor.execute('SELECT value FROM settings WHERE name="version";')
        query = query.fetchall()
        # If setting is not set, it's the latest version
        if len(query) == 0:
            return RAIDEN_DB_VERSION

        return int(query[0][0])

    def count_state_changes(self) -> int:
        cursor = self.conn.cursor()
        query = cursor.execute("SELECT COUNT(1) FROM state_changes")
        query = query.fetchall()

        if len(query) == 0:
            return 0

        return int(query[0][0])

    def write_state_change(self, state_change, log_time):
        with self.write_lock, self.conn:
            cursor = self.conn.execute(
                "INSERT INTO state_changes(identifier, data, log_time) VALUES(null, ?, ?)",
                (state_change, log_time),
            )
            last_id = cursor.lastrowid

        return last_id

    def write_state_snapshot(self, statechange_id, snapshot):
        with self.write_lock, self.conn:
            cursor = self.conn.execute(
                "INSERT INTO state_snapshot(statechange_id, data) VALUES(?, ?)",
                (statechange_id, snapshot),
            )
            last_id = cursor.lastrowid

        return last_id

    def write_events(self, events):
        """ Save events.

        Args:
            state_change_identifier: Id of the state change that generate these events.
            events: List of Event objects.
        """
        with self.write_lock, self.conn:
            self.conn.executemany(
                "INSERT INTO state_events("
                "   identifier, source_statechange_id, log_time, data"
                ") VALUES(?, ?, ?, ?)",
                events,
            )

    def delete_state_changes(self, state_changes_to_delete: List[int]) -> None:
        """ Delete state changes.

        Args:
            state_changes_to_delete: List of ids to delete.
        """
        with self.write_lock, self.conn:
            self.conn.executemany(
                "DELETE FROM state_events WHERE identifier = ?", state_changes_to_delete
            )

    def get_latest_state_snapshot(self) -> Optional[Tuple[int, Any]]:
        """ Return the tuple of (last_applied_state_change_id, snapshot) or None"""
        cursor = self.conn.execute(
            "SELECT statechange_id, data from state_snapshot ORDER BY identifier DESC LIMIT 1"
        )
        rows = cursor.fetchall()

        if rows:
            assert len(rows) == 1
            last_applied_state_change_id = rows[0][0]
            snapshot_state = rows[0][1]
            return (last_applied_state_change_id, snapshot_state)

        return None

    def get_snapshot_closest_to_state_change(
        self, state_change_identifier: int
    ) -> Tuple[int, Any]:
        """ Get snapshots earlier than state_change with provided ID. """

        if not (state_change_identifier == "latest" or isinstance(state_change_identifier, int)):
            raise ValueError("from_identifier must be an integer or 'latest'")

        cursor = self.conn.cursor()
        if state_change_identifier == "latest":
            cursor.execute("SELECT identifier FROM state_changes ORDER BY identifier DESC LIMIT 1")
            result = cursor.fetchone()

            if result:
                state_change_identifier = result[0]
            else:
                state_change_identifier = 0

        cursor = self.conn.execute(
            "SELECT statechange_id, data FROM state_snapshot "
            "WHERE statechange_id <= ? "
            "ORDER BY identifier DESC LIMIT 1",
            (state_change_identifier,),
        )
        rows = cursor.fetchall()

        if rows:
            assert len(rows) == 1, "LIMIT 1 must return one element"
            last_applied_state_change_id = rows[0][0]
            snapshot_state = rows[0][1]
            result = (last_applied_state_change_id, snapshot_state)
        else:
            result = (0, None)

        return result

    def get_latest_event_by_data_field(self, filters: Dict[str, Any]) -> EventRecord:
        """ Return all state changes filtered by a named field and value."""
        cursor = self.conn.cursor()

        filters = _filter_from_dict(filters)
        where_clauses = []
        args = []
        for field, value in filters.items():
            where_clauses.append("json_extract(data, ?)=?")
            args.append(f"$.{field}")
            args.append(value)

        cursor.execute(
            "SELECT identifier, source_statechange_id, data FROM state_events WHERE "
            f"{' AND '.join(where_clauses)}"
            "ORDER BY identifier DESC LIMIT 1",
            args,
        )

        result = EventRecord(event_identifier=0, state_change_identifier=0, data=None)

        row = cursor.fetchone()
        if row:
            event_id = row[0]
            state_change_identifier = row[1]
            event = row[2]
            result = EventRecord(
                event_identifier=event_id,
                state_change_identifier=state_change_identifier,
                data=event,
            )

        return result

    def _form_and_execute_json_query(
        self,
        query: str,
        limit: int = None,
        offset: int = None,
        filters: List[Tuple[str, Any]] = None,
        logical_and: bool = True,
    ) -> sqlite3.Cursor:
        limit, offset = _sanitize_limit_and_offset(limit, offset)
        cursor = self.conn.cursor()
        where_clauses = []
        args: List[Union[str, int]] = []
        if filters:
            for field, value in filters:
                where_clauses.append(f"json_extract(data, ?) LIKE ?")
                args.append(f"$.{field}")
                args.append(value)

            if logical_and:
                query += f"WHERE {' AND '.join(where_clauses)}"
            else:
                query += f"WHERE {' OR '.join(where_clauses)}"

        query += "ORDER BY identifier ASC LIMIT ? OFFSET ?"
        args.append(limit)
        args.append(offset)

        cursor.execute(query, args)
        return cursor

    def get_latest_state_change_by_data_field(self, filters: Dict[str, Any]) -> StateChangeRecord:
        """ Return all state changes filtered by a named field and value."""
        cursor = self.conn.cursor()

        where_clauses = []
        args = []
        filters = _filter_from_dict(filters)
        for field, value in filters.items():
            where_clauses.append("json_extract(data, ?)=?")
            args.append(f"$.{field}")
            args.append(value)

        where = " AND ".join(where_clauses)
        sql = (
            f"SELECT identifier, data "
            f"FROM state_changes "
            f"WHERE {where} "
            f"ORDER BY identifier "
            f"DESC LIMIT 1"
        )
        cursor.execute(sql, args)

        result = StateChangeRecord(state_change_identifier=0, data=None)
        row = cursor.fetchone()
        if row:
            state_change_identifier = row[0]
            state_change = row[1]
            result = StateChangeRecord(
                state_change_identifier=state_change_identifier, data=state_change
            )

        return result

    def _get_state_changes(
        self,
        limit: int = None,
        offset: int = None,
        filters: List[Tuple[str, Any]] = None,
        logical_and: bool = True,
    ) -> List[StateChangeRecord]:
        """ Return a batch of state change records (identifier and data)

        The batch size can be tweaked with the `limit` and `offset` arguments.

        Additionally the returned state changes can be optionally filtered with
        the `filters` parameter to search for specific data in the state change data.
        """
        cursor = self._form_and_execute_json_query(
            query="SELECT identifier, data FROM state_changes ",
            limit=limit,
            offset=offset,
            filters=filters,
            logical_and=logical_and,
        )
        result = [StateChangeRecord(state_change_identifier=row[0], data=row[1]) for row in cursor]

        return result

    def batch_query_state_changes(
        self, batch_size: int, filters: List[Tuple[str, Any]] = None, logical_and: bool = True
    ) -> Iterator[List[StateChangeRecord]]:
        """Batch query state change records with a given batch size and an optional filter

        This is a generator function returning each batch to the caller to work with.
        """
        limit = batch_size
        offset = 0
        result_length = 1

        while result_length != 0:
            result = self._get_state_changes(
                limit=limit, offset=offset, filters=filters, logical_and=logical_and
            )
            result_length = len(result)
            offset += result_length
            yield result

    def update_state_changes(self, state_changes_data: List[Tuple[str, int]]) -> None:
        """Given a list of identifier/data state tuples update them in the DB"""
        cursor = self.conn.cursor()
        cursor.executemany(
            "UPDATE state_changes SET data=? WHERE identifier=?", state_changes_data
        )
        self.maybe_commit()

    def get_statechanges_by_identifier(self, from_identifier, to_identifier):
        if not (from_identifier == "latest" or isinstance(from_identifier, int)):
            raise ValueError("from_identifier must be an integer or 'latest'")

        if not (to_identifier == "latest" or isinstance(to_identifier, int)):
            raise ValueError("to_identifier must be an integer or 'latest'")

        cursor = self.conn.cursor()

        if from_identifier == "latest":
            assert to_identifier is None

            cursor.execute("SELECT identifier FROM state_changes ORDER BY identifier DESC LIMIT 1")
            from_identifier = cursor.fetchone()

        if to_identifier == "latest":
            cursor.execute(
                "SELECT data FROM state_changes WHERE identifier >= ? ORDER BY identifier ASC",
                (from_identifier,),
            )
        else:
            cursor.execute(
                "SELECT data FROM state_changes WHERE identifier "
                "BETWEEN ? AND ? ORDER BY identifier ASC",
                (from_identifier, to_identifier),
            )

        result = [entry[0] for entry in cursor]
        return result

    def _query_events(self, limit: int = None, offset: int = None):
        limit, offset = _sanitize_limit_and_offset(limit, offset)
        cursor = self.conn.cursor()

        cursor.execute(
            """
            SELECT data, log_time FROM state_events
                ORDER BY identifier ASC LIMIT ? OFFSET ?
            """,
            (limit, offset),
        )

        return cursor.fetchall()

    def _get_event_records(
        self,
        limit: int = None,
        offset: int = None,
        filters: List[Tuple[str, Any]] = None,
        logical_and: bool = True,
    ) -> List[EventRecord]:
        """ Return a batch of event records

        The batch size can be tweaked with the `limit` and `offset` arguments.

        Additionally the returned events can be optionally filtered with
        the `filters` parameter to search for specific data in the event data.
        """
        cursor = self._form_and_execute_json_query(
            query="SELECT identifier, source_statechange_id, data FROM state_events ",
            limit=limit,
            offset=offset,
            filters=filters,
            logical_and=logical_and,
        )

        result = [
            EventRecord(event_identifier=row[0], state_change_identifier=row[1], data=row[2])
            for row in cursor
        ]
        return result

    def batch_query_event_records(
        self, batch_size: int, filters: List[Tuple[str, Any]] = None, logical_and: bool = True
    ) -> Iterator[List[EventRecord]]:
        """Batch query event records with a given batch size and an optional filter

        This is a generator function returning each batch to the caller to work with.
        """
        limit = batch_size
        offset = 0
        result_length = 1

        while result_length != 0:
            result = self._get_event_records(
                limit=limit, offset=offset, filters=filters, logical_and=logical_and
            )
            result_length = len(result)
            offset += result_length
            yield result

    def update_events(self, events_data: List[Tuple[str, int]]) -> None:
        """Given a list of identifier/data event tuples update them in the DB"""
        cursor = self.conn.cursor()
        cursor.executemany("UPDATE state_events SET data=? WHERE identifier=?", events_data)
        self.maybe_commit()

    def get_events_with_timestamps(self, limit: int = None, offset: int = None):
        entries = self._query_events(limit, offset)
        return [TimestampedEvent(entry[0], entry[1]) for entry in entries]

    def get_events(self, limit: int = None, offset: int = None):
        entries = self._query_events(limit, offset)
        return [entry[0] for entry in entries]

    def get_state_changes(self, limit: int = None, offset: int = None):
        entries = self._get_state_changes(limit, offset)
        return [entry.data for entry in entries]

    def get_snapshots(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT identifier, statechange_id, data FROM state_snapshot")

        return [SnapshotRecord(snapshot[0], snapshot[1], snapshot[2]) for snapshot in cursor]

    def update_snapshot(self, identifier, new_snapshot):
        cursor = self.conn.cursor()
        cursor.execute(
            "UPDATE state_snapshot SET data=? WHERE identifier=?", (new_snapshot, identifier)
        )
        self.maybe_commit()

    def update_snapshots(self, snapshots_data: List[Tuple[str, int]]):
        """Given a list of snapshot data, update them in the DB

        The snapshots_data should be a list of tuples of snapshots data
        and identifiers in that order.
        """
        cursor = self.conn.cursor()
        cursor.executemany("UPDATE state_snapshot SET data=? WHERE identifier=?", snapshots_data)
        self.maybe_commit()

    def maybe_commit(self):
        if not self.in_transaction:
            self.conn.commit()

    @contextmanager
    def transaction(self):
        cursor = self.conn.cursor()
        self.in_transaction = True
        try:
            cursor.execute("BEGIN")
            yield
            cursor.execute("COMMIT")
        except:  # noqa
            cursor.execute("ROLLBACK")
            raise
        finally:
            self.in_transaction = False

    def __del__(self):
        self.conn.close()


class SerializedSQLiteStorage(SQLiteStorage):
    def __init__(self, database_path, serializer: SerializationBase):
        super().__init__(database_path)

        self.serializer = serializer

    def write_state_change(self, state_change, log_time):
        serialized_data = self.serializer.serialize(state_change)
        return super().write_state_change(serialized_data, log_time)

    def write_state_snapshot(self, statechange_id, snapshot):
        serialized_data = self.serializer.serialize(snapshot)
        return super().write_state_snapshot(statechange_id, serialized_data)

    def write_events(self, state_change_identifier, events, log_time):
        """ Save events.

        Args:
            state_change_identifier: Id of the state change that generate these events.
            events: List of Event objects.
        """
        events_data = [
            (None, state_change_identifier, log_time, self.serializer.serialize(event))
            for event in events
        ]
        return super().write_events(events_data)

    def get_latest_state_snapshot(self) -> Optional[Tuple[int, Any]]:
        """ Return the tuple of (last_applied_state_change_id, snapshot) or None"""
        row = super().get_latest_state_snapshot()

        if row:
            last_applied_state_change_id = row[0]
            snapshot_state = self.serializer.deserialize(row[1])
            return (last_applied_state_change_id, snapshot_state)

        return None

    def get_snapshot_closest_to_state_change(
        self, state_change_identifier: int
    ) -> Tuple[int, Any]:
        """ Get snapshots earlier than state_change with provided ID. """

        row = super().get_snapshot_closest_to_state_change(state_change_identifier)

        if row[1]:
            last_applied_state_change_id = row[0]
            snapshot_state = self.serializer.deserialize(row[1])
            result = (last_applied_state_change_id, snapshot_state)
        else:
            result = (0, None)

        return result

    def get_latest_event_by_data_field(self, filters: Dict[str, Any]) -> EventRecord:
        """ Return all state changes filtered by a named field and value."""
        event = super().get_latest_event_by_data_field(filters)

        if event.event_identifier > 0:
            event = EventRecord(
                event_identifier=event.event_identifier,
                state_change_identifier=event.state_change_identifier,
                data=self.serializer.deserialize(event.data),
            )

        return event

    def get_latest_state_change_by_data_field(self, filters: Dict[str, str]) -> StateChangeRecord:
        """ Return all state changes filtered by a named field and value."""

        state_change = super().get_latest_state_change_by_data_field(filters)

        if state_change.state_change_identifier > 0:
            state_change = StateChangeRecord(
                state_change_identifier=state_change.state_change_identifier,
                data=self.serializer.deserialize(state_change.data),
            )

        return state_change

    def get_statechanges_by_identifier(self, from_identifier, to_identifier):
        state_changes = super().get_statechanges_by_identifier(from_identifier, to_identifier)
        return [self.serializer.deserialize(state_change) for state_change in state_changes]

    def get_events_with_timestamps(self, limit: int = None, offset: int = None):
        events = super().get_events_with_timestamps(limit, offset)
        return [
            TimestampedEvent(self.serializer.deserialize(event.wrapped_event), event.log_time)
            for event in events
        ]

    def get_events(self, limit: int = None, offset: int = None):
        events = super().get_events(limit, offset)
        return [self.serializer.deserialize(event) for event in events]
