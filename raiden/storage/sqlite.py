import sqlite3
from contextlib import contextmanager
from datetime import datetime
from enum import Enum
from pathlib import Path

from raiden.constants import RAIDEN_DB_VERSION, SQLITE_MIN_REQUIRED_VERSION
from raiden.exceptions import InvalidDBData, InvalidNumberInput
from raiden.storage.serialization import SerializationBase
from raiden.storage.ulid import ULID, ULIDMonotonicFactory
from raiden.storage.utils import DB_SCRIPT_CREATE_TABLES, TimestampedEvent
from raiden.transfer.architecture import Event, State, StateChange
from raiden.utils import get_system_spec
from raiden.utils.typing import (
    Any,
    Dict,
    Iterator,
    List,
    NamedTuple,
    NewType,
    Optional,
    RaidenDBVersion,
    Tuple,
    Union,
    cast,
)

StateChangeID = NewType("StateChangeID", ULID)
SnapshotID = NewType("SnapshotID", ULID)
EventID = NewType("EventID", ULID)
NULL_ULID = ULID((0).to_bytes(16, "big"))


class Operator(Enum):
    NONE = ""
    AND = "AND"
    OR = "OR"


class FilteredDBQuery(NamedTuple):
    """
    FilteredDBQuery is a datastructure that helps
    form a list of conditions and how they're grouped
    in order to form more complicated queries
    on the internal JSON representation
    of states / state changes and events.
    Note that it is not used to search
    the top-level attributes of the sqlite tables.
    """

    filters: List[Dict[str, Any]]
    main_operator: Operator
    inner_operator: Operator


class EventRecord(NamedTuple):
    event_identifier: EventID
    state_change_identifier: StateChangeID
    data: Any


class StateChangeRecord(NamedTuple):
    state_change_identifier: StateChangeID
    data: Any


class SnapshotRecord(NamedTuple):
    identifier: SnapshotID
    state_change_identifier: StateChangeID
    data: Any


def assert_sqlite_version() -> bool:  # pragma: no unittest
    if sqlite3.sqlite_version_info < SQLITE_MIN_REQUIRED_VERSION:
        return False
    return True


def adapt_ulid_identifier(ulid: ULID) -> bytes:
    return ulid.identifier


def convert_ulid_identifier(data: bytes) -> ULID:
    return ULID(identifier=data)


def _sanitize_limit_and_offset(limit: int = None, offset: int = None) -> Tuple[int, int]:
    if limit is not None and (not isinstance(limit, int) or limit < 0):  # pragma: no unittest
        raise InvalidNumberInput("limit must be a positive integer")

    if offset is not None and (not isinstance(offset, int) or offset < 0):  # pragma: no unittest
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


def _query_to_string(query: FilteredDBQuery) -> Tuple[str, List[str]]:
    """
    Converts a query object to a valid SQL string
    which can be used in the WHERE clause.
    A query object will contain a list of dictionaries
    where each key-value pair is used to filter records.
    All the key-value pairs in a dictionary are grouped
    together by `inner_operator` so that they form a SQL condition
    indepedently from other dictionaries in the list.

    Examples:
    - Performing a query with 1 filter
    FilteredDBQuery(
      filters=[{'a': 1, 'b': 2}],
      main_operator=NONE,
      inner_operator='AND'
    )
    Will result in:
    (a=1 AND b=2)

    - Performing a query with multiple filters
      `inner_operator` is used in the inner subqueries
      of the key-value pairs in a single dictionary.
      While `main_operator` is used in the outer query.

    FilteredDBQuery(
      filters=[
        {'a': 1, 'b': 2},
        {'c': 3, 'd': 4},
      ],
      main_operator='OR',
      inner_operator='AND'
    )
    Will result in:
    (a=1 AND b=2) OR (c=3 AND d=4)
    """

    query_where = []
    args = []
    for filter_set in query.filters:
        where_clauses = []
        filters = _filter_from_dict(filter_set)
        for field, value in filters.items():
            where_clauses.append("json_extract(data, ?)=?")
            args.append(f"$.{field}")
            args.append(value)

        filter_set_str = f" {query.inner_operator.value} ".join(where_clauses)
        query_where.append(f"({filter_set_str}) ")
    query_where_str = f" {query.main_operator.value} ".join(query_where)
    return query_where_str, args


class SQLiteStorage:
    def __init__(self, database_path: Path):
        sqlite3.register_adapter(ULID, adapt_ulid_identifier)
        sqlite3.register_converter("ULID", convert_ulid_identifier)

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

        self.conn = conn
        self.in_transaction = False
        self._ulid_factories: Dict[str, ULIDMonotonicFactory] = dict()

    def _ulid_factory(self, table_name: str) -> ULIDMonotonicFactory:
        """Return an ULID Factory for a specific table.

        In order to guarantee ID monotonicity for a specific table it's
        necessary to pick up the ID from the last run and restore the
        timestamp. Since there is no global storage to store the last timestamp
        across the whole database each table gets its own factory. The
        alternative would require a scan over all tables, because scanning
        would be error prone (it would depend on configuration of which tables
        have an ULID), this is not done.
        """
        assert table_name not in (None, ""), "A table name must be provided"

        factory = self._ulid_factories.get(table_name)

        if factory is None:
            cursor = self.conn.cursor()

            # Check the table name to avoid SQL injection
            query_table_exists = cursor.execute(
                "SELECT name FROM sqlite_master WHERE name=?", (table_name,)
            )
            assert query_table_exists.fetchone(), f"The table {table_name} does not exist."

            # At this point it should be safe to interpolate the table_name in
            # the SQL because the name was checked above.
            query_last_id = cursor.execute(
                f"SELECT identifier FROM {table_name} ORDER BY identifier DESC LIMIT 1"
            )
            result = query_last_id.fetchone()

            if result:
                timestamp = result[0].timestamp
            else:
                timestamp = None

            factory = ULIDMonotonicFactory(start=timestamp)
            self._ulid_factories[table_name] = factory

        return factory

    def update_version(self) -> None:
        cursor = self.conn.cursor()
        cursor.execute(
            'INSERT OR REPLACE INTO settings(name, value) VALUES("version", ?)',
            (str(RAIDEN_DB_VERSION),),
        )
        self.maybe_commit()

    def log_run(self) -> None:
        """ Log timestamp and raiden version to help with debugging """
        version = get_system_spec()["raiden"]
        cursor = self.conn.cursor()
        cursor.execute("INSERT INTO runs(raiden_version) VALUES (?)", [version])
        self.maybe_commit()

    def get_version(self) -> RaidenDBVersion:
        cursor = self.conn.cursor()
        query = cursor.execute('SELECT value FROM settings WHERE name="version";')
        result = query.fetchall()
        # If setting is not set, it's the latest version
        if len(result) == 0:
            return RAIDEN_DB_VERSION

        return RaidenDBVersion(int(result[0][0]))

    def count_state_changes(self) -> int:
        cursor = self.conn.cursor()
        query = cursor.execute("SELECT COUNT(1) FROM state_changes")
        result = query.fetchall()

        if len(result) == 0:
            return 0

        return int(result[0][0])

    def write_state_change(self, state_change: StateChange, timestamp: datetime) -> StateChangeID:
        state_change_id = StateChangeID(self._ulid_factory("state_changes").new())

        self.conn.execute(
            "INSERT INTO state_changes(identifier, data, timestamp) VALUES(?, ?, ?)",
            (state_change_id, state_change, timestamp),
        )
        self.maybe_commit()

        return state_change_id

    def write_state_snapshot(
        self, snapshot: str, statechange_id: StateChangeID, timestamp: datetime
    ) -> SnapshotID:
        snapshot_id = SnapshotID(self._ulid_factory("state_snapshot").new())

        query = (
            "INSERT INTO state_snapshot ("
            " identifier, statechange_id, data, timestamp"
            ") VALUES(?, ?, ?, ?)"
        )
        self.conn.execute(query, (snapshot_id, statechange_id, snapshot, timestamp))
        self.maybe_commit()

        return snapshot_id

    def write_events(self, events: List[Tuple[StateChangeID, datetime, str]]) -> List[EventID]:
        """ Save events.

        Args:
            state_change_identifier: Id of the state change that generate these events.
            events: List of Event objects.
        """
        ulid_factory = self._ulid_factory("state_events")
        events_ids: List[ULID] = list()

        query = (
            "INSERT INTO state_events("
            "   identifier, source_statechange_id, timestamp, data"
            ") VALUES(?, ?, ?, ?)"
        )
        self.conn.executemany(query, ulid_factory.prepend_and_save_ids(events_ids, events))
        self.maybe_commit()

        return cast(List[EventID], events_ids)

    def delete_state_changes(self, state_changes_to_delete: List[Tuple[StateChangeID]]) -> None:
        """ Delete state changes.

        Args:
            state_changes_to_delete: List of ids to delete.
        """
        self.conn.executemany(
            "DELETE FROM state_changes WHERE identifier = ?", state_changes_to_delete
        )
        self.maybe_commit()

    def get_latest_state_snapshot(self) -> Optional[SnapshotRecord]:
        """ Return the tuple of (last_applied_state_change_id, snapshot) or None"""
        cursor = self.conn.execute(
            "SELECT identifier, statechange_id, data "
            "FROM state_snapshot "
            "ORDER BY identifier "
            "DESC LIMIT 1"
        )
        rows = cursor.fetchall()

        if rows:
            assert len(rows) == 1
            snapshot_state_id = rows[0][0]
            last_applied_state_change_id = rows[0][1]
            snapshot_state = rows[0][2]
            return SnapshotRecord(snapshot_state_id, last_applied_state_change_id, snapshot_state)

        return None

    def get_snapshot_closest_to_state_change(
        self, state_change_identifier: Union[StateChangeID, str]
    ) -> Optional[SnapshotRecord]:
        """ Get snapshots earlier than state_change with provided ID. """

        is_valid_identifier = state_change_identifier in ("earliest", "latest") or isinstance(
            state_change_identifier, ULID
        )

        if not is_valid_identifier:  # pragma: no unittest
            raise ValueError("from_identifier must be an ULID, 'earliest' or 'latest'")

        cursor = self.conn.cursor()
        if state_change_identifier == "latest":
            cursor.execute("SELECT identifier FROM state_changes ORDER BY identifier DESC LIMIT 1")
            result = cursor.fetchone()

            if result:
                state_change_identifier = result[0]
            else:
                state_change_identifier = StateChangeID(NULL_ULID)

        elif state_change_identifier == "earliest":
            cursor.execute("SELECT identifier FROM state_changes ORDER BY identifier ASC LIMIT 1")
            result = cursor.fetchone()

            if result:
                state_change_identifier = result[0]
            else:
                state_change_identifier = StateChangeID(NULL_ULID)

        cursor = self.conn.execute(
            "SELECT identifier, statechange_id, data FROM state_snapshot "
            "WHERE statechange_id <= ? "
            "ORDER BY identifier DESC LIMIT 1",
            (state_change_identifier,),
        )

        rows = cursor.fetchall()

        if rows:
            assert len(rows) == 1, "LIMIT 1 must return one element"
            identifier = rows[0][0]
            last_applied_state_change_id = rows[0][1]
            snapshot_state = rows[0][2]
            result = SnapshotRecord(identifier, last_applied_state_change_id, snapshot_state)
        else:
            result = None

        return result

    def get_latest_event_by_data_field(self, query: FilteredDBQuery) -> Optional[EventRecord]:
        """ Return all state changes filtered by a named field and value."""
        cursor = self.conn.cursor()

        query_str, args = _query_to_string(query)

        cursor.execute(
            f"SELECT identifier, source_statechange_id, data FROM state_events WHERE "
            f"{query_str}"
            f"ORDER BY identifier DESC LIMIT 1",
            args,
        )

        result = None

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

    def get_latest_state_change_by_data_field(
        self, query: FilteredDBQuery
    ) -> Optional[StateChangeRecord]:
        """ Return all state changes filtered by a named field and value."""
        cursor = self.conn.cursor()

        query_str, args = _query_to_string(query)

        sql = (
            f"SELECT identifier, data "
            f"FROM state_changes "
            f"WHERE {query_str} "
            f"ORDER BY identifier "
            f"DESC LIMIT 1"
        )
        cursor.execute(sql, args)

        result = None
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

    def get_statechanges_by_identifier(
        self, from_identifier: Union[StateChangeID, str], to_identifier: Union[StateChangeID, str]
    ) -> List[StateChangeRecord]:
        is_valid_from_identifier = from_identifier in ("latest", "earliest") or isinstance(
            from_identifier, ULID
        )
        if not is_valid_from_identifier:  # pragma: no unittest
            raise ValueError("from_identifier must be an ULID, 'earliest' or 'latest'")

        is_valid_to_identifier = to_identifier in ("latest", "earliest") or isinstance(
            to_identifier, ULID
        )
        if not is_valid_to_identifier:  # pragma: no unittest
            raise ValueError("to_identifier must be an ULID, 'earliest'  or 'latest'")

        cursor = self.conn.cursor()

        from_: ULID
        if from_identifier == "earliest":
            from_ = NULL_ULID
        elif from_identifier == "latest":
            assert to_identifier is None

            cursor.execute("SELECT identifier FROM state_changes ORDER BY identifier DESC LIMIT 1")
            from_ = cursor.fetchone()
        else:
            assert isinstance(from_identifier, ULID)
            from_ = from_identifier

        if to_identifier == "latest":
            query = (
                "SELECT identifier, data "
                "FROM state_changes "
                "WHERE identifier >= ? "
                "ORDER BY identifier ASC"
            )
            cursor.execute(query, (from_,))
        else:
            cursor.execute(
                "SELECT identifier, data FROM state_changes WHERE identifier "
                "BETWEEN ? AND ? ORDER BY identifier ASC",
                (from_, to_identifier),
            )

        return [
            StateChangeRecord(state_change_identifier=entry[0], data=entry[1]) for entry in cursor
        ]

    def _query_events(self, limit: int = None, offset: int = None) -> List[Tuple[str, datetime]]:
        limit, offset = _sanitize_limit_and_offset(limit, offset)
        cursor = self.conn.cursor()

        cursor.execute(
            """
            SELECT data, timestamp FROM state_events
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

    def get_events_with_timestamps(
        self, limit: int = None, offset: int = None
    ) -> List[TimestampedEvent]:
        entries = self._query_events(limit, offset)
        return [TimestampedEvent(entry[0], entry[1]) for entry in entries]

    def get_events(self, limit: int = None, offset: int = None) -> List[str]:
        entries = self._query_events(limit, offset)
        return [entry[0] for entry in entries]

    def get_state_changes(self, limit: int = None, offset: int = None) -> List[str]:
        entries = self._get_state_changes(limit, offset)
        return [entry.data for entry in entries]

    def get_snapshots(self) -> List[SnapshotRecord]:
        cursor = self.conn.cursor()
        cursor.execute("SELECT identifier, statechange_id, data FROM state_snapshot")

        return [SnapshotRecord(snapshot[0], snapshot[1], snapshot[2]) for snapshot in cursor]

    def update_snapshot(self, identifier: SnapshotID, new_snapshot: str) -> None:
        cursor = self.conn.cursor()
        cursor.execute(
            "UPDATE state_snapshot SET data=? WHERE identifier=?", (new_snapshot, identifier)
        )
        self.maybe_commit()

    def update_snapshots(self, snapshots_data: List[Tuple[str, SnapshotID]]) -> None:
        """Given a list of snapshot data, update them in the DB

        The snapshots_data should be a list of tuples of snapshots data
        and identifiers in that order.
        """
        cursor = self.conn.cursor()
        cursor.executemany("UPDATE state_snapshot SET data=? WHERE identifier=?", snapshots_data)
        self.maybe_commit()

    def maybe_commit(self) -> None:
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

    def close(self) -> None:
        if not hasattr(self, "conn"):
            raise RuntimeError("The database connection was closed already.")

        self.conn.close()
        del self.conn

    def __del__(self):
        if hasattr(self, "conn"):
            raise RuntimeError("The database connection was not closed.")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):  # pylint: disable=unused-arguments
        self.close()


class SerializedSQLiteStorage:
    def __init__(self, database_path: Path, serializer: SerializationBase) -> None:
        self.database = SQLiteStorage(database_path)
        self.serializer = serializer

    def update_version(self) -> None:  # pragma: no unittest
        self.database.update_version()

    def count_state_changes(self) -> int:
        return self.database.count_state_changes()

    def get_version(self) -> RaidenDBVersion:
        return self.database.get_version()

    def log_run(self) -> None:
        self.database.log_run()

    def write_state_change(self, state_change: StateChange, timestamp: datetime) -> StateChangeID:
        serialized_data = self.serializer.serialize(state_change)
        return self.database.write_state_change(serialized_data, timestamp)

    def write_state_snapshot(
        self, snapshot: State, statechange_id: StateChangeID, timestamp: datetime
    ) -> SnapshotID:
        serialized_data = self.serializer.serialize(snapshot)
        return self.database.write_state_snapshot(serialized_data, statechange_id, timestamp)

    def write_events(
        self, state_change_identifier: StateChangeID, events: List[Event], timestamp: datetime
    ) -> List[EventID]:
        """ Save events.

        Args:
            state_change_identifier: Id of the state change that generate these events.
            events: List of Event objects.
        """
        events_data = [
            (state_change_identifier, timestamp, self.serializer.serialize(event))
            for event in events
        ]
        return self.database.write_events(events_data)

    def get_latest_state_snapshot(self) -> Optional[SnapshotRecord]:
        """ Return the tuple of (last_applied_state_change_id, snapshot) or None"""
        row = self.database.get_latest_state_snapshot()

        if row:
            snapshot_state = self.serializer.deserialize(row.data)
            return SnapshotRecord(row.identifier, row.state_change_identifier, snapshot_state)

        return None

    def get_snapshot_closest_to_state_change(
        self, state_change_identifier: Union[StateChangeID, str]
    ) -> Optional[SnapshotRecord]:
        """ Get snapshots earlier than state_change with provided ID. """
        result: Optional[SnapshotRecord]

        row = self.database.get_snapshot_closest_to_state_change(state_change_identifier)

        if row is not None:
            result = SnapshotRecord(
                row.identifier, row.state_change_identifier, self.serializer.deserialize(row.data)
            )
        else:
            result = None

        return result

    def get_latest_event_by_data_field(self, query: FilteredDBQuery) -> Optional[EventRecord]:
        """ Return all state changes filtered by a named field and value."""
        event = self.database.get_latest_event_by_data_field(query)

        if event is not None:
            event = EventRecord(
                event_identifier=event.event_identifier,
                state_change_identifier=event.state_change_identifier,
                data=self.serializer.deserialize(event.data),
            )

        return event

    def get_latest_state_change_by_data_field(
        self, query: FilteredDBQuery
    ) -> Optional[StateChangeRecord]:
        """ Return all state changes filtered by a named field and value."""

        state_change = self.database.get_latest_state_change_by_data_field(query)

        if state_change is not None:
            state_change = StateChangeRecord(
                state_change_identifier=state_change.state_change_identifier,
                data=self.serializer.deserialize(state_change.data),
            )

        return state_change

    def get_statechanges_by_identifier(
        self, from_identifier: Union[StateChangeID, str], to_identifier: Union[StateChangeID, str]
    ) -> List[StateChangeRecord]:
        state_changes = self.database.get_statechanges_by_identifier(
            from_identifier, to_identifier
        )
        return [
            StateChangeRecord(
                state_change_identifier=state_change.state_change_identifier,
                data=self.serializer.deserialize(state_change.data),
            )
            for state_change in state_changes
        ]

    def get_events_with_timestamps(
        self, limit: int = None, offset: int = None
    ) -> List[TimestampedEvent]:
        events = self.database.get_events_with_timestamps(limit, offset)
        return [
            TimestampedEvent(self.serializer.deserialize(event.wrapped_event), event.log_time)
            for event in events
        ]

    def get_events(self, limit: int = None, offset: int = None) -> List[Event]:
        events = self.database.get_events(limit, offset)
        return [self.serializer.deserialize(event) for event in events]

    def get_state_changes(self, limit: int = None, offset: int = None) -> List[StateChange]:
        state_changes = self.database.get_state_changes(limit, offset)
        return [self.serializer.deserialize(state_change) for state_change in state_changes]

    def close(self) -> None:
        self.database.close()
