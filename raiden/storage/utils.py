"""
Notes:

Every primary key *MUST* also have *NOT NULL* specified [1].

`WITHOUT ROWID` [2] was considered, in order to force sqlite3 to use "proper"
clustered indexes and to enforce the NOT NULL constraint for primary keys.
However the write/read pattern for Raiden does not fall under the recommended
categories, and some important features of the database won't work with that
flag. Instead of `WITHOUT ROWID` the implicit rowid column is used.

Using an explicit `INTEGER PRIMARY KEY` [3] was considered, however 64 bits
are too few to fit a well ordered ID with nanosecond precision and a random
tag.

The primary key is *not* auto-increment because the IDs are populated with
ULIDs [7]. ULIDs are necessary because the application must know the ID of
elements inserted in bulk, and this cannot be know reliably if auto increment
is used, even with synchronizaiton over `lastrowid`. Additionally random IDs
are less likely to collide, which is useful to detect programming errors. Typos
are a good example that can have catastrophic results, where REPLACE/DELETE
queries can operate on the wrong table or column and with the possibility of
collision change the wrong data.

ULIDs are necessary over UUIDs because they are lexicographically sortable by
design, and state changes must be saved in order. This has the additional
benefit of being a good write pattren, even though the implicit clustered index
based on rowid will prevent large rewrites of the DB's tables, using ULIDs
prevent rewrites of the PK Index.

Manifest typing [4] is used for the ULIDs instead PARSE_COLNAMES [5] because
of the easy of conversion.

1- https://www.sqlite.org/lang_createtable.html#constraints
2- https://www.sqlite.org/withoutrowid.html
3- https://www.sqlite.org/lang_createtable.html#rowid
4- https://www.sqlite.org/different.html#typing
5- https://docs.python.org/3/library/sqlite3.html#sqlite3.PARSE_COLNAMES
6- https://tools.ietf.org/html/rfc4122.html
7- https://github.com/ulid/spec
"""
from dataclasses import dataclass
from datetime import datetime

from raiden.transfer.architecture import Event


@dataclass
class TimestampedEvent:
    event: Event
    log_time: datetime

    def __getattr__(self, item: str) -> Event:
        return getattr(self.event, item)


DB_CREATE_SETTINGS = """
CREATE TABLE IF NOT EXISTS settings (
    name VARCHAR[24] UNIQUE PRIMARY KEY NOT NULL,
    value TEXT
);
"""

DB_CREATE_STATE_CHANGES = """
CREATE TABLE IF NOT EXISTS state_changes (
    identifier ULID PRIMARY KEY NOT NULL,
    data JSON,
    timestamp TIMESTAMP DEFAULT(STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW')) NOT NULL
);
"""

DB_CREATE_SNAPSHOT = """
CREATE TABLE IF NOT EXISTS state_snapshot (
    identifier ULID PRIMARY KEY NOT NULL,
    statechange_id ULID UNIQUE,
    statechange_qty INTEGER,
    data JSON,
    timestamp TIMESTAMP DEFAULT(STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW')) NOT NULL,
    FOREIGN KEY(statechange_id) REFERENCES state_changes(identifier)
);
"""

DB_CREATE_STATE_EVENTS = """
CREATE TABLE IF NOT EXISTS state_events (
    identifier ULID PRIMARY KEY NOT NULL,
    source_statechange_id ULID NOT NULL,
    data JSON,
    timestamp TIMESTAMP DEFAULT(STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW')) NOT NULL,
    FOREIGN KEY(source_statechange_id) REFERENCES state_changes(identifier)
);
"""

DB_CREATE_RUNS = """
CREATE TABLE IF NOT EXISTS runs (
    started_at TIMESTAMP DEFAULT(STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW')) PRIMARY KEY NOT NULL,
    raiden_version TEXT NOT NULL
);
"""

DB_SCRIPT_CREATE_TABLES = """
PRAGMA foreign_keys=off;
BEGIN TRANSACTION;
{}{}{}{}{}
COMMIT;
PRAGMA foreign_keys=on;
""".format(
    DB_CREATE_SETTINGS,
    DB_CREATE_STATE_CHANGES,
    DB_CREATE_SNAPSHOT,
    DB_CREATE_STATE_EVENTS,
    DB_CREATE_RUNS,
)
