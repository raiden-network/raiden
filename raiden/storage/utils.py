from collections import namedtuple


class TimestampedEvent(namedtuple('TimestampedEvent', 'wrapped_event log_time')):
    def __getattr__(self, item):
        return getattr(self.wrapped_event, item)


DB_CREATE_SETTINGS = '''
CREATE TABLE IF NOT EXISTS settings (
    name VARCHAR[24] NOT NULL PRIMARY KEY,
    value TEXT
);
'''

DB_CREATE_STATE_CHANGES = '''
CREATE TABLE IF NOT EXISTS state_changes (
    identifier INTEGER PRIMARY KEY AUTOINCREMENT,
    data JSON,
    log_time TEXT
);
'''

DB_CREATE_SNAPSHOT = '''
CREATE TABLE IF NOT EXISTS state_snapshot (
    identifier INTEGER PRIMARY KEY,
    statechange_id INTEGER,
    data JSON,
    FOREIGN KEY(statechange_id) REFERENCES state_changes(identifier)
);
'''

DB_CREATE_STATE_EVENTS = '''
CREATE TABLE IF NOT EXISTS state_events (
    identifier INTEGER PRIMARY KEY,
    source_statechange_id INTEGER NOT NULL,
    log_time TEXT,
    data JSON,
    FOREIGN KEY(source_statechange_id) REFERENCES state_changes(identifier)
);
'''

DB_CREATE_RUNS = '''
CREATE TABLE IF NOT EXISTS runs (
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP PRIMARY KEY,
    raiden_version TEXT NOT NULL
);
'''

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
