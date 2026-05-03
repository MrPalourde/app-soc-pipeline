PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip TEXT,
  timestamp INTEGER,
  hostname TEXT,
  service TEXT
);


CREATE TABLE IF NOT EXISTS auditd_execution(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id INTEGER,
  cwd TEXT,
  exe TEXT,
  binary TEXT,
  loader TEXT,
  owner TEXT,
  permissions TEXT,
  command TEXT,
  args JSON,
  success BOOLEAN,
  proctitle TEXT,
  uid TEXT,
  FOREIGN KEY(event_id) REFERENCES events(id) ON DELETE CASCADE
);
