PRAGMA foreign_keys = ON;


CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip TEXT,
  timestamp INTEGER,
  hostname TEXT,
  service TEXT,
  cwd TEXT,
  exe TEXT,
  severity INTEGER,
  proctitle TEXT,
  execve_command TEXT,
  args JSON
);


CREATE TABLE IF NOT EXISTS syscall(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id INTEGER,
  syscall TEXT,
  pid INTEGER,
  ppid INTEGER,
  success BOOLEAN,
  exit INTEGER,
  tty TEXT,
  session INTEGER,
  uid INTEGER,
  euid INTEGER,
  auid INTEGER,
  FOREIGN KEY(event_id) REFERENCES events(id) ON DELETE CASCADE
);


CREATE TABLE IF NOT EXISTS path(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id INTEGER,
  binary TEXT,
  loader TEXT,
  owner TEXT,
  permissions TEXT,
  FOREIGN KEY(event_id) REFERENCES events(id) ON DELETE CASCADE
);
