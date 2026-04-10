# 🛡️ App SOC Pipeline

Multi-OS Security Operations Center (SOC) log ingestion and analysis pipeline built in Rust.

This project collects system logs from Linux and Windows machines, processes them in real-time, and stores them in a structured SQLite database for fast querying, security monitoring, and anomaly detection.

---

## 🚀 Features

- High-performance log ingestion via TCP
- Rust-based backend for speed and safety
- SQLite storage for structured log analysis
- Multi-OS support (Linux & Windows)
- Support for auditd, rsyslog, and Windows Event Logs
- Extensible architecture for future detection engine

---

## 🧠 Data Flow

Logs are generated on client machines  
Agents forward logs to SOC server  
Rust server receives logs over TCP  
Logs are parsed into structured events  
Events are stored in SQLite database  
Queries and analysis are performed on stored data  

---

## 📦 Log Format (Internal Structure)

Each log is normalized into a structured event:

{
  "timestamp": "",
  "host": "",
  "user": "",
  "event_type": "",
  "command": "",
  "source": "",
  "severity": ""
}

---

## 🗄️ Database Schema (SQLite)

CREATE TABLE logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER,
    host TEXT,
    user TEXT,
    event_type TEXT,
    command TEXT,
    source TEXT,
    severity TEXT,
    raw_log TEXT
);

### Recommended Indexes

CREATE INDEX idx_user ON logs(user);
CREATE INDEX idx_time ON logs(timestamp);
CREATE INDEX idx_host ON logs(host);
CREATE INDEX idx_event ON logs(event_type);

---

## 🔐 Security (Planned)

- TLS encrypted communication between clients and server
- Optional authentication per client
- Integrity checks for log transmission
- Secure log ingestion pipeline

---

## 📈 Scalability Strategy

To handle large log volumes:

- SQLite WAL mode enabled
- Batch inserts (performance optimization)
- Log rotation (daily/weekly DB files)
- Archiving old logs
- Indexed queries for fast search

Example:

logs_2026_01.db  
logs_2026_02.db  
archive_logs.tar.gz  

---

## 🛠️ Installation

### Build Rust server

cargo build --release

### Run server

./target/release/soc-server

---

## 📌 Roadmap

- [ ] Implement Rust TCP ingestion server  
- [ ] Add log parsing engine  
- [ ] Integrate SQLite storage layer  
- [ ] Add Linux agent (rsyslog/auditd integration)  
- [ ] Add Windows Event Log support  
- [ ] Add TLS encryption layer  
- [ ] Add anomaly detection engine  
- [ ] Add log rotation system  
- [ ] Add REST API for querying logs  

---

## 📊 Goals

- Build a lightweight SOC-like system  
- Learn real-world log ingestion architecture  
- Understand SIEM fundamentals  
- Combine Rust performance with structured storage  
- Support multi-OS environments  

---

## 👤 Author

Project: App SOC Pipeline  
Purpose: Cybersecurity learning project (SOC / SIEM architecture, Rust systems programming)

---

## ⚠️ Disclaimer

This project is for educational and research purposes only.
