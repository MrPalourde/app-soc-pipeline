![Status](https://img.shields.io/badge/status-WIP-orange)
![Rust](https://img.shields.io/badge/built%20with-Rust-orange?logo=rust)
![License](https://img.shields.io/badge/license-MIT-blue)
![DB](https://img.shields.io/badge/database-SQLite-003B57?logo=sqlite)
![Async](https://img.shields.io/badge/async-Tokio-purple)

# App SOC Pipeline
Linux Security Operations Center (SOC) log ingestion and analysis pipeline written in Rust.
This project collects system logs from Linux machines via rsyslog, processes them in real time, and stores them in a structured SQLite database to enable efficient querying, security monitoring, and anomaly detection.

## Status
Work in progress — v1 in development.  
Core pipeline functional (TCP ingestion, auditd logs parsing, SQLite storage)

## Features
- Log ingestion over TCP (Tokio async)
- Support for auditd logs (execve, path, cwd, proctitle, syscall)
- SQLite database for structured storage and querying

## How it works
1. Logs are generated on client machines  
2. Agents forward logs to a central server  
3. The Rust server receives logs over TCP  
4. Logs are parsed into structured events  
5. Events are stored in a SQLite database  
6. Stored data can be queried for analysis

## Architecture
```
┌─────────────────────────────────────────────────────────┐
│                     CLIENT MACHINES                     │
│                                                         │
│             events                                      │
│               │                                         │
│            [auditd]  ──►  [rsyslog]                     │
└───────────────────────────────┬─────────────────────────┘
                                │ TCP
                                ▼
┌─────────────────────────────────────────────────────────┐
│                    RUST SOC SERVER                      │
│                                                         │
│   [TCP Listener]  ──►  [Parser]  ──►  [Event Builder]   │
│                                             │           │
│                                             ▼           │
│                                        [SQLite DB]      │
│                                             │           │
│                                             ▼           │
│                                    [Query / Analysis]   │
└─────────────────────────────────────────────────────────┘
```
## Tech Stack
- Rust, Tokio, SQLite, rusqlite, auditd, rsyslog

## Roadmap
- [X] Log ingestion over TCP (Tokio async)
- [X] Support for auditd logs (execve, path, cwd, proctitle, syscall)
- [X] SQLite database for structured storage and querying
- [ ] Support for all auditd logs type that are necessary for a soc server
- [ ] Support for rsyslog and system logs
- [ ] Anomaly detection and alert on suspicious logs 
- [ ] Store only useful logs
- [ ] Encrypted communication between clients and server (TLS)
- [ ] Add Windows Event Log support 
- [ ] Implement log rotation 

## Author
Milan Rousseau  
Built to learn SOC architecture and systems programming in Rust
