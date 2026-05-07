use serde::Deserialize;
use std::fs;
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use std::sync::Arc;
use std::collections::HashMap;
use std::time::Instant;
use rusqlite::{Connection, Result};
use crate::types::*;

mod server;
mod parser;
mod analyzer;
mod types;

#[derive(Debug, Deserialize)]
struct Config {
    server: Server,
}

#[derive(Debug, Deserialize)]
struct Server {
    host: String,
    port: u16,
}

type State = Arc<Mutex<HashMap<String, (Vec<String>, Instant)>>>;

#[tokio::main]
async fn main() {
    let config_str = fs::read_to_string("config/server.toml").expect("Failed to read file");
    let config: Config = toml::from_str(&config_str).expect("Failed to parse TOML");

    let db_result: Result<()> = initialise_database();

    if db_result != Ok(()) {
        println!("Error with db opening or creation !");
    }

    let (tx_server, mut rx_server) = mpsc::channel(1000);
    let (tx_logs, mut rx_logs) = mpsc::channel::<Log>(1000);

    tokio::spawn(async move {
        server::open_server(tx_server, config.server.host.to_string(), config.server.port.to_string()).await;
    });

    let state: State = Arc::new(Mutex::new(HashMap::new()));

    let parse_state = state.clone();
    tokio::spawn(async move {
        while let Some(log) = rx_server.recv().await {
            parser::parse(log, parse_state.clone()).await;
        }
    });

    let watcher_state = state.clone();
    tokio::spawn(async move {
        parser::watcher(watcher_state, tx_logs).await;
    });

    while let Some(logs) = rx_logs.recv().await {
        if logs.content != ServiceLogType::NotSupported(()) {
            let insert_result = insert_in_db(&logs);
            if insert_result != Ok(()) {
                println!("Error with insertion of : {:?}", insert_result);
            } else {
                analyzer::analyze_log(logs);
            }
        }
    }
}

fn insert_in_db(log: &Log) -> Result<()> {
    let mut conn = Connection::open("app_database.db")?;
    let transaction = conn.transaction()?;

    transaction.execute(
        "INSERT INTO events (
            ip, timestamp, hostname, service
        )
        VALUES (?1, ?2, ?3, ?4)",
        (
            log.ip.clone(),
            log.timestamp,
            log.hostname.clone(),
            log.service.clone(),
        ),
    )?;

    let event_id = transaction.last_insert_rowid();

    match &log.content {
        ServiceLogType::Auditd(AuditdLogType::Execution(auditd)) => {
            transaction.execute(
                "INSERT INTO auditd_execution (
                    event_id, cwd, exe, binary, loader, owner,
                    permissions, command, args, success, proctitle, uid
                )
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                (
                    event_id, &auditd.cwd, &auditd.exe, &auditd.binary,
                    &auditd.loader, &auditd.owner, &auditd.permissions,
                    &auditd.command, serde_json::to_string(&auditd.args).unwrap(),
                    &auditd.success, &auditd.proctitle, &auditd.uid,
                ),
            )?;
        },
        ServiceLogType::Auditd(AuditdLogType::UserLogin(auditd)) => {
            transaction.execute(
                "INSERT INTO auditd_user_login (
                    event_id, address, exe, result, user_id
                )
                VALUES (?1, ?2, ?3, ?4, ?5)",
                (
                    event_id, &auditd.address, &auditd.exe, &auditd.result, &auditd.user_id,
                ),
            )?;
        },
        _ => {}
    }
 
    transaction.commit()?;
    Ok(())
}

fn initialise_database() -> Result<()> {
    let conn = Connection::open("app_database.db")?;

    let schema = include_str!("../assets/schema.sql");
    conn.execute_batch(schema)?;

    println!("Database and table created successfully.");
    Ok(())
}

