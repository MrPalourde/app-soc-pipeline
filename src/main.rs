use serde::Deserialize;
use std::fs;
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use std::sync::Arc;
use std::collections::HashMap;
use std::time::Instant;
use serde_json::Value;
use rusqlite::{Connection, Result};

mod server;
mod parser;

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

    let db_result: Result<()> = open_or_create_database();

    if db_result != Ok(()) {
        println!("Error with db opening or creation !");
    }

    let (tx_server, mut rx_server) = mpsc::channel(1000);
    let (tx_logs, mut rx_logs) = mpsc::channel::<Value>(1000);

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
        let insert_result = insert_in_db(logs);
        if insert_result != Ok(()) {
            println!("Error with insertion of : {:?}", insert_result);
        }
    }
}

fn insert_in_db(log: Value) -> Result<()> {
    let mut conn = Connection::open("app_database.db")?;
    let transaction = conn.transaction()?;

    transaction.execute(
        "INSERT INTO events (
            ip, timestamp, hostname, service, cwd, exe,
            severity, proctitle, execve_command
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        (
            log["ip"].as_str().unwrap_or(""),
            log["timestamp"].as_i64().unwrap_or(0),
            log["hostname"].as_str().unwrap_or(""),
            log["service"].as_str().unwrap_or(""),
            log["cwd"].as_str().unwrap_or(""),
            log["exe"].as_str().unwrap_or(""),
            log["severity"].as_i64().unwrap_or(-1),
            log["infos"]["proctitle"].as_str().unwrap_or(""),
            log["infos"]["execve_command"].as_str().unwrap_or(""),
        ),
    )?;

    let event_id = transaction.last_insert_rowid();

    transaction.execute(
        "INSERT INTO syscall (
            event_id, syscall, pid, ppid, success, exit,
            tty, session, uid, euid, auid
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        (
            event_id,
            log["infos"]["syscall"]["what"]["syscall"].as_str().unwrap_or(""),
            log["infos"]["syscall"]["what"]["pid"].as_i64().unwrap_or(0),
            log["infos"]["syscall"]["what"]["ppid"].as_i64().unwrap_or(0),
            log["infos"]["syscall"]["result"]["success"].as_i64().unwrap_or(-1),
            log["infos"]["syscall"]["result"]["exit"].as_i64().unwrap_or(-1),
            log["infos"]["syscall"]["context"]["tty"].as_str().unwrap_or(""),
            log["infos"]["syscall"]["context"]["session"].as_i64().unwrap_or(0),
            log["infos"]["syscall"]["who"]["uid"].as_i64().unwrap_or(0),
            log["infos"]["syscall"]["who"]["euid"].as_i64().unwrap_or(0),
            log["infos"]["syscall"]["who"]["auid"].as_i64().unwrap_or(0),
        ),
    )?;

    transaction.execute(
        "INSERT INTO path (
            event_id, binary, loader, owner, permissions
        )
        VALUES (?1, ?2, ?3, ?4, ?5)",
        (
            event_id,
            log["infos"]["path"]["binary"].as_str().unwrap_or(""),
            log["infos"]["path"]["loader"].as_str().unwrap_or(""),
            log["infos"]["path"]["owner"].as_str().unwrap_or(""),
            log["infos"]["path"]["permissions"].as_str().unwrap_or(""),
        ),
    )?;

    transaction.commit()?;
    Ok(())
}

fn open_or_create_database() -> Result<()> {
    let conn = Connection::open("app_database.db")?;

    let schema = include_str!("../assets/schema.sql");
    conn.execute_batch(schema)?;

    println!("Database and table created successfully.");
    Ok(())
}

