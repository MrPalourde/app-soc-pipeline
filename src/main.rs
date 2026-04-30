use serde::Deserialize;
use std::fs;
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use std::sync::Arc;
use std::collections::HashMap;
use std::time::Instant;
use serde_json::Value;

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
        println!("Event : {:?}", logs);
    }

    /*
    while let Some(log) = rx_server.recv().await {
        let parser_state = state.clone();
        parser::parse(log, parser_state).await;
        
        let watcher_state = state.clone();
        
        let regrouped_logs: Value = parser::watcher(watcher_state).await.into();
        println!("Event : {:?}", regrouped_logs);
    }     */
}
