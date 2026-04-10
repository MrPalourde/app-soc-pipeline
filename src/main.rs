use serde::Deserialize;
use std::fs;
use tokio::sync::mpsc;

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

#[tokio::main]
async fn main() {
    // Read and parse the TOML file
    let config_str = fs::read_to_string("config/server.toml").expect("Failed to read file");
    let config: Config = toml::from_str(&config_str).expect("Failed to parse TOML");

    // Create channel [main.rs <-> server.rs]
    let (tx_server, mut rx_server) = mpsc::channel(1000);

    // Launch server to start receive logs from clients
    tokio::spawn(async move {
        server::open_server(tx_server, config.server.host.to_string(), config.server.port.to_string()).await;
    });

    // Get logs from server and process
    while let Some(log) = rx_server.recv().await {
        let value = parser::parse(log).await;
        println!("Parsed : {}", value);
    }
}
