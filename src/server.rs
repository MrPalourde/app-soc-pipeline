use tokio::net::TcpListener;
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc::Sender;
use chrono::Utc;

pub async fn open_server(tx: Sender<String>, ip: String, port: String) {
    let socket = format!("{}:{}", ip, port);
    let listener = TcpListener::bind(&socket).await.unwrap();
    println!("Server bound to {}", socket);
    loop {
        let (mut socket, addr) = listener.accept().await.unwrap();
        let tx = tx.clone();
        println!("Client {} connected", addr.ip());
        tokio::spawn(async move {
            let mut buffer = vec![0; 4096];
            let mut leftover = String::new();

            // In a loop, read data from the socket and write the data back.
            loop {
                let n = match socket.read(&mut buffer).await {
                    // socket closed
                    Ok(0) => return,
                    Ok(n) => n,
                    Err(_) => return,
                };

                // Get each line of logs and send it to the channel
                let chunk = String::from_utf8_lossy(&buffer[..n]);
                leftover.push_str(&chunk);
                while let Some(pos) = leftover.find('\n') {
                    let raw_line = leftover[..pos].to_string();
                    let unix_time: i64 = Utc::now().timestamp();
                    let line = format!("{} {} {}", addr.ip(), unix_time, raw_line);
                    leftover = leftover[pos + 1..].to_string();
                    if tx.send(line).await.is_err() {
                        return;
                    }
                }

            }
        });
    }
}
