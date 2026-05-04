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

            loop {
                let n = match socket.read(&mut buffer).await {
                    Ok(0) => return,
                    Ok(n) => n,
                    Err(_) => return,
                };

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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream;
    use chrono::Utc;

    async fn spawn_server(port: u16) -> mpsc::Receiver<String> {
        let (tx, rx) = mpsc::channel::<String>(100);
        tokio::spawn(async move {
            open_server(tx, "127.0.0.1".to_string(), port.to_string()).await;
        });
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        rx
    }

    #[tokio::test]
    async fn test_single_line() {
        let mut rx = spawn_server(9001).await;
        let mut stream = TcpStream::connect("127.0.0.1:9001").await.unwrap();

        stream.write_all(b"<174>Apr 29 16:50:22 raspberrypi auditd: type=SYSCALL msg=audit(1777474222.322:1408665):\n")
            .await.unwrap();

        let msg = rx.recv().await.unwrap();
        let unix_time: i64 = Utc::now().timestamp();

        assert_eq!(
            msg,
            format!(
                "127.0.0.1 {} <174>Apr 29 16:50:22 raspberrypi auditd: type=SYSCALL msg=audit(1777474222.322:1408665):",
                unix_time
            )
        )
    }

    #[tokio::test]
    async fn test_multiple_lines() {
        let mut rx = spawn_server(9002).await;
        let mut stream = TcpStream::connect("127.0.0.1:9002").await.unwrap();

        stream.write_all(b"<174>Apr 29 16:50:22 raspberrypi auditd: type=SYSCALL msg=audit(1777474222.322:1408665):\n<174>Apr 29 16:50:22 raspberrypi auditd: type=CWD msg=audit(1777474222.322:1408665):")
            .await.unwrap();

        let msg = rx.recv().await.unwrap();
        let unix_time: i64 = Utc::now().timestamp();

        assert_eq!(
            msg,
            format!(
                "127.0.0.1 {} <174>Apr 29 16:50:22 raspberrypi auditd: type=SYSCALL msg=audit(1777474222.322:1408665):",
                unix_time
            )
        )

    }
}
