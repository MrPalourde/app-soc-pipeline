use crate::types::*;
use rusqlite::{Connection, params};
use sha2::{Sha256, Digest};

pub fn analyze_log(conn: &Connection, log: Log) {
    let mut hasher = Sha256::new();
    hasher.update(log.ip.as_bytes());
    hasher.update(log.hostname.as_bytes());
    let result = hasher.finalize();
    let user_id = i64::from_be_bytes(result[0..8].try_into().unwrap());

    init_score(&conn, user_id);

    let delta: i16 = {
        match &log.content {
            ServiceLogType::Auditd(AuditdLogType::Execution(auditd)) => {
                match auditd.exe.as_str() {
                    "sudo" => -5,
                    _ => 0
                }
            },
            _ => {0}
        }
    };
    
    conn.execute(
        "INSERT INTO analyze_scores (user_id, score)
         VALUES (?1, ?2)
         ON CONFLICT(user_id)
         DO UPDATE SET score = score + excluded.score",
        params![user_id, delta],
    ).unwrap();

    println!("{}", delta);
}

fn init_score(conn: &Connection, user_id: i64) {
    conn.execute(
        "INSERT INTO analyze_scores (user_id, score)
         VALUES (?1, 100)
         ON CONFLICT(user_id) DO NOTHING",
        [user_id],
    ).unwrap();
}
