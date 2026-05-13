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
        let mut score: f64 = 100.0;
        match &log.content {
            ServiceLogType::Auditd(AuditdLogType::Execution(auditd)) => {
                if auditd.exe.as_str() == "sudo" {
                    score *= 1.5;
                }
                if auditd.cwd.as_str() == "/" {
                    score *= 1.1;
                }
                if auditd.uid.as_str() == "0" {
                    score *= -1.0;
                }
            },
            _ => {}
        }
        score as i16
    };

    conn.execute(
        "INSERT INTO analyze_scores (user_id, score)
         VALUES (?1, ?2)
         ON CONFLICT(user_id)
         DO UPDATE SET score = score + excluded.score",
        params![user_id, delta],
    ).unwrap();
    let score = get_score(&conn, user_id);
    if score > 100 {
        println!("Log to check with score -{} : {:?}", get_score(&conn, user_id), log);
    }
}

fn init_score(conn: &Connection, user_id: i64) {
    conn.execute(
        "INSERT INTO analyze_scores (user_id, score)
         VALUES (?1, 100)
         ON CONFLICT(user_id) DO NOTHING",
        [user_id],
    ).unwrap();
}

fn get_score(conn: &Connection, user_id: i64) -> i16 {
    conn.query_row(
        "SELECT score FROM analyze_scores WHERE user_id = ?1",
        [user_id],
        |row| row.get(0),
    ).unwrap()
}
