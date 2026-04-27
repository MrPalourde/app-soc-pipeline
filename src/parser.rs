use regex::Regex;
use std::collections::HashMap;
use tokio::sync::Mutex;
use std::sync::Arc;
use tokio::sync::MutexGuard;
use std::time::Instant;
use std::time::Duration;

/*
    Function parse return a Vector<String> of 1 or multiple logs with the same ID
    @log: Log line to parse
    @log_hash_map: HashMap to store the logs to regroup them
    @return: A Vector<String> with all logs that have the same ID
*/
pub async fn parse(
    log: String,
    log_hash_map: Arc<Mutex<HashMap<String, (Vec<String>, Instant)>>>
) -> Vec<String> {
    let mut log_vector:(Vec<String>, Instant) = (Vec::new(), Instant::now());
    let log_slashed: Vec<_> = log.split_whitespace().collect();
    for log_part in log_slashed {
        log_vector.0.push(log_part.to_string());
    }
    let log_type = log_vector.0.get(6).unwrap().as_str().to_string();
    if log_type == String::from("auditd:") {
        let regex_event_id = Regex::new(r#"msg=audit\([0-9]*.[0-9]*:([0-9]*)\)"#).unwrap();
        let event_id = regex_event_id.captures(&log).unwrap().get(1).unwrap().as_str().to_string();
        let map = log_hash_map.lock().await;
        insert_in_hashmap(&event_id, map, log_vector);
        return vec![];
    }
    return organize(log_vector);
}

fn insert_in_hashmap(
    event_id: &String,
    mut log_hash_map: MutexGuard<'_, HashMap<String, (Vec<String>, Instant)>>,
    log_vector: (Vec<String>, Instant)
) {
    log_hash_map.entry(event_id.to_string())
        .or_insert_with(|| (Vec::new(), Instant::now()))
        .0 // Vec<String>
        .extend(log_vector.0);
    log_hash_map.get_mut(event_id.as_str()).unwrap().1 = Instant::now();
}

/*
    Function remove duplicate and put in specific order multiple log into one
    @logs_in_vector: A vector containing the log(s) to regroup and/or organize
    @return: A vector containing the regrouped and organized logs in this order :
        IP, unix_time, hostname, origin_service, infos(list all infos terminated by an EOL)
*/
fn organize(
    logs_in_vector: (Vec<String>, Instant)
) -> Vec<String> {
    let mut organized_log:Vec<String> = Vec::new();
    organized_log.push(logs_in_vector.0[0].clone());
    organized_log.push(logs_in_vector.0[1].clone());
    
    return organized_log;
}

pub async fn watcher(
    log_hash_map: Arc<Mutex<HashMap<String,(Vec<String>, Instant)>>>
) -> Vec<String> {
    loop {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let mut map = log_hash_map.lock().await;
        let now = Instant::now();
        let stale_ids: Vec<String> = map
            .iter()
            .filter(|(_, (_, last_seen))| now.duration_since(*last_seen).as_secs_f32() >= 2.0)
            .map(|(id, _)| id.clone())
            .collect();
        for id in stale_ids {
            if let Some((lines, _)) = map.remove(&id) {
                return organize((lines.clone(), now));
            }
        }
    }
}
