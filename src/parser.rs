use regex::Regex;
use std::collections::HashMap;
use tokio::sync::Mutex;
use std::sync::Arc;
use tokio::sync::MutexGuard;
use std::time::Instant;
use std::time::Duration;
use serde_json::{json, Value};

const IP: usize = 0;
const TIMESTAMP: usize = 1;
const HOSTNAME: usize = 5;
const SERVICE: usize = 6;
const AUDITD_CONTENT_INDEX: usize = 3;
const PATH_PERMISSIONS_INDEX: usize = 4;
const PATH_OWNER_INDEX: usize = 14;

/*
    Function parse return a Vector<String> of 1 or multiple logs with the same ID
    @log: Log line to parse
    @log_hash_map: HashMap to store the logs to regroup them
    @return: A Vector<String> with all logs that have the same ID
*/
pub async fn parse(
    log: String,
    log_hash_map: Arc<Mutex<HashMap<String, (Vec<String>, Instant)>>>
) -> Value {
    let mut log_vector:(Vec<String>, Instant) = (Vec::new(), Instant::now());
    let log_slashed: Vec<_> = log.split_whitespace().collect();
    for log_part in log_slashed {
        log_vector.0.push(log_part.to_string());
    }
    let log_type = log_vector.0.get(6)
        .unwrap()
        .as_str()
        .to_string();
    if log_type == String::from("auditd:") {
        let regex_event_id = Regex::new(r#"msg=audit\([0-9]*.[0-9]*:([0-9]*)\)"#).unwrap();
        let event_id = regex_event_id.captures(&log)
            .unwrap()
            .get(1)
            .unwrap()
            .as_str()
            .to_string();
        let map = log_hash_map.lock().await;
        insert_in_hashmap(&event_id, map, log_vector);
        return json!({});
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
        IP, unix_time, hostname, origin_service, infos
*/
fn organize(
    logs_in_vector: (Vec<String>, Instant)
) -> Value {
    let mut data: Value = serde_json::from_str(include_str!("../assets/data_template.json")).unwrap();
    data["ip"] = json!(logs_in_vector.0[IP].clone());
    data["timestamp"] = json!(logs_in_vector.0[TIMESTAMP].clone());
    data["hostname"] = json!(logs_in_vector.0[HOSTNAME].clone());
    let service: String = logs_in_vector.0[SERVICE].clone();
    data["service"] = json!(service.clone());
    if service == "auditd:".to_string() {
        let auditd_indices: Vec<usize> = logs_in_vector.0
            .iter()
            .enumerate()
            .filter(|(_,s)| *s == "auditd:")
            .map(|(i,_)| i)
            .collect();
        let regex_execve_commands = Regex::new(r#"a[0-9]+=(?:")?([^\\"\s]*)"#).unwrap();
        for auditd_type_index in auditd_indices {
            match logs_in_vector.0[auditd_type_index+1].as_str() {
                "type=PROCTITLE" => {
                    let mut proctitle: String = logs_in_vector.0[auditd_type_index+AUDITD_CONTENT_INDEX]
                        .clone();
                    proctitle = proctitle
                        .chars()
                        .skip(10)
                        .collect::<String>();
                    data["infos"]["proctitle"] = json!(proctitle);
                },
                "type=EXECVE" => {
                    let execve_index: usize = auditd_type_index + AUDITD_CONTENT_INDEX;
                    let args_count: usize = logs_in_vector.0[execve_index]
                        .clone()
                        .chars()
                        .skip(5)
                        .collect::<String>()
                        .parse()
                        .unwrap();
                    let mut executed_command: String = String::new();
                    for arg in execve_index+1..=execve_index+args_count {
                        let mut current_arg: String = logs_in_vector.0[arg]
                            .clone()
                            .to_string()
                            .replace('\0', " ");
                        current_arg = regex_execve_commands.captures(&current_arg)
                            .unwrap()
                            .get(1)
                            .unwrap()
                            .as_str()
                            .to_string();
                        data["infos"]["execve_args"]
                            .as_array_mut()
                            .unwrap()
                            .push(json!(current_arg.clone().to_string()));
                        executed_command.push_str(&current_arg);
                        executed_command.push(' ');
                    }
                    data["infos"]["execve_command"] = json!(executed_command.trim().to_string());
                },
                "type=PATH" => {
                    let path_start: usize = auditd_type_index + AUDITD_CONTENT_INDEX;
                    let is_loader: bool = logs_in_vector.0[path_start]
                        .clone()
                        .as_str()[5..] != "0".to_string();
                    let mut filename: String = logs_in_vector.0[path_start + 1].clone();
                    filename = filename[6..filename.len() - 1].to_string();
                    if is_loader {
                        data["infos"]["path"]["loader"] = json!(filename);
                    } else {
                        data["infos"]["path"]["binary"] = json!(filename);
                        let mut permissions: String = logs_in_vector.0[path_start + PATH_PERMISSIONS_INDEX].clone();
                        permissions = (&permissions[5..]).to_string();
                        let mut owner: String = logs_in_vector.0[path_start + PATH_OWNER_INDEX].clone();
                        owner = owner[6..owner.len() - 1].to_string();
                        data["infos"]["path"]["owner"] = json!(owner);
                        data["infos"]["path"]["permissions"] = json!(permissions);
                    }
                },
                "type=CWD" => {
                    let mut cwd: String = logs_in_vector.0[auditd_type_index + AUDITD_CONTENT_INDEX].clone();
                    cwd = (&cwd[5..6]).to_string();
                    data["cwd"] = json!(cwd);
                },
                "type=SYSCALL" => { 
                    continue;
                },
                &_ => {
                    continue;
                }
            }
        }
    }
    return data;
}

pub async fn watcher(
    log_hash_map: Arc<Mutex<HashMap<String,(Vec<String>, Instant)>>>
) -> Value {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::Mutex;
    use std::time::Instant;

    fn make_map() -> Arc<Mutex<HashMap<String, (Vec<String>, Instant)>>> {
        Arc::new(Mutex::new(HashMap::new()))
    }
    
    // -------------------------------------------------------------------------
    // parse()
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn test_parse_auditd_log_returns_empty() {
        let map = make_map();
        let log = "192.168.1.60 1777474222 <174>Apr 29 16:50:22 raspberrypi auditd: type=SYSCALL msg=audit(1777474222.322:1408665): arch=c00000b7 syscall=221 success=yes exit=0 a0=400046fd10 a1=400020fc80 a2=4000302460 a3=0 items=2 ppid=1530 pid=15232 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=4294967295 comm=\"runc\" exe=\"/usr/bin/runc\" key=\"user-commands\"\u{1d}ARCH=aarch64 SYSCALL=execve AUID=\"unset\" UID=\"root\" GID=\"root\" EUID=\"root\" SUID=\"root\" FSUID=\"root\" EGID=\"root\" SGID=\"root\" FSGID=\"root\"".to_string();
        let result = parse(log, map).await;

        assert_eq!(result, vec![] as Vec<String>);
    }

    #[tokio::test]
    async fn test_parse_non_auditd_log_returns_organized() {
        let map = make_map();
        let log = "192.168.1.60 1777474221 <30>Apr 29 16:50:21 raspberrypi systemd[1]: Started rsyslog.service - System Logging Service.".to_string();
        let result = parse(log, map).await;

        assert_eq!(result, vec!["192.168.1.60", "1777474221", "raspberrypi", "systemd[1]:"]);
    }

    // -------------------------------------------------------------------------
    // insert_in_hashmap()
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn test_insert_in_hashmap_new_entry() {
        let map = make_map();
        let event_id = "42".to_string();
        let log_vector = (
            vec!["token1".to_string(), "token2".to_string()],
            Instant::now(),
        );

        {
            let guard = map.lock().await;
            insert_in_hashmap(&event_id, guard, log_vector);
        }

        let locked = map.lock().await;
        assert!(locked.contains_key("42"));
        assert_eq!(locked.get("42").unwrap().0, vec!["token1", "token2"]);
    }

    #[tokio::test]
    async fn test_insert_in_hashmap_accumulates_lines() {
        let map = make_map();
        let event_id = "42".to_string();

        {
            let guard = map.lock().await;
            insert_in_hashmap(&event_id, guard, (vec!["token1".to_string()], Instant::now()));
        }
        {
            let guard = map.lock().await;
            insert_in_hashmap(&event_id, guard, (vec!["token2".to_string()], Instant::now()));
        }

        let locked = map.lock().await;
        assert_eq!(locked.get("42").unwrap().0, vec!["token1", "token2"]);
    }

    #[tokio::test]
    async fn test_insert_in_hashmap_updates_timestamp() {
        let map = make_map();
        let event_id = "42".to_string();

        {
            let guard = map.lock().await;
            insert_in_hashmap(&event_id, guard, (vec!["token1".to_string()], Instant::now()));
        }
        let t1 = map.lock().await.get("42").unwrap().1;

        tokio::time::sleep(Duration::from_millis(10)).await;

        {
            let guard = map.lock().await;
            insert_in_hashmap(&event_id, guard, (vec!["token2".to_string()], Instant::now()));
        }
        let t2 = map.lock().await.get("42").unwrap().1;

        assert!(t2 > t1);
    }

    #[tokio::test]
    async fn test_insert_in_hashmap_different_ids_are_separate() {
        let map = make_map();

        {
            let guard = map.lock().await;
            insert_in_hashmap(&"1".to_string(), guard, (vec!["a".to_string()], Instant::now()));
        }
        {
            let guard = map.lock().await;
            insert_in_hashmap(&"2".to_string(), guard, (vec!["b".to_string()], Instant::now()));
        }

        let locked = map.lock().await;
        assert_eq!(locked.get("1").unwrap().0, vec!["a"]);
        assert_eq!(locked.get("2").unwrap().0, vec!["b"]);
    }

}
