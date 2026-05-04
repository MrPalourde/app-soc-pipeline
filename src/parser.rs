use regex::Regex;
use std::collections::HashMap;
use tokio::sync::Mutex;
use std::sync::Arc;
use tokio::sync::MutexGuard;
use std::time::Instant;
use std::time::Duration;
use crate::types::{AuditdExecutionLog, AuditdLogType, ServiceLogType, Log};

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
) {
    let mut log_vector:(Vec<String>, Instant) = (Vec::new(), Instant::now());
    let log_slashed: Vec<_> = log.split_whitespace().collect();
    for log_part in log_slashed {
        log_vector.0.push(log_part.to_string());
    }
    let log_type = log_vector.0.get(6)
        .unwrap()
        .as_str()
        .to_string();
    let map = log_hash_map.lock().await;
    if log_type == String::from("auditd:") {
        let regex_event_id = Regex::new(r#"msg=audit\([0-9]*.[0-9]*:([0-9]*)\)"#).unwrap();
        let event_id = regex_event_id.captures(&log)
            .unwrap()
            .get(1)
            .unwrap()
            .as_str()
            .to_string();
        insert_in_hashmap(&event_id, map, log_vector);
    } else {
        let id: u128 = fastrand::u128(..);
        insert_in_hashmap(&id.to_string(), map, log_vector);
    }
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
) -> Log {
    let log_ip: String = logs_in_vector.0[IP].clone();
    let log_timestamp: i32 = logs_in_vector.0[TIMESTAMP].clone().parse().unwrap();
    let log_hostname: String = logs_in_vector.0[HOSTNAME].clone();
    let log_service: String = logs_in_vector.0[SERVICE].clone();

    let log_content: ServiceLogType = {
        match log_service.as_str() {
            "auditd:" => {
                let result: Option<AuditdLogType> = auditd_log_organize(logs_in_vector.0);
                if result.is_some() {
                    result.unwrap().into()
                } else {
                    ServiceLogType::NotSupported(())
                }
            },
            _ => {
                ServiceLogType::NotSupported(())
            }
        }
    };

    Log {
        ip: log_ip,
        timestamp: log_timestamp,
        hostname: log_hostname,
        service: log_service,
        content: log_content,
    }
}

fn auditd_log_organize(logs_in_vector: Vec<String>) -> Option<AuditdLogType> {
    let auditd_indices: Vec<usize> = logs_in_vector
        .iter()
        .enumerate()
        .filter(|(_,s)| *s == "auditd:")
        .map(|(i,_)| i)
        .collect();
    let regex_execve_commands = Regex::new(r#"a[0-9]+=(?:")?([^\\"\s]*)"#).unwrap();

    let is_execution_log: bool = logs_in_vector
        .iter()
        .any(|log| log.as_str().contains("type=EXECVE"));
   
    let mut auditd: Option<AuditdLogType> = None;

    if is_execution_log {
        let mut auditd_exec = AuditdExecutionLog::default();

        for auditd_type_index in auditd_indices {
            match logs_in_vector[auditd_type_index+1].as_str() {
                "type=PROCTITLE" => {
                    let mut proctitle: String = logs_in_vector[auditd_type_index+AUDITD_CONTENT_INDEX]
                        .clone();
                    proctitle = proctitle
                        .chars()
                        .skip(10)
                        .collect::<String>();
                    auditd_exec.proctitle = proctitle;
                },
                "type=EXECVE" => {
                    let execve_index: usize = auditd_type_index + AUDITD_CONTENT_INDEX;
                    let args_count: usize = logs_in_vector[execve_index]
                        .clone()
                        .chars()
                        .skip(5)
                        .collect::<String>()
                        .parse()
                        .unwrap();
                    let mut executed_command: String = String::new();
                    let mut args: Vec<String> = vec![];
                    for arg in execve_index+1..=execve_index+args_count {
                        let mut current_arg: String = logs_in_vector[arg]
                            .clone()
                            .to_string()
                            .replace('\0', " ");
                        current_arg = regex_execve_commands.captures(&current_arg)
                            .unwrap()
                            .get(1)
                            .unwrap()
                            .as_str()
                            .to_string();
                        args.push(current_arg.clone().to_string());
                        executed_command.push_str(&current_arg);
                        executed_command.push(' ');
                    }
                    let mut exe_name: String = args[0].to_string();
                    exe_name = exe_name
                        .as_str()
                        .rsplit('/')
                        .next()
                        .unwrap_or(&exe_name)
                        .to_string();
                    exe_name = exe_name.as_str()[0..exe_name.len()].to_string();
                    auditd_exec.exe = exe_name;
                    auditd_exec.command = executed_command.trim().to_string();
                    auditd_exec.args = args.into();
                },
                "type=PATH" => {
                    let path_start: usize = auditd_type_index + AUDITD_CONTENT_INDEX;
                    let is_loader: bool = logs_in_vector[path_start]
                        .clone()
                        .as_str()[5..] != "0".to_string();
                    let mut filename: String = logs_in_vector[path_start + 1].clone();
                    filename = filename[6..filename.len() - 1].to_string();
                    if is_loader {
                        auditd_exec.loader = filename;
                    } else {
                        auditd_exec.binary = filename;
                        let mut permissions: String = logs_in_vector[path_start + PATH_PERMISSIONS_INDEX].clone();
                        permissions = (&permissions[5..]).to_string();
                        let mut owner: String = logs_in_vector[path_start + PATH_OWNER_INDEX].clone();
                        owner = owner[6..owner.len() - 1].to_string();
                        auditd_exec.owner = owner;
                        auditd_exec.permissions = permissions;
                    }
                },
                "type=CWD" => {
                    let mut cwd: String = logs_in_vector[auditd_type_index + AUDITD_CONTENT_INDEX].clone();
                    cwd = (&cwd[5..6]).to_string();
                    auditd_exec.cwd = cwd;
                },
                "type=SYSCALL" => { 
                    let is_success_option: Option<&str> = logs_in_vector
                        .iter()
                        .find(|f| f.starts_with("success="))
                        .map(|f| &f[8..]);
                    let mut is_success: bool = false;
                    if Some(is_success_option).is_some() {
                        is_success = true;
                    }
                    auditd_exec.success = is_success;
                    
                    let uid_option: Option<&str> = logs_in_vector
                        .iter()
                        .find(|f| f.starts_with("uid="))
                        .map(|f| &f[4..]);
                    let mut uid: String = String::from("uid not found");
                    if Some(uid_option).is_some() {
                        uid = uid_option.unwrap().to_string();
                    }
                    auditd_exec.uid = uid;
                },
                &_ => {
                    continue;
                }
            }
        }
        auditd = Some(AuditdLogType::Execution(auditd_exec));
    }
    auditd
}

pub async fn watcher(
    log_hash_map: Arc<Mutex<HashMap<String,(Vec<String>, Instant)>>>,
    tx: tokio::sync::mpsc::Sender<Log>
) {
    loop {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let now = Instant::now();
        
        let mut map = log_hash_map.lock().await;
        let stale_ids: Vec<String> = map
            .iter()
            .filter(|(_, (_, last_seen))| now.duration_since(*last_seen) >= Duration::from_secs(2))
            .map(|(id, _)| id.clone())
            .collect();

        for id in stale_ids {
            if let Some((lines, _)) = map.remove(&id) {
                let _ = tx.send(organize((lines, now))).await;
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
    use tokio::sync::mpsc;

    fn make_map() -> Arc<Mutex<HashMap<String, (Vec<String>, Instant)>>> {
        Arc::new(Mutex::new(HashMap::new()))
    }

    // -------------------------------------------------------------------------
    // parse()
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn test_parse_auditd_log_inserted_in_map() {
        let map = make_map();
        let log = "192.168.1.60 1777474222 <174>Apr 29 16:50:22 raspberrypi auditd: type=SYSCALL msg=audit(1777474222.322:1408665): arch=c00000b7 syscall=221 success=yes exit=0 a0=400046fd10 a1=400020fc80 a2=4000302460 a3=0 items=2 ppid=1530 pid=15232 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=4294967295 comm=\"runc\" exe=\"/usr/bin/runc\" key=\"user-commands\"\u{1d}ARCH=aarch64 SYSCALL=execve AUID=\"unset\" UID=\"root\" GID=\"root\" EUID=\"root\" SUID=\"root\" FSUID=\"root\" EGID=\"root\" SGID=\"root\" FSGID=\"root\"".to_string();
        
        parse(log, map.clone()).await;

        let locked = map.lock().await;
        assert!(locked.contains_key("1408665"));
        assert_eq!(locked.get("1408665").unwrap().0[0], "192.168.1.60");
    }

    #[tokio::test]
    async fn test_parse_non_auditd_log_inserted_in_map() {
        let map = make_map();
        let log = "192.168.1.60 1777474221 <30>Apr 29 16:50:21 raspberrypi systemd[1]: Started rsyslog.service - System Logging Service.".to_string();
        
        parse(log, map.clone()).await;

        let locked = map.lock().await;
        assert_eq!(locked.len(), 1);
        let entry = locked.values().next().unwrap();
        assert_eq!(entry.0[0], "192.168.1.60");
        assert_eq!(entry.0[1], "1777474221");
        assert_eq!(entry.0[5], "raspberrypi");
        assert_eq!(entry.0[6], "systemd[1]:");
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
    
    // -------------------------------------------------------------------------
    // watcher()
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn test_watcher_remove_log_after_2s() {
        let map = make_map();
        let (tx, _rx) = mpsc::channel::<Log>(10);
        let event_id = "50".to_string();
        {
            let guard = map.lock().await;
            insert_in_hashmap(&event_id, guard, (vec!["token1".to_string()], Instant::now()));
        }
        tokio::spawn(watcher(map.clone(), tx));
        tokio::time::sleep(Duration::from_millis(2500)).await;
        let locked = map.lock().await;
        assert!(locked.is_empty());
    }

    // -------------------------------------------------------------------------
    // organize()
    // -------------------------------------------------------------------------




}
