use regex::Regex;

pub async fn parse(log: String) -> Vec<String> {
    let mut log_vector:Vec<String> = Vec::new();
    let regex_message_level = Regex::new(r#"^<([0-9]*)>"#).unwrap();
    let id = regex_message_level.captures(&log).unwrap();
    log_vector.push(id.get(1).unwrap().as_str().to_string());
    let log_slashed: Vec<_> = log.splitn(2, '>').nth(1).unwrap().split_whitespace().collect();
    for log_part in log_slashed {
        log_vector.push(log_part.to_string());
    }
    return log_vector;
}
