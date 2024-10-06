use std::fs::OpenOptions;
use std::io::{BufWriter, Write as _};
use serde_json::{json, Value};
use std::path::PathBuf;

use super::config::get_app_dirs;
use super::log_entry::check_log_file_size;

pub fn agent_logger(log_level: &str, module: &str, msg_json: &str) {
    let current_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Time went backwards");
    
    let (_, _, log_path) = get_app_dirs();
    let log_folder = determine_log_folder(log_path);

    if log_folder.exists() {
        check_log_file_size(&log_folder);
    }

    let log_writer = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_folder)
        .expect("Failed to open log file");

    let mut log_writer = BufWriter::new(log_writer);

    let mut log_entry: Value = json!({
        "timestamp": current_epoch.as_secs(),
        "component": "agent_logger",
        "module": module,
        "log_level": log_level.to_uppercase(),
    });

    // Parse the JSON string and merge it into the base object
    let msg_json_value: Value = serde_json::from_str(msg_json).expect("Failed to parse JSON string");
    if let Value::Object(map) = msg_json_value {
        log_entry.as_object_mut().unwrap().extend(map);
    }

    // Serialize the final object into a JSON string
    let msg_json_str = serde_json::to_string(&log_entry).expect("Failed to serialize JSON");

    // Write the JSON string to the log file
    writeln!(log_writer, "{}", msg_json_str).expect("Failed to write to log file");
}

fn determine_log_folder(log_path: PathBuf) -> PathBuf {
    let log_path_str = log_path.to_string_lossy();
    if log_path_str.contains("splunk") || log_path_str.contains("splunkforwarder") || log_path_str.contains("splunkuniversalforwarder") {
        log_path.join("var/log/splunk/agent_logger_json.log")
    } else {
        log_path.join("agent_logger_json.log")
    }
}