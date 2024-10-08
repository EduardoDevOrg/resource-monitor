use std::time::Duration;
use reqwest::{blocking::{Client, ClientBuilder}, Error};
use serde_json::json;
use super::logging::agent_logger;
use super::log_entry::LogEntry;
use super::storewatch::StorewatchEntryLinux;
pub fn get_signalfx_client() -> Result<Client, Error> {
    let client = ClientBuilder::new()
            .danger_accept_invalid_certs(true)
            .build()
            .expect("Failed to build client");
    
        agent_logger("info", "get_signalfx_client", 
            r#"{
                    "message": "Client successfully created."
                }"#);
    Ok(client)
}

pub fn generate_storage_gauge(storewatch_entry: &Vec<StorewatchEntryLinux>, rmtag: &str) -> String {
    let mut gauge_array = Vec::new();

    for entry in storewatch_entry {
        let timestamp = entry.timestamp * 1000;
        let host = entry.hostname.clone();
    
        let metrics = [
            ("free_size", entry.free_size),
            ("used_size", entry.used_size),
        ];

        for (metric, value) in &metrics {
            gauge_array.push(json!({
                "metric": metric,
                "value": value,
                "dimensions": {
                    "host": host,
                    "environment": rmtag,
                    "disk_name": entry.disk_name,
                    "mounts": entry.mounts.join(";")
                },
                "timestamp": timestamp
            }));
        }
    }

    let gauge_json = json!({
        "gauge": gauge_array
    });

    agent_logger("debug", "generate_storage_gauge", 
        r#"{
                "message": "Storage Gauge JSON successfully generated."
            }"#);
    gauge_json.to_string()
}

pub fn generate_agent_gauge(log_entry: &LogEntry, rmtag: &str) -> String {
    let timestamp = log_entry.timestamp * 1000;
    let host = log_entry.hostname.clone();
    
    let metrics = [
        ("cpu_usage", log_entry.cpu_usage),
        ("mem_usage", log_entry.mem_usage),
        ("disk_read", log_entry.disk_read as f64),
        ("disk_write", log_entry.disk_write as f64),
        ("bytes_in", log_entry.bytes_in as f64),
        ("bytes_out", log_entry.bytes_out as f64),
        ("packets_in", log_entry.packets_in as f64),
        ("packets_out", log_entry.packets_out as f64),
        ("tx_dropped", log_entry.tx_dropped as f64),
        ("rx_dropped", log_entry.rx_dropped as f64),
    ];

    let gauge_array: Vec<_> = metrics.iter().map(|(metric, value)| {
        json!({
            "metric": metric,
            "value": value,
            "dimensions": {
                "host": host,
                "environment": rmtag
            },
            "timestamp": timestamp
        })
    }).collect();

    let gauge_json = json!({
        "gauge": gauge_array
    });
    agent_logger("debug", "generate_agent_gauge", 
        r#"{
                "message": "Agent Gauge JSON successfully generated."
            }"#);
    gauge_json.to_string()
}

pub fn send_gauge(client: &Client, uri: &str, data_json: &str, token: &str, timeout: u64) -> Result<(), Error> {

    // Send the request
    let response_result = client.post(uri)
        .header("Content-Type", "application/json; charset=utf-8")
        .header("X-SF-Token", token)
        .body(data_json.to_string())
        .timeout(Duration::from_secs(timeout))
        .send();

    match response_result {
        Ok(_) => {
            agent_logger("info", "send_gauge", 
            r#"{
                    "message": "Data successfully sent."
                }"#);
            Ok(())
        },
        Err(e) => {
            // Check if the error is a timeout
            if e.is_timeout() {
                agent_logger("error", "send_gauge", 
                r#"{
                        "message": "Request timed out.",
                        "error": "Timeout!"
                    }"#);
            } else {
                agent_logger("error", "send_gauge", 
                r#"{
                        "message": "Data could not be sent."
                    }"#);
            }
            Err(e)
        }
    }
}

