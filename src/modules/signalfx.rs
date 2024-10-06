use reqwest::{blocking::{Client, ClientBuilder}, Error};
use serde_json::json;
use super::logging::agent_logger;
use super::log_entry::LogEntry;

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

pub fn generate_gauge_json(log_entry: &LogEntry) -> String {
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
    ];

    let gauge_array: Vec<_> = metrics.iter().map(|(metric, value)| {
        json!({
            "metric": metric,
            "value": value,
            "dimensions": {
                "host": host
            },
            "timestamp": timestamp
        })
    }).collect();

    let gauge_json = json!({
        "gauge": gauge_array
    });
    agent_logger("debug", "generate_gauge_json", 
        r#"{
                "message": "Gauge JSON successfully generated."
            }"#);
    gauge_json.to_string()
}

pub fn send_gauge(client: &Client, uri: &str, data_json: &str, token: &str) -> Result<(), Error> {
    let response_result = client.post(uri)
        .header("Content-Type", "application/json")
        .header("X-SF-Token", token)
        .body(data_json.to_string())
        .send();

    match response_result {
        Ok(_response) => {
            agent_logger("info", "send_gauge", 
            r#"{
                    "message": "Data successfully sent."
                }"#);
            Ok(())
        },
        Err(e) => {
            agent_logger("error", "send_gauge", 
            r#"{
                    "message": "Data could not be sent.",
                    "error": e.to_string()
                }"#);
            Err(e)
        }
    }
}

