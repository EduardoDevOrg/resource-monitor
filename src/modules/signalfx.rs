use std::{sync::Arc, time::Duration};
use reqwest::{blocking::{Client, ClientBuilder}, Error};
use serde_json::json;
use super::logging::agent_logger;
use super::log_entry::LogEntry;
use super::storewatch::StorewatchEntry;

// Create a client with connection pooling enabled
pub fn get_signalfx_client() -> Result<Client, Error> {
    let client = ClientBuilder::new()
            .danger_accept_invalid_certs(true)
            .pool_max_idle_per_host(10) // Enable connection pooling
            .pool_idle_timeout(Duration::from_secs(30))
            .timeout(Duration::from_secs(5))
            .build()?;
    
    // agent_logger("info", "signalfx", "get_signalfx_client", 
    //     r#"{"message": "Client successfully created."}"#);
    Ok(client)
}

// Pre-allocate capacity for gauge arrays to avoid reallocations
pub fn generate_storage_gauge(storewatch_entries: &Vec<StorewatchEntry>, rmtag: &str) -> String {
    // Pre-allocate with estimated capacity
    let capacity = storewatch_entries.len() * 12; // 12 metrics per entry as a safe upper bound
    let mut gauge_array = Vec::with_capacity(capacity);

    for entry in storewatch_entries {
        match entry {
            StorewatchEntry::Linux(linux_entry) => {
                let timestamp = linux_entry.timestamp * 1000;
                let host = &linux_entry.hostname;
                
                // Create dimensions object once to reuse
                let dimensions = json!({
                    "host": host,
                    "environment": rmtag,
                    "disk_name": linux_entry.disk_name,
                    "mounts": linux_entry.mounts.join(";")
                });
            
                // Linux-specific metrics
                let metrics = [
                    ("disk_usage", linux_entry.disk_usage),
                    ("free_size", linux_entry.free_size as f64),
                    ("used_size", linux_entry.used_size as f64),
                    ("reads", linux_entry.reads as f64),
                    ("writes", linux_entry.writes as f64),
                    ("time_read", linux_entry.time_read as f64),
                    ("time_write", linux_entry.time_write as f64),
                    ("time_in_progress", linux_entry.time_in_progress as f64),
                    ("weighted_time_in_progress", linux_entry.weighted_time_in_progress as f64),
                    ("in_progress", linux_entry.in_progress as f64),
                    ("bytes_read", linux_entry.bytes_read as f64),
                    ("bytes_written", linux_entry.bytes_written as f64),
                ];

                for (metric, value) in &metrics {
                    gauge_array.push(json!({
                        "metric": metric,
                        "value": value,
                        "dimensions": dimensions,
                        "timestamp": timestamp
                    }));
                }
            },
            
            StorewatchEntry::Windows(windows_entry) => {
                let timestamp = windows_entry.timestamp * 1000;
                let host = &windows_entry.hostname;
                
                // Create dimensions object once to reuse
                let dimensions = json!({
                    "host": host,
                    "environment": rmtag,
                    "disk_name": windows_entry.disk_name,
                    "partitions": windows_entry.partitions.join(";") // Note: using "partitions" for Windows
                });
            
                // Windows-specific metrics (reduced set)
                let metrics = [
                    ("free_size", windows_entry.free_size as f64),
                    ("used_size", windows_entry.used_size as f64),
                    ("bytes_read", windows_entry.bytes_read as f64),
                    ("bytes_written", windows_entry.bytes_written as f64),
                ];

                for (metric, value) in &metrics {
                    gauge_array.push(json!({
                        "metric": metric,
                        "value": value,
                        "dimensions": dimensions,
                        "timestamp": timestamp
                    }));
                }
            }
        }
    }

    let gauge_json = json!({
        "gauge": gauge_array
    });

    gauge_json.to_string()
}

pub fn generate_agent_gauge(log_entry: &LogEntry, hostname: &str, rmtag: &str, timestamp: u64) -> String {
    // Create dimensions object once
    let dimensions = json!({
        "host": hostname,
        "environment": rmtag
    });
    
    let timestamp_ms = timestamp * 1000;
    
    // Common metrics for all platforms
    #[cfg(not(target_os = "windows"))]
    let capacity = 10; // Unix has all 10 metrics
    
    #[cfg(target_os = "windows")]
    let capacity = 8;  // Windows has 8 metrics (no dropped packets)
    
    // Pre-allocate with exact capacity
    let mut gauge_array = Vec::with_capacity(capacity);
    
    // Common metrics for all platforms
    let common_metrics = [
        ("cpu_usage", log_entry.cpu_usage),
        ("mem_usage", log_entry.mem_usage),
        ("disk_read", log_entry.disk_read as f64),
        ("disk_write", log_entry.disk_write as f64),
        ("bytes_in", log_entry.bytes_in as f64),
        ("bytes_out", log_entry.bytes_out as f64),
        ("packets_in", log_entry.packets_in as f64),
        ("packets_out", log_entry.packets_out as f64),
    ];

    for (metric, value) in &common_metrics {
        gauge_array.push(json!({
            "metric": metric,
            "value": value,
            "dimensions": dimensions.clone(),
            "timestamp": timestamp_ms
        }));
    }
    
    // Unix-specific metrics
    #[cfg(not(target_os = "windows"))]
    {
        let unix_metrics = [
            ("tx_dropped", log_entry.tx_dropped as f64),
            ("rx_dropped", log_entry.rx_dropped as f64),
        ];
        
        for (metric, value) in &unix_metrics {
            gauge_array.push(json!({
                "metric": metric,
                "value": value,
                "dimensions": dimensions.clone(),
                "timestamp": timestamp_ms
            }));
        }
    }

    // Use a static structure to avoid allocations
    let gauge_obj = json!({ "gauge": gauge_array });
    gauge_obj.to_string()
}

pub fn send_gauge(client: &Client, uri: &str, data_json: &str, token: Arc<Option<String>>, timeout: u64) -> Result<(), Error> {
    // Get token value once
    let token_value = match token.as_ref() {
        Some(t) => t.as_str(),
        None => return Ok(()) // Skip if no token available
    };
    
    // Send the request
    let response_result = client.post(uri)
        .header("Content-Type", "application/json; charset=utf-8")
        .header("X-SF-Token", token_value)
        .body(data_json.to_string())
        .timeout(Duration::from_secs(timeout))
        .send();

    match response_result {
        Ok(_) => {
            // agent_logger("debug", "signalfx", "send_gauge", 
            //     r#"{"message": "Data successfully sent."}"#);
            Ok(())
        },
        Err(e) => {
            // Simplified error logging
            let error_type = if e.is_timeout() { "timeout" } 
                else if e.is_connect() { "connection" }
                else { "request" };
                
            agent_logger("error", "signalfx", "send_gauge", 
                &format!(r#"{{"message": "Failed to send data", "error_type": "{}", "error": "{}"}}"#, 
                    error_type, e));
            Err(e)
        }
    }
}

// pub fn send_event(client: &Client, uri: &str, data_json: &str, token: Arc<Option<String>>, timeout: u64) -> Result<(), Error> {

//     let response_result = client.post(format!("{}event", uri))
//         .header("Content-Type", "application/json; charset=utf-8")
//         .header("X-SF-Token", <std::option::Option<std::string::String> as Clone>::clone(token.as_ref()).unwrap().as_str())
//         .body(data_json.to_string())
//         .timeout(Duration::from_secs(timeout))
//         .send();

//         match response_result {
//             Ok(_) => {
//                 agent_logger("info", "send_event", 
//                 r#"{
//                         "message": "Data successfully sent."
//                     }"#);
//                 Ok(())
//             },
//             Err(e) => {
//                 // Check if the error is a timeout
//                 if e.is_timeout() {
//                     agent_logger("error", "send_event", 
//                     r#"{
//                             "message": "Request timed out.",
//                             "error": "Timeout!"
//                         }"#);
//                 } else {
//                     agent_logger("error", "send_event", 
//                     r#"{
//                             "message": "Data could not be sent."
//                         }"#);
//                 }
//                 Err(e)
//             }
//         }
    
// }