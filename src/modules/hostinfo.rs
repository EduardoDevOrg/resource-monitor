use std::time::{SystemTime, UNIX_EPOCH};
use reqwest::blocking::Client;
use reqwest::header::AUTHORIZATION;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct SplunkInfo {
    timestamp: i64,
    cpu_arch: String,
    guid: String,
    health_info: String,
    hostname: String,
    host_fqdn: String,
    manager_uri: String,
    mode: String,
    cpu_num: i64,
    mem_gb: i64,
    os_name: String,
    os_version: String,
    server_name: String,
    server_roles: String,
    shutting_down: bool,    
    startup_time: i64,
    splunk_version: String
}

impl SplunkInfo {
    pub fn new() -> Self {
        SplunkInfo {
            timestamp: 0,
            cpu_arch: String::new(),
            guid: String::new(),
            health_info: String::new(),
            hostname: String::new(),
            host_fqdn: String::new(),
            manager_uri: String::new(),
            mode: String::new(),
            cpu_num: 0,
            mem_gb: 0,
            os_name: String::new(),
            os_version: String::new(),
            server_name: String::new(),
            server_roles: String::new(),
            shutting_down: false,
            startup_time: 0,
            splunk_version: String::new()
        }
    }

    pub fn as_json(&self) -> String {
        serde_json::to_string(self).expect("Failed to serialize startup entry")
    }

    pub fn add_wrapper(&self, index: &str, source: &str, sourcetype: &str, host: String) -> String {
        let splunk_info_json = serde_json::to_string(self).expect("Failed to serialize splunk info entry");

        let wrapper = serde_json::json!({
            "index": index,
            "source": source,
            "sourcetype": sourcetype,
            "host": host,
            "event": serde_json::from_str::<serde_json::Value>(&splunk_info_json).expect("Failed to parse log entry JSON")
        });

        serde_json::to_string(&wrapper).expect("Failed to serialize wrapped log entry")
    }
}


pub fn get_splunkinfo(api: String, token: String) -> Result<SplunkInfo, Box<dyn std::error::Error>> { 
    let url = format!("https://{}/services/server/info", api);

    let client = Client::builder()
        .danger_accept_invalid_certs(true) 
        .build()?;

    let actual_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs() as i64; 

    let response = client.get(url)
        .header(AUTHORIZATION, format!("Splunk {}", token))
        .query(&[("output_mode", "json")])
        .send()?;

    let mut splunk_info = SplunkInfo::new();

    if response.status().is_success() {
        let data: serde_json::Value = response.json()?; 
        let entry_content = &data["entry"][0]["content"];

        splunk_info.timestamp = actual_time;
        splunk_info.cpu_arch = entry_content["cpu_arch"].as_str().unwrap_or("").to_string();
        splunk_info.guid = entry_content["guid"].as_str().unwrap_or("").to_string();
        splunk_info.health_info = entry_content["health_info"].as_str().unwrap_or("").to_string();
        splunk_info.hostname = entry_content["host"].as_str().unwrap_or("").to_string();
        splunk_info.host_fqdn = entry_content["host_fqdn"].as_str().unwrap_or("").to_string();
        splunk_info.manager_uri = entry_content["manager_uri"].as_str().unwrap_or("").to_string();
        splunk_info.mode = entry_content["mode"].as_str().unwrap_or("").to_string();
        splunk_info.cpu_num = entry_content["numberOfVirtualCores"].as_i64().unwrap_or(0);
        splunk_info.mem_gb = ((entry_content["physicalMemoryMB"].as_i64().unwrap_or(0) as f64 / 1024.0).ceil()) as i64;
        splunk_info.os_name = entry_content["os_name"].as_str().unwrap_or("").to_string();
        splunk_info.os_version = entry_content["os_version"].as_str().unwrap_or("").to_string();
        splunk_info.server_name = entry_content["serverName"].as_str().unwrap_or("").to_string();
        splunk_info.server_roles = entry_content["server_roles"].as_str().unwrap_or("").to_string();
        splunk_info.shutting_down = entry_content["shutting_down"].as_bool().unwrap_or(false);
        splunk_info.startup_time = entry_content["startup_time"].as_i64().unwrap_or(0);
        splunk_info.splunk_version = entry_content["version"].as_str().unwrap_or("").to_string();


        
    }
    Ok(splunk_info)
}
