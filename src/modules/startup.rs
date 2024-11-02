use std::{error::Error, fs, net::IpAddr, path::Path, process};
use sysinfo::System;
use serde::{Serialize, Deserialize};
use if_addrs::get_if_addrs;
use super::logging::agent_logger;
use super::config::get_splunk_pid;

#[derive(Serialize, Deserialize, Debug)]
pub struct StartupEntry {
    timestamp: u64,
    hostname: String,
    component: String,
    ip_address: Vec<String>,
    splunk_version: String,
    instance_id: String,
    cpu_num: u64,
    mem_total: u64,
    splunk_pid: u32
}

impl StartupEntry {
    pub fn new(hostname: String, splunk_root: &Path) -> Self {
        StartupEntry {
            timestamp: 0,
            hostname,   
            component:"startup".to_string(),
            ip_address: Vec::new(),
            splunk_version: get_splunk_version(splunk_root),
            instance_id: get_instance_id(splunk_root),
            cpu_num: 0,
            mem_total: 0,
            splunk_pid: get_splunk_pid(splunk_root)
        }
    }

    pub fn as_json(&self) -> String {
        serde_json::to_string(self).expect("Failed to serialize startup entry")
    }

    pub fn add_wrapper(&self, index: &str, source: &str, sourcetype: &str, host: String) -> String {
        let entry = serde_json::to_string(self).expect("Failed to serialize log entry");
    
        let wrapper = serde_json::json!({
            "index": index,
            "source": source,
            "sourcetype": sourcetype,
            "host": host,
            "event": serde_json::from_str::<serde_json::Value>(&entry).expect("Failed to parse log entry JSON")
        });
    
        serde_json::to_string(&wrapper).expect("Failed to serialize wrapped log entry")
    }
}

fn get_splunk_version(splunk_root: &Path) -> String {
    let splunk_path = splunk_root.join("etc/splunk.version");
    if splunk_path.exists() {
        let version_contents = std::fs::read_to_string(&splunk_path).unwrap();
        let version_line = version_contents.lines()
            .find(|line| line.starts_with("VERSION="))
            .unwrap_or("");
        version_line.split('=').nth(1).unwrap_or("").to_string()
    } else {
        String::from("non_splunk")
    }
}

fn get_instance_id(splunk_root: &Path) -> String {
    let instance_id_path = splunk_root.join("etc/instance.cfg");
    
    if let Ok(instance_id_content) = std::fs::read_to_string(&instance_id_path) {
        for line in instance_id_content.lines() {
            if let Some(guid) = line.trim().strip_prefix("guid = ").map(str::trim) {
                return guid.to_string();
            }
        }
        agent_logger("error", "get_instance_id", 
        r#"{
                "message": "No instance ID found in instance.cfg",
                "module": "startup"
            }"#);
    }
    
    String::from("non_splunk")
}

fn create_stopswitch(switchpath: &Path) {    
    let stopswitch_path = switchpath.join(".stopswitch");
    if !stopswitch_path.exists() {
        std::fs::File::create(&stopswitch_path).expect("Failed to create .stopswitch file");
    }
}

pub fn check_stopswitch(switchpath: &Path) {    
    let stopswitch_path = switchpath.join(".stopswitch");
    if stopswitch_path.exists() {
        fs::remove_file(&stopswitch_path).expect("Failed to remove .stopswitch file");
        agent_logger("info", "check_stopswitch", 
        r#"{
                "message": "Stopswitch file detected and removed. Exiting process.",
                "module": "startup"
            }"#);
        process::exit(0);
    }
}

pub fn startup_log(hostname: &str, app_folder: &Path) -> Result<StartupEntry, Box<dyn Error>> {
    let timestamp_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();

    let splunk_root;
    let mut is_splunk = false;
    let app_folder_str = app_folder.to_string_lossy();
    if ["splunk", "splunkforwarder", "splunkuniversalforwarder"]
        .iter()
        .any(|&s| app_folder_str.contains(s))
    {
        splunk_root = app_folder.parent().unwrap().parent().unwrap().parent().unwrap();
        is_splunk = true;
    } else {
        splunk_root = app_folder;
    }

    let mut startup_entry = StartupEntry::new(hostname.to_string(), splunk_root);
    startup_entry.timestamp = timestamp_epoch;
    startup_entry.hostname = hostname.to_string();

    // Get the IP addresses
    let if_addrs = get_if_addrs()?;
    let mut ip_addresses = Vec::new();
    for iface in if_addrs {
        if let IpAddr::V4(ipv4) = iface.ip() {
            if !iface.name.starts_with("lo") {
                ip_addresses.push(ipv4.to_string());
            }
        }
    }
    startup_entry.ip_address = ip_addresses;

    // Get the number of CPUs and total memory
    let sys = System::new_all();
    startup_entry.cpu_num = sys.cpus().len() as u64;
    startup_entry.mem_total = sys.total_memory();

    if is_splunk {
        let app_path = app_folder.join("bin");
        create_stopswitch(&app_path);
    }

    Ok(startup_entry)
}