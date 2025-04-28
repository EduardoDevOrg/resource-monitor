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
        let startup_entry_json = serde_json::to_string(self).expect("Failed to serialize startup entry");

        let wrapper = serde_json::json!({
            "index": index,
            "source": source,
            "sourcetype": sourcetype,
            "host": host,
            "event": serde_json::from_str::<serde_json::Value>(&startup_entry_json).expect("Failed to parse log entry JSON")
        });

        serde_json::to_string(&wrapper).expect("Failed to serialize wrapped log entry")
    }
}


fn get_splunk_version(splunk_root: &Path) -> String {
    // Construct the path to splunk.version based on the platform
    #[cfg(target_os = "windows")]
    let splunk_path = splunk_root.join("etc").join("splunk.version");
    
    #[cfg(not(target_os = "windows"))]
    let splunk_path = splunk_root.join("etc/splunk.version");
    
    if splunk_path.exists() {
        match std::fs::read_to_string(&splunk_path) {
            Ok(version_contents) => {
                let version_line = version_contents.lines()
                    .find(|line| line.starts_with("VERSION="))
                    .unwrap_or("");
                version_line.split('=').nth(1).unwrap_or("").to_string()
            },
            Err(_) => String::from("unknown"),
        }
    } else {
        String::from("non_splunk")
    }
}

fn get_instance_id(splunk_root: &Path) -> String {
    // Construct the path to instance.cfg based on the platform
    #[cfg(target_os = "windows")]
    let instance_id_path = splunk_root.join("etc").join("instance.cfg");
    
    #[cfg(not(target_os = "windows"))]
    let instance_id_path = splunk_root.join("etc/instance.cfg");
    
    if instance_id_path.exists() {
        match std::fs::read_to_string(&instance_id_path) {
            Ok(instance_id_content) => {
                for line in instance_id_content.lines() {
                    if line.trim().starts_with("guid =") {
                        if let Some(guid) = line.split('=').nth(1) {
                            return guid.trim().to_string();
                        }
                    }
                }
                // Log error if no GUID found
                agent_logger("error", "startup", "get_instance_id",
                r#"{
                    "message": "No instance ID found in instance.cfg"
                }"#);
                String::from("non_splunk")
            },
            Err(e) => {
                // Log error if can't read the file
                agent_logger("error", "startup", "get_instance_id",
                &format!(r#"{{
                    "message": "Failed to read instance.cfg",
                    "error": "{}"
                }}"#, e));
                String::from("unknown")
            }
        }
    } else {
        String::from("non_splunk")
    }
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
        agent_logger("info", "startup", "check_stopswitch",
        r#"{
                "message": "Stopswitch file detected and removed. Exiting process."
            }"#);
        process::exit(0);
    }
}

pub fn startup_log(hostname: &str, app_folder: &Path) -> Result<StartupEntry, Box<dyn Error>> {
    let timestamp_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();


    agent_logger("debug", "startup", "startup_log", r#"{
                "message": "Starting startup log."
            }"#);
    let splunk_root;
    let mut is_splunk = false;
    let app_folder_str = app_folder.to_string_lossy().to_lowercase();
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
        agent_logger(
            "INFO", "startup", "startup_log", r#"{
                "message": "Startup_log completed successfully. Stopswitch file created."
            }"#);
        create_stopswitch(&app_folder);
    }

    Ok(startup_entry)
}