use std::{error::Error, fs, net::IpAddr, path::Path, process};
use pnet::datalink::interfaces;
use sysinfo::System;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct StartupEntry {
    timestamp: u64,
    hostname: String,
    ip_address: Vec<String>,
    splunk_version: String,
    cpu_num: u64,
    mem_total: u64
}

fn get_splunk_version(splunk_root: &Path) -> String {
    let splunk_version_path = splunk_root.join("etc/splunk.version");
    if splunk_version_path.exists() {
        let version_contents = std::fs::read_to_string(&splunk_version_path).unwrap();
        let version_line = version_contents.lines()
            .find(|line| line.starts_with("VERSION="))
            .unwrap_or("");
        version_line.split('=').nth(1).unwrap_or("").to_string()
    } else {
        String::new()
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
        println!("Stopswitch file detected and removed. Exiting process.");
        process::exit(0);
    }
}

pub fn startup_log(hostname: String, splunk_root: &Path, app_folder: &Path) -> Result<String, Box<dyn Error>> {
    let timestamp_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();

    // Initialize the startup entry
    let mut startup_entry = StartupEntry {
        timestamp: timestamp_epoch,
        hostname,
        ip_address: Vec::new(),
        splunk_version: get_splunk_version(splunk_root),
        cpu_num: 0,
        mem_total: 0
    };

    // Get the IP addresses
    let interfaces = interfaces();
    let mut ip_addresses = Vec::new();
    for interface in interfaces {
        for ip in interface.ips {
            
            if let IpAddr::V4(ipv4) = ip.ip() {
                if interface.name != "lo" {
                    ip_addresses.push(ipv4.to_string());
                }
            }
        }
    }
    startup_entry.ip_address = ip_addresses;

    // Get the number of CPUs and total memory
    let sys = System::new_all();
    startup_entry.cpu_num = sys.cpus().len() as u64;
    startup_entry.mem_total = sys.total_memory();

    let app_path = app_folder.join("bin");
    create_stopswitch(&app_path);
    let json_entry = serde_json::to_string(&startup_entry)?;
    Ok(json_entry)
}