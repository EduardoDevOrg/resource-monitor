use std::{fs, path::Path};

use serde::{Serialize, Deserialize};
use sysinfo::{System, Networks};

#[derive(Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: u64,
    cpu_usage: f32,
    total_mem: u64,
    used_mem: u64,
    mem_usage: f32,
    disk_read: u64,
    disk_write: u64,
    bytes_in: u64,
    bytes_out: u64,
    packets_in: u64,
    packets_out: u64,
    hostname: String,
    pub uptime: u64,
    pub component: String,
    pub splunk_uptime: u64,
}

impl LogEntry {
    pub fn new(hostname: String, component: String, splunk_uptime: u64) -> Self {
        Self {
            timestamp: 0,
            cpu_usage: 0.0,
            total_mem: 0,
            used_mem: 0,
            mem_usage: 0.0,
            disk_read: 0,
            disk_write: 0,
            bytes_in: 0,
            bytes_out: 0,
            packets_in: 0,
            packets_out: 0,
            uptime: 0,
            hostname,
            component,
            splunk_uptime,
        }
    }

    pub fn reset(&mut self) {
        self.timestamp = 0;
        self.cpu_usage = 0.0;
        self.total_mem = 0;
        self.used_mem = 0;
        self.mem_usage = 0.0;
        self.disk_read = 0;
        self.disk_write = 0;
        self.bytes_in = 0;
        self.bytes_out = 0;
        self.packets_in = 0;
        self.packets_out = 0;
        self.uptime = 0;
    }

    pub fn update(&mut self, sys: &System, networks: &Networks) {
        for (_interface_name, network) in networks {
            self.bytes_in += network.received();
            self.bytes_out += network.transmitted();
            self.packets_in += network.packets_received();
            self.packets_out += network.packets_transmitted();
        }

        for process in sys.processes().values() {
            let disk_usage = process.disk_usage();
            self.disk_read += disk_usage.read_bytes;
            self.disk_write += disk_usage.written_bytes;
        }

        self.cpu_usage += sys.global_cpu_info().cpu_usage();

        let total_mem = sys.total_memory();
        let used_mem = sys.used_memory();
        self.total_mem += total_mem;
        self.used_mem += used_mem;
        self.mem_usage += used_mem as f32 / total_mem as f32 * 100.0;
    }

    pub fn average(&mut self, interval: u64) {
        self.bytes_in /= interval;
        self.bytes_out /= interval;
        self.packets_in /= interval;
        self.packets_out /= interval;
        self.cpu_usage /= interval as f32;
        self.mem_usage /= interval as f32;
        self.total_mem /= interval;
        self.used_mem /= interval;
    }
}

pub fn check_log_file_size(log_path: &Path) {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let metadata = fs::metadata(log_path).expect("Unable to get log file metadata");
    let file_size = metadata.len();
    if file_size > 10 * 1024 * 1024 {
        fs::write(log_path, "").expect("Unable to clear log file");
        println!("{timestamp} - log_level=\"INFO\" - module=\"hostagent_log\" - Hostagent log was rotated!");
    }
}