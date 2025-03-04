use std::{fs, path::Path};
use serde::{Serialize, Deserialize};
use serde_json::ser::Formatter;
use sysinfo::{System, Networks};
use std::io::Write;
use super::logging::agent_logger;

#[derive(Serialize, Deserialize, Debug)]
pub struct LogEntry<'a> {
    pub timestamp: u64,
    pub cpu_usage: f64,
    pub total_mem: u64,
    pub used_mem: u64,
    pub mem_usage: f64,
    pub disk_read: u64,
    pub disk_write: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub packets_in: u64,
    pub packets_out: u64,
    pub tx_dropped: u64,
    pub rx_dropped: u64,
    #[serde(skip_serializing)]
    pub tx_dropped_baseline: u64,
    #[serde(skip_serializing)]
    pub rx_dropped_baseline: u64,
    pub hostname: &'a str,
    pub uptime: u64,
    pub component: &'a str,
    pub agent_starttime: u64,
}

struct CustomFormatter;

impl Formatter for CustomFormatter {
    fn write_f64<W>(&mut self, writer: &mut W, value: f64) -> std::io::Result<()>
    where
        W: Write + ?Sized,
    {
        write!(writer, "{:.3}", value)
    }
}

impl<'a> LogEntry<'a> {
    pub fn new(hostname: &'a str, component: &'a str, agent_starttime: u64) -> Self {
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
            tx_dropped: 0,
            rx_dropped: 0,
            tx_dropped_baseline: 0,
            rx_dropped_baseline: 0,
            uptime: 0,
            hostname,
            component,
            agent_starttime,
        }
    }

    pub fn calculate_baseline(&mut self, networks: &Networks) {
        let mut tx_dropped_path = String::with_capacity(64);
        let mut rx_dropped_path = String::with_capacity(64);
        
        for (interface_name, _) in networks.iter() {
            tx_dropped_path.clear();
            rx_dropped_path.clear();
            
            tx_dropped_path.push_str("/sys/class/net/");
            tx_dropped_path.push_str(interface_name);
            tx_dropped_path.push_str("/statistics/tx_dropped");
            
            rx_dropped_path.push_str("/sys/class/net/");
            rx_dropped_path.push_str(interface_name);
            rx_dropped_path.push_str("/statistics/rx_dropped");

            if let Ok(tx_dropped_str) = fs::read_to_string(&tx_dropped_path) {
                if let Ok(tx_dropped_value) = tx_dropped_str.trim().parse::<u64>() {
                    self.tx_dropped_baseline += tx_dropped_value;
                }
            }

            if let Ok(rx_dropped_str) = fs::read_to_string(&rx_dropped_path) {
                if let Ok(rx_dropped_value) = rx_dropped_str.trim().parse::<u64>() {
                    self.rx_dropped_baseline += rx_dropped_value;
                }
            }
        }
    }

    pub fn update(&mut self, system: &System, networks: &Networks) {
        let mut total_tx_dropped = 0;
        let mut total_rx_dropped = 0;
        
        let mut tx_dropped_path = String::with_capacity(64);
        let mut rx_dropped_path = String::with_capacity(64);

        for (interface_name, network) in networks.iter() {
            self.bytes_in += network.received();
            self.bytes_out += network.transmitted();
            self.packets_in += network.packets_received();
            self.packets_out += network.packets_transmitted();

            tx_dropped_path.clear();
            rx_dropped_path.clear();
            
            tx_dropped_path.push_str("/sys/class/net/");
            tx_dropped_path.push_str(interface_name);
            tx_dropped_path.push_str("/statistics/tx_dropped");
            
            rx_dropped_path.push_str("/sys/class/net/");
            rx_dropped_path.push_str(interface_name);
            rx_dropped_path.push_str("/statistics/rx_dropped");

            if let Ok(tx_dropped_str) = fs::read_to_string(&tx_dropped_path) {
                if let Ok(tx_dropped_value) = tx_dropped_str.trim().parse::<u64>() {
                    total_tx_dropped += tx_dropped_value;
                }
            }

            if let Ok(rx_dropped_str) = fs::read_to_string(&rx_dropped_path) {
                if let Ok(rx_dropped_value) = rx_dropped_str.trim().parse::<u64>() {
                    total_rx_dropped += rx_dropped_value;
                }
            }
        }

        self.tx_dropped += total_tx_dropped.saturating_sub(self.tx_dropped_baseline);
        self.rx_dropped += total_rx_dropped.saturating_sub(self.rx_dropped_baseline);
        self.tx_dropped_baseline = total_tx_dropped;
        self.rx_dropped_baseline = total_rx_dropped;

        let mut total_disk_read = 0;
        let mut total_disk_write = 0;
        
        for process in system.processes().values() {
            let disk_usage = process.disk_usage();
            total_disk_read += disk_usage.read_bytes;
            total_disk_write += disk_usage.written_bytes;
        }
        
        self.disk_read += total_disk_read;
        self.disk_write += total_disk_write;

        self.cpu_usage += system.global_cpu_usage() as f64;
        self.total_mem = system.total_memory();
        self.used_mem = system.used_memory();
        self.mem_usage += self.used_mem as f64 / self.total_mem as f64 * 100.0;
    }

    pub fn finalize(&mut self, sample_count: u64) {
        if sample_count == 0 {
            return;
        }
        
        let count = sample_count as f64;
        self.cpu_usage /= count;
        self.mem_usage /= count;
        
        self.bytes_in /= sample_count;
        self.bytes_out /= sample_count;
        self.packets_in /= sample_count;
        self.packets_out /= sample_count;
        self.disk_read /= sample_count;
        self.disk_write /= sample_count;
    }

    pub fn reset(&mut self) {
        self.cpu_usage = 0.0;
        self.mem_usage = 0.0;
        self.bytes_in = 0;
        self.bytes_out = 0;
        self.packets_in = 0;
        self.packets_out = 0;
        self.disk_read = 0;
        self.disk_write = 0;
        self.tx_dropped = 0;
        self.rx_dropped = 0;
    }

    pub fn write_json<W: Write>(&self, writer: W) -> serde_json::Result<()> {
        let mut serializer = serde_json::Serializer::with_formatter(writer, CustomFormatter);
        self.serialize(&mut serializer)
    }

    pub fn add_wrapper(&self, index: &str, source: &str, sourcetype: &str, host: String) -> String {
        let mut json_buffer = Vec::with_capacity(1024);
        self.write_json(&mut json_buffer).expect("Failed to serialize log entry");
        
        let event_value = serde_json::from_slice::<serde_json::Value>(&json_buffer)
            .expect("Failed to parse log entry JSON");
        
        let wrapper = serde_json::json!({
            "index": index,
            "source": source,
            "sourcetype": sourcetype,
            "host": host,
            "event": event_value
        });

        serde_json::to_string(&wrapper).expect("Failed to serialize wrapped log entry")
    }
}

const LOG_FILE_SIZE_LIMIT: u64 = 10 * 1024 * 1024;

pub fn check_log_file_size(log_path: &Path) {
    match fs::metadata(log_path) {
        Ok(metadata) => {
            let file_size = metadata.len();
            if file_size > LOG_FILE_SIZE_LIMIT {
                if let Err(e) = fs::write(log_path, "") {
                    agent_logger("error", "log_entry", "check_log_file_size", 
                        &format!(r#"{{"message": "Failed to clear log file", "error": "{}"}}"#, e));
                } else {
                    agent_logger("info", "log_entry", "check_log_file_size", 
                        r#"{"message": "Agent log was rotated!"}"#);
                }
            }
        },
        Err(e) => {
            agent_logger("error", "log_entry", "check_log_file_size", 
                &format!(r#"{{"message": "Unable to get log file metadata", "error": "{}"}}"#, e));
        }
    }
}
