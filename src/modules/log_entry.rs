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
        for (interface_name, _network) in networks.iter() {
            let tx_dropped_path = format!("/sys/class/net/{}/statistics/tx_dropped", interface_name);
            let rx_dropped_path = format!("/sys/class/net/{}/statistics/rx_dropped", interface_name);

            if let Ok(tx_dropped_str) = fs::read_to_string(&tx_dropped_path) {
                if let Ok(tx_dropped_value) = tx_dropped_str.trim().parse::<u64>() {
                    self.tx_dropped_baseline += tx_dropped_value; // Set initial baseline
                }
            }

            if let Ok(rx_dropped_str) = fs::read_to_string(&rx_dropped_path) {
                if let Ok(rx_dropped_value) = rx_dropped_str.trim().parse::<u64>() {
                    self.rx_dropped_baseline += rx_dropped_value; // Set initial baseline
                }
            }
        }
    }


    pub fn update(&mut self, sys: &System, networks: &Networks) {
        let mut total_tx_dropped = 0;
        let mut total_rx_dropped = 0;

        for (interface_name, network) in networks.iter() {
            self.bytes_in += network.received();
            self.bytes_out += network.transmitted();
            self.packets_in += network.packets_received();
            self.packets_out += network.packets_transmitted();

            let tx_dropped_path = format!("/sys/class/net/{}/statistics/tx_dropped", interface_name);
            let rx_dropped_path = format!("/sys/class/net/{}/statistics/rx_dropped", interface_name);

            if let Ok(tx_dropped_str) = fs::read_to_string(&tx_dropped_path) {
                if let Ok(tx_dropped_value) = tx_dropped_str.trim().parse::<u64>() {
                    total_tx_dropped += tx_dropped_value; // Track total dropped in this period
                }
            }

            if let Ok(rx_dropped_str) = fs::read_to_string(&rx_dropped_path) {
                if let Ok(rx_dropped_value) = rx_dropped_str.trim().parse::<u64>() {
                    total_rx_dropped += rx_dropped_value; // Track total dropped in this period
                }
            }
        }

        self.tx_dropped += total_tx_dropped.saturating_sub(self.tx_dropped_baseline);
        self.rx_dropped += total_rx_dropped.saturating_sub(self.rx_dropped_baseline);
        self.tx_dropped_baseline = total_tx_dropped;
        self.rx_dropped_baseline = total_rx_dropped;


        for process in sys.processes().values() {
            let disk_usage = process.disk_usage();
            self.disk_read += disk_usage.read_bytes;
            self.disk_write += disk_usage.written_bytes;
        }

        self.cpu_usage += sys.global_cpu_usage() as f64;

        let total_mem = sys.total_memory();
        let used_mem = sys.used_memory();
        self.total_mem = total_mem; // Set to the current value
        self.used_mem = used_mem; // Set to the current value
        self.mem_usage += used_mem as f64 / total_mem as f64 * 100.0;
    }

    pub fn finalize(&mut self, sample_count: u64) {
        self.cpu_usage /= sample_count as f64;
        self.mem_usage /= sample_count as f64;
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
        let log_entry_json = serde_json::to_string(self).expect("Failed to serialize log entry");

        let wrapper = serde_json::json!({
            "index": index,
            "source": source,
            "sourcetype": sourcetype,
            "host": host,
            "event": serde_json::from_str::<serde_json::Value>(&log_entry_json).expect("Failed to parse log entry JSON")
        });

        serde_json::to_string(&wrapper).expect("Failed to serialize wrapped log entry")
    }

}



pub fn check_log_file_size(log_path: &Path) {
    let metadata = fs::metadata(log_path).expect("Unable to get log file metadata");
    let file_size = metadata.len();
    if file_size > 10 * 1024 * 1024 {
        fs::write(log_path, "").expect("Unable to clear log file");
        agent_logger("info", "check_log_file_size", 
        r#"{
                "message": "Agent log was rotated!"
            }"#);
    }
}
