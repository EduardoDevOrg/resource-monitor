use std::{fs::File, io::{BufRead, BufReader, Write}};
use serde::{Serialize, Deserialize};
use sysinfo::{Pid, Process};
use serde_json::ser::Formatter;
#[derive(Serialize, Deserialize, Debug)]
pub struct SplunkdTracker {
    pub timestamp: u64,
    pub component: String,
    pub pid: u32,
    pub mem_usage: f64,
    pub cpu_usage: f64,
    pub run_time: u64,
    pub disk_write: u64,
    pub disk_read: u64,
    pub tasks: u64,
    pub packets_in: u64,
    pub packets_out: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub tx_dropped: u64,
    pub rx_dropped: u64,
    pub open_connections: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SplunkEntry {
    pub timestamp: u64,
    pub component: String,
    pub pid: u32,
    pub message: String,
    pub eventtype: String,
    pub category: String,
}

#[derive(Debug, Clone)]
pub struct NetworkStats {
    pub packets_in: u64,
    pub packets_out: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub tx_dropped: u64,
    pub rx_dropped: u64,
    pub open_connections: u64,
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

impl SplunkdTracker {
    pub fn new(pid: u32) -> Self {
        Self { timestamp: 0, component: "splunkd_tracker".to_string(), pid, mem_usage: 0.0, cpu_usage: 0.0, run_time: 0, disk_write: 0, disk_read: 0, tasks: 0, packets_in: 0, packets_out: 0, bytes_in: 0, bytes_out: 0, tx_dropped: 0, rx_dropped: 0, open_connections: 0 }
    }

    pub fn update(&mut self, p_entry: &Process, network_stats: &NetworkStats, total_mem: u64, cpu_num: u64) {
        self.mem_usage += p_entry.memory() as f64 / total_mem as f64 * 100.0;
        self.cpu_usage += p_entry.cpu_usage() as f64 / cpu_num as f64;
        self.disk_write += p_entry.disk_usage().written_bytes;
        self.disk_read += p_entry.disk_usage().read_bytes;
        self.tasks += p_entry.tasks().map_or(0, |tasks| tasks.len() as u64);
        self.packets_in += network_stats.packets_in;
        self.packets_out += network_stats.packets_out;
        self.bytes_in += network_stats.bytes_in;
        self.bytes_out += network_stats.bytes_out;
        self.tx_dropped += network_stats.tx_dropped;
        self.rx_dropped += network_stats.rx_dropped;
        self.open_connections += network_stats.open_connections;
        self.run_time = p_entry.run_time();
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
        self.tasks /= sample_count;
        self.open_connections /= sample_count;
    }


    pub fn write_json<W: Write>(&self, writer: W) -> serde_json::Result<()> {
        let mut serializer = serde_json::Serializer::with_formatter(writer, CustomFormatter);
        self.serialize(&mut serializer)
    }
}

impl NetworkStats {
    pub fn new() -> Self {
        Self { packets_in: 0, packets_out: 0, bytes_in: 0, bytes_out: 0, tx_dropped: 0, rx_dropped: 0, open_connections: 0 }
    }
}

impl SplunkEntry {
    pub fn new(timestamp: u64, pid: u32, message: String, eventtype: &str, category: &str) -> Self {
        Self { timestamp, component: "splunkd_tracker".to_string(), pid, message, eventtype: eventtype.to_string(), category: category.to_string() }
    }

    pub fn write_json<W: Write>(&self, writer: W) -> serde_json::Result<()> {
        let mut serializer = serde_json::Serializer::with_formatter(writer, CustomFormatter);
        self.serialize(&mut serializer)
    }
}

pub fn get_network_stats(pid: Pid) -> NetworkStats {
    let mut network_stats = NetworkStats::new();
    let net_stats = format!("/proc/{}/net/dev", pid);
    let conn_stats = format!("/proc/{}/net/tcp", pid);
    let file = File::open(net_stats).expect("Failed to open /proc/net/dev");
    let conn_file = File::open(conn_stats).expect("Failed to open /proc/net/tcp");
    let reader = BufReader::new(file);
    let conn_reader = BufReader::new(conn_file);

    for line in reader.lines().skip(2) { // Skip the first two header lines
        let line = line.expect("Failed to read line");
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() != 2 {
            continue; // Skip malformed lines
        }
        let values: Vec<&str> = parts[1].split_whitespace().collect();
        if values.len() < 16 {
            continue; // Skip lines with insufficient data
        }

        // Accumulate stats from all interfaces
        network_stats.bytes_in += values[0].parse::<u64>().unwrap_or(0);
        network_stats.packets_in += values[1].parse::<u64>().unwrap_or(0);
        network_stats.rx_dropped += values[3].parse::<u64>().unwrap_or(0);
        network_stats.bytes_out += values[8].parse::<u64>().unwrap_or(0);
        network_stats.packets_out += values[9].parse::<u64>().unwrap_or(0);
        network_stats.tx_dropped += values[11].parse::<u64>().unwrap_or(0);
    }

    for line in conn_reader.lines().skip(1) { // Skip the header line
        let line = line.expect("Failed to read line");
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue; // Skip malformed lines
        }
        
        // Check if the connection state is ESTABLISHED (01)
        if parts[3] == "01" {
            network_stats.open_connections += 1;
        }
    }

    network_stats
}

pub fn network_change(pid: Pid, old_network_stats: &mut NetworkStats) -> NetworkStats {
    let mut new_network_stats = get_network_stats(pid);
    let new_baseline = new_network_stats.clone();
    new_network_stats.packets_in -= old_network_stats.packets_in;
    new_network_stats.packets_out -= old_network_stats.packets_out;
    new_network_stats.bytes_in -= old_network_stats.bytes_in;
    new_network_stats.bytes_out -= old_network_stats.bytes_out;
    new_network_stats.tx_dropped -= old_network_stats.tx_dropped;
    new_network_stats.rx_dropped -= old_network_stats.rx_dropped;
    *old_network_stats = new_baseline;
    new_network_stats
}

pub fn pid_compare(old_pid: u32, pid: u32) -> Option<SplunkEntry> {
    if old_pid != pid {  
        let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Time went backwards")  
        .as_secs();
        let message = "Splunkd process has been started!".to_string();
        let splunk_entry = SplunkEntry::new(timestamp, pid, message, "splunkd_start", "EXCEPTION");
        Some(splunk_entry)
    } else {
        None
    }
}