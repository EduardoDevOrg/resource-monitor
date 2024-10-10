use std::collections::HashMap;

use serde::{Serialize, Deserialize};
use sysinfo::Disks;
use super::diskstats;

#[derive(Serialize, Deserialize, Debug)]
pub struct StorewatchEntryLinux {
    pub timestamp: u64,
    pub hostname: String,
    pub component: String,
    pub disk_name: String,
    pub mounts: Vec<String>,
    pub total_size: u64,
    pub free_size: u64,
    pub used_size: u64,
    pub disk_usage: f64,
    pub reads: u64,
    pub writes: u64,
    pub time_read: u64,
    pub time_write: u64,
    pub in_progress: u64,
    pub time_in_progress: u64,
    pub weighted_time_in_progress: u64,
    pub bytes_read: u64,
    pub bytes_written: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct StorewatchEntryWindows {
    timestamp: u64,
    hostname: String,
    component: String,
    disk_name: String,
    partition_name: String,
    total_size: u64,
    free_size: u64,
    used_size: u64,
    disk_usage: f64
}

impl StorewatchEntryLinux {
    pub fn new_linux(hostname: String) -> Self {
        StorewatchEntryLinux {
            timestamp: 0,
            hostname,   
            component:"storage_watcher".to_string(),
            disk_name: "".to_string(),
            mounts: Vec::new(),
            total_size: 0,
            free_size: 0,
            used_size: 0,
            disk_usage: 0.0,
            reads: 0,
            writes: 0,
            time_read: 0,
            time_write: 0,
            in_progress: 0,
            time_in_progress: 0,
            weighted_time_in_progress: 0,
            bytes_read: 0,
            bytes_written: 0,
        }
    }

    pub fn add_wrapper(&self, index: &str, source: &str, sourcetype: &str, host: String) -> String {
        let storewatch_entry_json = serde_json::to_string(self).expect("Failed to serialize startup entry");

        let wrapper = serde_json::json!({
            "index": index,
            "source": source,
            "sourcetype": sourcetype,
            "host": host,
            "event": serde_json::from_str::<serde_json::Value>(&storewatch_entry_json).expect("Failed to parse log entry JSON")
        });

        serde_json::to_string(&wrapper).expect("Failed to serialize wrapped log entry")
    }
}
impl StorewatchEntryWindows {

    pub fn new_windows(hostname: String) -> Self {
        StorewatchEntryWindows {
            timestamp: 0,
            hostname,   
            component:"storage_watcher".to_string(),
            disk_name: "".to_string(),
            partition_name: "".to_string(),
            total_size: 0,
            free_size: 0,
            used_size: 0,
            disk_usage: 0.0
        }
    }

    pub fn add_wrapper(&self, index: &str, source: &str, sourcetype: &str, host: String) -> String {
        let storewatch_entry_json = serde_json::to_string(self).expect("Failed to serialize startup entry");

        let wrapper = serde_json::json!({
            "index": index,
            "source": source,
            "sourcetype": sourcetype,
            "host": host,
            "event": serde_json::from_str::<serde_json::Value>(&storewatch_entry_json).expect("Failed to parse log entry JSON")
        });

        serde_json::to_string(&wrapper).expect("Failed to serialize wrapped log entry")
    }
}

pub fn get_storage_linux(hostname: &str) -> Vec<StorewatchEntryLinux> {
    let mut disk_stats_collection: HashMap<String, Vec<diskstats::DiskStat>> = HashMap::new();
    let mut disk_info_collection: HashMap<String, Vec<(u64, u64, u64, f64)>> = HashMap::new();
    let mut disk_data = Disks::new_with_refreshed_list();

    for i in 0..11 {  // We now collect 11 samples to calculate 10 differences
        disk_data.refresh();
        let disks = disk_data.list();
        for disk in disks {
            let disk_name = disk.name().to_string_lossy().to_string();
            let total_size = disk.total_space();
            let available_size = disk.available_space();
            let used_size = total_size - available_size;
            let disk_usage = (used_size as f64 / total_size as f64) * 100.0;
            
            disk_info_collection.entry(disk_name.clone())
                .or_default()
                .push((total_size, available_size, used_size, disk_usage));
        }

        let diskstats = diskstats::read_current();
        for stat in diskstats {
            disk_stats_collection.entry(stat.name.clone())
                .or_default()
                .push(stat);
        }
        if i < 10 {  // Don't sleep after the last iteration
            std::thread::sleep(std::time::Duration::from_millis(990));
        }
    }

    let timestamp_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();

    let mut storage_entries = Vec::new();

    for (disk_name, disk_info) in disk_info_collection.iter() {
        let mut storage_entry = StorewatchEntryLinux::new_linux(hostname.to_string());
        storage_entry.timestamp = timestamp_epoch;
        storage_entry.disk_name = disk_name.clone();

        // Calculate averages
        let info_len = disk_info.len() as u64;
        storage_entry.total_size = disk_info.iter().map(|&(total, _, _, _)| total).sum::<u64>() / info_len;
        storage_entry.free_size = disk_info.iter().map(|&(_, free, _, _)| free).sum::<u64>() / info_len;
        storage_entry.used_size = disk_info.iter().map(|&(_, _, used, _)| used).sum::<u64>() / info_len;
        storage_entry.disk_usage = disk_info.iter().map(|&(_, _, _, usage)| usage).sum::<f64>() / info_len as f64;

        // Get the mount points from the last entry (assuming they don't change)
        if let Some(last_disk) = disk_data.list().iter().find(|d| d.name().to_string_lossy() == *disk_name) {
            storage_entry.mounts.push(last_disk.mount_point().to_string_lossy().to_string());
        }

        let sanitized_disk_name = disk_name.replace("/dev/", "");
        let sector_size = diskstats::get_sector_size(&sanitized_disk_name).unwrap_or(512);

        // Calculate average disk stats changes if available
        if let Some(stats) = disk_stats_collection.get(disk_name) {
            if stats.len() > 1 {
                let mut total_reads = 0;
                let mut total_writes = 0;
                let mut total_time_read = 0;
                let mut total_time_write = 0;
                let mut total_time_in_progress = 0;
                let mut total_weighted_time_in_progress = 0;
                let mut total_bytes_read = 0;
                let mut total_bytes_written = 0;

                for i in 1..stats.len() {
                    let prev = &stats[i-1];
                    let curr = &stats[i];
                    total_reads += curr.reads.saturating_sub(prev.reads);
                    total_writes += curr.writes.saturating_sub(prev.writes);
                    total_time_read += curr.time_reading.saturating_sub(prev.time_reading);
                    total_time_write += curr.time_writing.saturating_sub(prev.time_writing);
                    total_time_in_progress += curr.time_in_progress.saturating_sub(prev.time_in_progress);
                    total_weighted_time_in_progress += curr.weighted_time_in_progress.saturating_sub(prev.weighted_time_in_progress);
                    total_bytes_read += (curr.sectors_read * sector_size).saturating_sub(prev.sectors_read * sector_size);
                    total_bytes_written += (curr.sectors_written * sector_size).saturating_sub(prev.sectors_written * sector_size);
                }

                let samples = (stats.len() - 1) as u64;
                storage_entry.reads = total_reads / samples;
                storage_entry.writes = total_writes / samples;
                storage_entry.time_read = total_time_read / samples;
                storage_entry.time_write = total_time_write / samples;
                storage_entry.time_in_progress = total_time_in_progress / samples;
                storage_entry.weighted_time_in_progress = total_weighted_time_in_progress / samples;
                storage_entry.in_progress = stats.last().map_or(0, |s| s.in_progress);
                storage_entry.bytes_read = total_bytes_read / samples;
                storage_entry.bytes_written = total_bytes_written / samples;
            }
        }

        storage_entries.push(storage_entry);
    }
    storage_entries     
}

pub fn get_storage_windows(hostname: &str) -> Vec<StorewatchEntryWindows> {
    let disk_data = Disks::new_with_refreshed_list();
    let disks = disk_data.list();

    let timestamp_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();

        let mut storage_entries = Vec::new();

        for disk in disks {
            let total_size = disk.total_space();
            let used_size = disk.total_space() - disk.available_space();
            let free_size = disk.available_space();
            let usage = (used_size as f64 / total_size as f64) * 100.0;
            
            let mut storage_entry = StorewatchEntryWindows::new_windows(hostname.to_string());
            storage_entry.timestamp = timestamp_epoch;
            storage_entry.partition_name = disk.name().to_string_lossy().to_string();
            storage_entry.disk_name = disk.mount_point().to_string_lossy().to_string();
            storage_entry.total_size = total_size;
            storage_entry.free_size = free_size;
            storage_entry.used_size = used_size;
            storage_entry.disk_usage = usage;

            storage_entries.push(storage_entry);
        }

        storage_entries
}
