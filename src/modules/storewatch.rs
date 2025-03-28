use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use sysinfo::Disks;
use super::logging::agent_logger;
#[cfg(target_os = "linux")]
use super::diskstats;

// Platform-agnostic StorewatchEntry trait
#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "platform")]
pub enum StorewatchEntry {
    #[serde(rename = "linux")]
    Linux(StorewatchEntryLinux),
    #[serde(rename = "windows")]
    Windows(StorewatchEntryWindows),
}

impl StorewatchEntry {
    pub fn add_wrapper(&self, index: &str, source: &str, sourcetype: &str, host: String) -> String {
        let entry_json = serde_json::to_string(self).expect("Failed to serialize entry");

        let wrapper = serde_json::json!({
            "index": index,
            "source": source,
            "sourcetype": sourcetype,
            "host": host,
            "event": serde_json::from_str::<serde_json::Value>(&entry_json).expect("Failed to parse log entry JSON")
        });

        serde_json::to_string(&wrapper).expect("Failed to serialize wrapped log entry")
    }
}

// Linux-specific implementation (existing code)
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

impl StorewatchEntryLinux {
    #[allow(dead_code)]
    pub fn new(hostname: String) -> Self {
        StorewatchEntryLinux {
            timestamp: 0,
            hostname,   
            component: "storage_watcher".to_string(),
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
}

// Windows-specific implementation with reduced fields
#[derive(Serialize, Deserialize, Debug)]
pub struct StorewatchEntryWindows {
    pub timestamp: u64,
    pub hostname: String,
    pub component: String,
    pub disk_name: String,
    pub partitions: Vec<String>, // "mounts" renamed to "partitions" for Windows
    pub total_size: u64,
    pub free_size: u64,
    pub used_size: u64,
    pub bytes_read: u64,
    pub bytes_written: u64,
}

impl StorewatchEntryWindows {
    #[allow(dead_code)]
    pub fn new(hostname: String) -> Self {
        StorewatchEntryWindows {
            timestamp: 0,
            hostname,   
            component: "storage_watcher".to_string(),
            disk_name: "".to_string(),
            partitions: Vec::new(),
            total_size: 0,
            free_size: 0,
            used_size: 0,
            bytes_read: 0,
            bytes_written: 0,
        }
    }
}

// Cross-platform function to get storage information
pub fn get_storage(hostname: &str) -> Vec<StorewatchEntry> {
    #[cfg(target_os = "linux")]
    {
        get_storage_linux(hostname)
            .into_iter()
            .map(StorewatchEntry::Linux)
            .collect()
    }
    #[cfg(target_os = "windows")]
    {
        get_storage_windows(hostname)
            .into_iter()
            .map(StorewatchEntry::Windows)
            .collect()
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        agent_logger("error", "storewatch", "get_storage",
            r#"{
                "message": "Unsupported operating system"
            }"#
        );
        Vec::new()
    }
}

// Linux implementation (existing code)
#[cfg(target_os = "linux")]
pub fn get_storage_linux(hostname: &str) -> Vec<StorewatchEntryLinux> {
    let mut disk_stats_collection: HashMap<String, Vec<diskstats::DiskStat>> = HashMap::new();
    let mut disk_info_collection: HashMap<String, Vec<(u64, u64, u64, f64)>> = HashMap::new();
    let mut disk_data = Disks::new_with_refreshed_list();
    if disk_data.list().is_empty() {
        agent_logger("error", "storewatch", "get_storage_linux",
            r#"{
                "message": "Failed to retrieve disk data"
            }"#
        );
    }

    for i in 0..11 {  // We now collect 11 samples to calculate 10 differences
        disk_data.refresh(true);
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
        let mut storage_entry = StorewatchEntryLinux::new(hostname.to_string());
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

// Windows implementation
#[cfg(target_os = "windows")]
pub fn get_storage_windows(hostname: &str) -> Vec<StorewatchEntryWindows> {
    let mut disk_info_collection: HashMap<String, Vec<(u64, u64, u64)>> = HashMap::new();
    let mut disk_io_collection: HashMap<String, Vec<(u64, u64)>> = HashMap::new();
    let mut disk_data = Disks::new_with_refreshed_list();
    
    if disk_data.list().is_empty() {
        agent_logger("error", "storewatch", "get_storage_windows",
            r#"{
                "message": "Failed to retrieve disk data"
            }"#
        );
    }

    for i in 0..11 {  // Collect 11 samples to calculate 10 differences
        disk_data.refresh(true);
        let disks = disk_data.list();
        
        for disk in disks {
            let disk_name = disk.name().to_string_lossy().to_string();
            let total_size = disk.total_space();
            let free_size = disk.available_space();
            let used_size = total_size - free_size;
            
            disk_info_collection.entry(disk_name.clone())
                .or_default()
                .push((total_size, free_size, used_size));
            
            // For Windows, get the disk I/O using windows-specific APIs
            // We'll use the sysinfo's disk usage which gives read/write bytes
            let (read_bytes, written_bytes) = get_windows_disk_io(&disk_name);
            disk_io_collection.entry(disk_name.clone())
                .or_default()
                .push((read_bytes, written_bytes));
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
        let mut storage_entry = StorewatchEntryWindows::new(hostname.to_string());
        storage_entry.timestamp = timestamp_epoch;
        storage_entry.disk_name = disk_name.clone();
        
        // Calculate averages
        let info_len = disk_info.len() as u64;
        storage_entry.total_size = disk_info.iter().map(|&(total, _, _)| total).sum::<u64>() / info_len;
        storage_entry.free_size = disk_info.iter().map(|&(_, free, _)| free).sum::<u64>() / info_len;
        storage_entry.used_size = disk_info.iter().map(|&(_, _, used)| used).sum::<u64>() / info_len;
        
        // Get the drive letter or partition info
        if let Some(last_disk) = disk_data.list().iter().find(|d| d.name().to_string_lossy() == *disk_name) {
            storage_entry.partitions.push(last_disk.mount_point().to_string_lossy().to_string());
        }
        
        // Calculate disk I/O bytes read/written if available
        if let Some(io_stats) = disk_io_collection.get(disk_name) {
            if io_stats.len() > 1 {
                let mut total_bytes_read = 0;
                let mut total_bytes_written = 0;
                
                for i in 1..io_stats.len() {
                    let prev = &io_stats[i-1];
                    let curr = &io_stats[i];
                    total_bytes_read += curr.0.saturating_sub(prev.0);
                    total_bytes_written += curr.1.saturating_sub(prev.1);
                }
                
                let samples = (io_stats.len() - 1) as u64;
                storage_entry.bytes_read = total_bytes_read / samples;
                storage_entry.bytes_written = total_bytes_written / samples;
            }
        }
        
        storage_entries.push(storage_entry);
    }
    
    storage_entries
}

#[cfg(target_os = "windows")]
fn get_windows_disk_io(_disk_name: &str) -> (u64, u64) {
    // This is a placeholder. In a real implementation, you would use
    // Windows Performance Counters or other Windows-specific APIs to get disk I/O stats.
    // 
    // For example, you might use the windows crate to access the Windows API:
    // - CreateFile to open a handle to the physical drive
    // - DeviceIoControl with IOCTL_DISK_PERFORMANCE to get performance data
    // 
    // Or use libraries like windows-rs/winapi that expose Performance Counter APIs:
    // - PdhOpenQuery, PdhAddCounter for "PhysicalDisk" counters
    
    // For demonstration purposes, we're returning default values
    // In a real implementation, replace this with actual Windows API calls
    (0, 0)
}