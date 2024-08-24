use serde::{Serialize, Deserialize};
use sysinfo::Disks;

#[derive(Serialize, Deserialize, Debug)]
pub struct StorewatchEntryLinux {
    timestamp: u64,
    hostname: String,
    component: String,
    disk_name: String,
    mounts: Vec<String>,
    total_size: u64,
    free_size: u64,
    used_size: u64,
    disk_usage: f64
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
    let disk_data = Disks::new_with_refreshed_list();
    let disks = disk_data.list();

    let timestamp_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();

    let mut storage_entries = Vec::new();

    for disk in disks {
        let disk_name = disk.name().to_string_lossy().to_string();
        let mount_point = disk.mount_point().to_string_lossy().to_string();

        let total_size = disk.total_space();
        let available_size = disk.available_space();
        let used_size = disk.total_space() - disk.available_space();
        let disk_usage = (used_size as f64 / total_size as f64) * 100.0;

        let mut storage_entry = StorewatchEntryLinux::new_linux(hostname.to_string());
        storage_entry.timestamp = timestamp_epoch;
        storage_entry.disk_name = disk_name.clone();
        storage_entry.total_size = total_size;
        storage_entry.free_size = available_size;
        storage_entry.used_size = used_size;
        storage_entry.disk_usage = disk_usage;
        storage_entry.mounts.push(mount_point);

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
