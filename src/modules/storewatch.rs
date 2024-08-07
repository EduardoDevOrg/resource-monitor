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

// pub fn get_storage_info(hostname: &str, storewatch_entry: &mut StorewatchEntry) -> Vec<serde_json::Value> {
//     let disk_data = Disks::new_with_refreshed_list();
//     let disks = disk_data.list();

//     let timestamp = SystemTime::now()
//         .duration_since(UNIX_EPOCH)
//         .unwrap()
//         .as_secs();

//     storewatch_entry.timestamp = timestamp;
//     storewatch_entry.hostname = hostname.to_string();
//     let mut disk_info = std::collections::HashMap::new();
//     let mut disk_objects = Vec::new();


//         for disk in disks {
//             let disk_name = disk.name().to_string_lossy().to_string();
//             let mount_point = disk.mount_point().to_string_lossy().to_string();
        
//             let entry = disk_info.entry(disk_name.clone()).or_insert_with(|| {
//                 let total_size = disk.total_space();
//                 let available_size = disk.available_space();
//                 let used_size = disk.total_space() - disk.available_space();
//                 let disk_usage = (used_size as f64 / total_size as f64) * 100.0;
        
//                 let mut disk_details = std::collections::HashMap::new();
//                 disk_details.insert("disk_name", serde_json::json!(disk_name));
//                 disk_details.insert("total_size", serde_json::Value::Number(total_size.into()));
//                 disk_details.insert("free_size", serde_json::Value::Number(available_size.into()));
//                 disk_details.insert("used_size", serde_json::Value::Number(used_size.into()));
//                 disk_details.insert("disk_usage", serde_json::Value::Number(serde_json::Number::from_f64(disk_usage).unwrap()));
//                 disk_details.insert("mounts", serde_json::json!(Vec::<String>::new()));
//                 disk_details
//             });
        
//             let mounts = entry.get_mut("mounts").unwrap().as_array_mut().unwrap();
//             mounts.push(serde_json::json!(mount_point));
//         }

//         for (_, details) in disk_info.iter() {
//             let mut disk_json = serde_json::Map::new();

//             for (key, value) in details {
//                 disk_json.insert(key.to_string(), serde_json::json!(value));
//             }
//             disk_objects.push(serde_json::Value::Object(disk_json));
//         }
    
//         disk_objects
        

//     } else {
//         for disk in disks {
//             let total_size = disk.total_space();
//             let used_size = disk.total_space() - disk.available_space();
//             let usage = (used_size as f64 / total_size as f64) * 100.0;
    
//             let mut disk_map = HashMap::new();

//             disk_map.insert(
//                 "partition_name".to_string(),
//                 disk.name().to_string_lossy().to_string(),
//             );
//             disk_map.insert(
//                 "disk_name".to_string(),
//                 disk.mount_point().to_string_lossy().to_string(),
//             );
//             disk_map.insert("total_size".to_string(), total_size.to_string());
//             disk_map.insert("used_size".to_string(), used_size.to_string());
//             disk_map.insert("usage".to_string(), format!("{:.2}", usage));
    
//             disk_info.push(disk_map);
//         }
    
//         disk_info

//     }

// }