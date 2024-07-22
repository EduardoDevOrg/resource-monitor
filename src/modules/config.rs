use std::{collections::HashMap, env, fs, path::{Path, PathBuf}, process};

#[derive(Debug)]
pub struct ConfigEntry {
    pub log_type: String,
    pub location: String,
    pub interval: u64,
    pub bin_folder: PathBuf,
    pub app_folder: PathBuf,
    pub root_folder: PathBuf,
}
fn get_app_dirs() -> (PathBuf, PathBuf, PathBuf) {
    let current_exe = env::current_exe().unwrap();
    let mut bin_folder = current_exe.clone();
    let mut app_folder = current_exe.clone();
    bin_folder.pop();

    app_folder.pop();
    app_folder.pop();

    let mut root_folder = PathBuf::new();
    for component in current_exe.components() {
        if component.as_os_str() == "etc" {
            break;
        }
        root_folder.push(component);
    }

    (bin_folder, app_folder, root_folder)
}

fn read_config_file(config_path: &Path) -> HashMap<String, HashMap<String, String>> {
    let mut config_data = HashMap::new();
    let mut last_modified_time = std::time::SystemTime::UNIX_EPOCH;

    fn read_file(path: &Path, config_data: &mut HashMap<String, HashMap<String, String>>, last_modified_time: &mut std::time::SystemTime) {
        if path.is_file() {
            if let Ok(metadata) = fs::metadata(path) {
                if let Ok(modified_time) = metadata.modified() {
                    if modified_time > *last_modified_time {
                        if let Ok(contents) = fs::read_to_string(path) {
                            let mut section = String::new();
                            let mut section_map = HashMap::new();

                            for line in contents.lines() {
                                let line = line.trim();
                                if line.is_empty() || line.starts_with('#') {
                                    continue;
                                }
                                if line.starts_with('[') && line.ends_with(']') {
                                    if !section.is_empty() {
                                        config_data.insert(section.clone(), section_map.clone());
                                        section_map.clear();
                                    }
                                    section = line[1..line.len() - 1].to_string();
                                } else if let Some((key, value)) = line.split_once('=') {
                                    section_map.insert(key.trim().to_string(), value.trim().to_string());
                                }
                            }

                            if !section.is_empty() {
                                config_data.insert(section, section_map);
                            }
                            *last_modified_time = modified_time;
                        }
                    }
                }
            }
        }
    }

    fn visit_dirs(dir: &Path, config_data: &mut HashMap<String, HashMap<String, String>>, last_modified_time: &mut std::time::SystemTime) {
        if dir.is_dir() {
            if let Ok(entries) = fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        visit_dirs(&path, config_data, last_modified_time);
                    } else if path.file_name().unwrap_or_default() == "splunkagent.conf" {
                        read_file(&path, config_data, last_modified_time);
                    }
                }
            }
        }
    }

    visit_dirs(config_path, &mut config_data, &mut last_modified_time);
    config_data
}

pub fn get_configmap() -> ConfigEntry {
    let (bin_folder, app_folder, root_folder) = get_app_dirs();
    let config_data = read_config_file(&app_folder);
    
    let default_type = String::from("file");
    let config_type = config_data
        .get("default")
        .and_then(|section| section.get("type"))
        .unwrap_or(&default_type)
        .to_string();
    
    let default_location = String::from("/var/log/splunk");
    let location = config_data
        .get("default")
        .and_then(|section| section.get("location"))
        .unwrap_or(&default_location)
        .trim_start_matches('/')
        .to_string();
    

    let default_interval = 10;
    let interval: u64 = config_data
        .get("default")
        .and_then(|section| section.get("interval"))
        .and_then(|s| s.parse().ok())
        .unwrap_or(default_interval);

    if config_type == "file" {
        let log_location = format!("{}/{}", root_folder.display(), location);
        let log_folder = PathBuf::from(&log_location);

        if !Path::new(&log_folder).exists() {
            fs::create_dir_all(&log_folder).expect("Failed to create log directory");
        }

    } else if config_type == "tcp" {
        println!("TCP type is not supported yet");
        process::exit(1);
    } else if config_type == "http" {
        println!("HTTP type is not supported yet");
        process::exit(1);
    }

    let config_entry = ConfigEntry {
        log_type: config_type,
        location,
        interval,
        bin_folder,
        app_folder,
        root_folder,
    };
    config_entry
}