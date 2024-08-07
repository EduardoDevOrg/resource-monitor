use std::{collections::HashMap, env, fs, path::{Path, PathBuf}, process};

#[derive(Debug)]
#[allow(dead_code)]
pub struct ConfigEntry {
    pub log_type: String,
    pub log_folder: PathBuf,
    pub interval: u64,
    pub bin_folder: PathBuf,
    pub app_folder: PathBuf,
    pub root_folder: PathBuf,
    pub host: String,
    pub port: u16,
    pub api: String,
    pub add_wrapper: bool,
    pub index: String,
    pub source: String,
    pub sourcetype: String
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

fn read_file(path: &Path, last_modified_time: &mut std::time::SystemTime) -> HashMap<String, HashMap<String, String>>{
    let mut config_data = HashMap::new();
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
    config_data
}

fn visit_dirs(dir: &Path) -> Option<PathBuf> {
    // Search in the provided directory
    let agent_conf_path = dir.join("agent.conf");
    if agent_conf_path.exists() {
        return Some(agent_conf_path);
    }

    // Go one directory up and search in `default` or `local`
    if let Some(parent_dir) = dir.parent() {
        let default_dir = parent_dir.join("default").join("agent.conf");
        if default_dir.exists() {
            return Some(default_dir);
        }

        let local_dir = parent_dir.join("local").join("agent.conf");
        if local_dir.exists() {
            return Some(local_dir);
        }
    }

    // If no file is found, print a message and return None
    println!("No agent.conf found");
    None
}

fn read_config_file(config_path: &Path) -> HashMap<String, HashMap<String, String>> {
    let mut config_data = HashMap::new();
    let config_path = visit_dirs(config_path);
    let mut last_modified_time = std::time::SystemTime::UNIX_EPOCH;
    if let Some(config_path) = config_path {
        config_data = read_file(&config_path, &mut last_modified_time);
    }
    config_data
}

fn parse_bool(value: &str) -> Option<bool> {
    match value.to_lowercase().as_str() {
        "t" | "true" | "1" => Some(true),
        "f" | "false" | "0" => Some(false),
        _ => None,
    }
}

pub fn get_configmap(module: &str) -> ConfigEntry {
    match module {
        "startup" | "agent" | "diskstats" | "storewatch" => {
            let (bin_folder, app_folder, root_folder) = get_app_dirs();

            let config_data = read_config_file(&bin_folder);
            
            let default_type = String::from("file");
            let config_type = config_data
                .get("default")
                .and_then(|section| section.get("type"))
                .unwrap_or(&default_type)
                .to_string();
            
            let default_location = String::from("/var/log/");
            let location = config_data
                .get("default")
                .and_then(|section| section.get("location"))
                .unwrap_or(&default_location)
                .trim_start_matches('/')
                .to_string();

            let default_port = 0;
            let port: u16 = config_data
                .get("default")
                .and_then(|section| section.get("port"))
                .and_then(|s| s.parse().ok())
                .unwrap_or(default_port);

            let default_add_wrapper = false;
            let add_wrapper: bool = config_data
                .get("default")
                .and_then(|section| section.get("add_wrapper"))
                .and_then(|s| parse_bool(s))
                .unwrap_or(default_add_wrapper);

            let default_interval = 10;
            let interval: u64 = config_data
                .get(module)
                .and_then(|section| section.get("interval"))
                .and_then(|s| s.parse().ok())
                .unwrap_or(default_interval);

            let default_index = String::from("_internal");
            let index: String = config_data
                .get(module)
                .and_then(|section| section.get("index"))
                .unwrap_or(&default_index)
                .to_string();

            let default_source = String::from("Resmonitor:JSON");
            let source: String = config_data
                .get(module)
                .and_then(|section| section.get("source"))
                .unwrap_or(&default_source)
                .to_string();

            let default_sourcetype = String::from("resmonitor_json");
            let sourcetype: String = config_data
                .get(module)
                .and_then(|section| section.get("sourcetype"))
                .unwrap_or(&default_sourcetype)
                .to_string();



            let log_location: String;
            let mut log_folder = PathBuf::new(); // Initialize with a default value
            let mut host = String::new();
            let mut api = String::new();

            if config_type == "file" {
                if root_folder.to_string_lossy().contains("splunk") || root_folder.to_string_lossy().contains("splunkforwarder") || root_folder.to_string_lossy().contains("splunkuniversalforwarder") {
                    log_location = format!("{}/{}", root_folder.display(), location);
                    log_folder = PathBuf::from(&log_location);
                } else {
                    log_location = format!("/{}", location);
                    log_folder = PathBuf::from(&log_location);
                }
            
                if !Path::new(&log_folder).exists() {
                    fs::create_dir_all(&log_folder).expect("Failed to create log directory");
                }

            } else if config_type == "tcp" {
                println!("TCP type is not supported yet");
                process::exit(1);
            } else if config_type == "udp" {
                host = location;
            } else if config_type == "splunkapi" {
                api = location;
            } else if config_type == "http" {
                println!("HTTP type is not supported yet");
                process::exit(1);
            }



            ConfigEntry {
                log_type: config_type,
                log_folder,
                interval,
                bin_folder,
                app_folder,
                root_folder,
                host,
                port,
                api,
                add_wrapper,
                index,
                source,
                sourcetype
            }
        },
        _ => {
            eprintln!("Error: Invalid module '{}'. Valid modules are: startup, agent, diskstats, storewatch", module);
            process::exit(1);
        }
    }
}