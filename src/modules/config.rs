use std::{collections::HashMap, env, fs, path::{Path, PathBuf}, process};

use super::logging::agent_logger;

#[derive(Debug)]
#[allow(dead_code)]
pub struct ConfigEntry {
    pub log_type: String,
    pub log_folder: PathBuf,
    pub file_name: String,
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
    pub sourcetype: String,
    pub localapi: String,
    pub password: String,
    pub signalfx_uri: String,
    pub rmtag: String,
}

pub fn get_app_dirs() -> (PathBuf, PathBuf, PathBuf) {
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

    let root_folder_lossy = root_folder.to_string_lossy();
    if root_folder_lossy.contains("splunk") || 
        root_folder_lossy.contains("splunkforwarder") || 
        root_folder_lossy.contains("splunkuniversalforwarder") {
        (bin_folder, app_folder, root_folder)
    } else {
        // Move one directory up for non-splunk paths
        root_folder = root_folder.parent().unwrap().to_path_buf();
        (bin_folder, app_folder, root_folder)
    }

    
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

fn visit_dirs(dir: &Path, module: &str) -> Option<PathBuf> {
    if ["agent", "storewatch", "startup", "hostinfo"].contains(&module) {
        // Search in the provided directory
        let conf_path = dir.join("agent.conf");
        if conf_path.exists() {
            return Some(conf_path);
        }

        // Go one directory up and search in `default` or `local`
        if let Some(parent_dir) = dir.parent() {
            for subdir in ["default", "local"] {
                let path = parent_dir.join(subdir).join("agent.conf");
                if path.exists() {
                    return Some(path);
                }
            }
        }

        // If no file is found, print a message and return None
        agent_logger("debug", "config","visit_dirs", 
        &format!( 
            r#"{{
                "message": "No configuration file found for module '{}' in '{}' or '{}' or '{}'",
                "module": "{}"
            }}"#,
            module, dir.to_string_lossy(), dir.parent().unwrap().to_string_lossy(), dir.parent().unwrap().parent().unwrap().to_string_lossy(), module
        ));
        None
    } else {
        Some(dir.to_path_buf())
    }
}

fn get_config_path(config_path: &Path, module: &str) -> HashMap<String, HashMap<String, String>> {
    let mut config_data = HashMap::new();
    let config_path = visit_dirs(config_path, module);
    let mut last_modified_time = std::time::SystemTime::UNIX_EPOCH;
    if let Some(config_path) = config_path {
        config_data = read_file(&config_path, &mut last_modified_time);
    }
    config_data
}

pub fn get_splunk_hostname(splunk_root: &Path) -> String {
    if splunk_root.to_string_lossy().contains("splunk") || splunk_root.to_string_lossy().contains("splunkforwarder") || splunk_root.to_string_lossy().contains("splunkuniversalforwarder") {
        let inputs_conf = splunk_root.join("etc").join("system").join("local").join("inputs.conf");
        let server_conf = splunk_root.join("etc").join("system").join("local").join("server.conf");

        if inputs_conf.exists() {
            let inputs_conf_data = get_config_path(&inputs_conf, "inputs");
            if let Some(hostname) = inputs_conf_data.get("default").and_then(|section| section.get("host")) {
                return hostname.to_string();
            }
        }

        if server_conf.exists() {
            let server_conf_data = get_config_path(&server_conf, "server");
            if let Some(hostname) = server_conf_data.get("general").and_then(|section| section.get("serverName")) {
                return hostname.to_string();
            }
        }
        agent_logger("debug", "config","get_splunk_hostname", 
        &format!( 
            r#"{{
                "message": "No hostname found in inputs.conf or server.conf",
                "module": "{}"
            }}"#,
            "agent"
        ));
        String::from("no_host")
    } else {
        String::from("no_host")
    }
}

pub fn get_splunk_pid(splunk_root: &Path) -> u32 {
    let pid_file = splunk_root.join("var").join("run").join("splunk").join("splunkd.pid");
    if pid_file.exists() {
        if let Ok(contents) = fs::read_to_string(pid_file.clone()) { // Clone here
            if let Some(line) = contents.lines().next() {
                match line.trim().parse::<u32>() {
                    Ok(pid) => return pid,
                    Err(e) => {
                        agent_logger("warn", "config","get_splunk_pid", 
                            &format!(r#"{{"message": "Failed to parse PID from file: {}", "error": "{}"}}"#, 
                            pid_file.display(), e));
                        return 0;
                    }
                }
            }
        }
    }
    0
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
        "startup" | "agent" | "storewatch" | "hostinfo" | "splunkd_tracker" => {
            let (bin_folder, app_folder, root_folder) = get_app_dirs();
            let config_data = get_config_path(&bin_folder, module);

            let config_type = config_data.get(module)
                .and_then(|s| s.get("type"))
                .unwrap_or(&"file".to_string())
                .to_string();

            let location = config_data.get(module)
                .and_then(|s| s.get("location"))
                .unwrap_or(&"/var/log/".to_string())
                .trim_start_matches('/')
                .to_string();

            let port = config_data.get(module)
                .and_then(|s| s.get("port"))
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);

            let add_wrapper = config_data.get(module)
                .and_then(|s| s.get("add_wrapper"))
                .and_then(|s| parse_bool(s))
                .unwrap_or(false);

            let interval = config_data.get(module)
                .and_then(|s| s.get("interval"))
                .and_then(|s| s.parse().ok())
                .unwrap_or(10);

            let index = config_data.get(module)
                .and_then(|s| s.get("index"))
                .unwrap_or(&"_internal".to_string())
                .to_string();

            let source = config_data.get(module)
                .and_then(|s| s.get("source"))
                .unwrap_or(&format!("{}:json", module).to_string())
                .to_string();

            let sourcetype = config_data.get(module)
                .and_then(|s| s.get("sourcetype"))
                .unwrap_or(&format!("{}_json", module).to_string())
                .to_string();

            let file_name = config_data.get(module)
                .and_then(|s| s.get("file_name"))
                .unwrap_or(&format!("{}_json.log", module).to_string())
                .to_string();

            let password = config_data.get(module)
                .and_then(|s| s.get("password"))
                .unwrap_or(&"".to_string())
                .to_string();

            let signalfx_uri = config_data.get(module)
                .and_then(|s| s.get("signalfx_uri"))
                .unwrap_or(&"".to_string())
                .to_string();

            let localapi = config_data.get(module)
                .and_then(|s| s.get("localapi"))
                .unwrap_or(&"127.0.0.1:8089".to_string())
                .to_string();

            let rmtag = config_data.get(module)
                .and_then(|s| s.get("rmtag"))
                .unwrap_or(&"".to_string())
                .to_string();

            let (log_folder, host, api) = match config_type.as_str() {
                "file" => {
                    let log_location = if root_folder.to_string_lossy().contains("splunk") {
                        format!("{}/{}", root_folder.display(), location)
                    } else {
                        format!("/{}", location)
                    };
                    let log_folder = PathBuf::from(&log_location);
                    if !log_folder.exists() {
                        fs::create_dir_all(&log_folder).expect("Failed to create log directory");
                    }
                    (log_folder, String::new(), String::new())
                },
                "http" => {
                    agent_logger("error", "config","get_configmap", &format!(r#"{{"message": "{} type is not supported yet", "module": "{}"}}"#, config_type, module));
                    process::exit(1);
                },
                "tcp" => (PathBuf::new(), location, String::new()),
                "udp" => (PathBuf::new(), location, String::new()),
                "splunkapi" => (PathBuf::new(), String::new(), location),
                _ => (PathBuf::new(), String::new(), String::new()),
            };

            ConfigEntry {
                log_type: config_type,
                log_folder,
                file_name,
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
                sourcetype,
                localapi,
                password,
                signalfx_uri,
                rmtag,
            }
        },
        _ => {
            agent_logger("error", "config","get_configmap", &format!(r#"{{"message": "Invalid module '{}'. Valid modules are: startup, agent, storewatch, hostinfo"}}"#, module));
            process::exit(1);
        }
    }
}