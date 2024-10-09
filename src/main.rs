use std::{fs::{self, OpenOptions}, io::BufWriter, net::{TcpStream, ToSocketAddrs, UdpSocket}, path::Path, process};
use std::io::Write;
use gethostname::gethostname;
use modules::config::get_splunk_hostname;
mod modules {
    pub mod startup;
    pub mod config;
    pub mod log_entry;
    pub mod storewatch;
    pub mod logging;
    pub mod hostinfo;
    pub mod decryptor;
    pub mod signalfx;
    pub mod diskstats;
}
use std::env::consts::OS;
use sysinfo::{Networks, Pid, System};
use reqwest::blocking::ClientBuilder;

fn check_running_process(exe: &Path, current_pid: &u32) {
    let pid_file_path = exe.join(".agent.pid");
    let executable = std::env::current_exe().unwrap();
    let pid_file = pid_file_path.to_str().unwrap();
    modules::logging::agent_logger("debug", "check_process", 
    &format!(
        r#"{{
            "message": "Checking for running process",
            "exe": "{}",
            "current_pid": {}
        }}"#,
        executable.display(), current_pid
    ));

    let mut system = System::new_all();
    system.refresh_all();

    if !Path::new(pid_file).exists() {
        // Create the PID file and write the appropriate PID
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(pid_file)
            .expect("Failed to create or open PID file");

        let mut matching_processes = Vec::new();
        for (pid, process) in system.processes() {
            if process.pid() != Pid::from_u32(*current_pid)
                && process.parent().map_or(true, |parent| parent != Pid::from_u32(*current_pid))
                && process.exe().map_or(false, |exe| exe == executable)
                && process.cmd().get(1).map_or(false, |arg| arg == "agent")
            {
                matching_processes.push((pid.as_u32(), process.start_time()));
            }
            
        }

        // Find the oldest process
        if let Some((oldest_pid, _)) = matching_processes.into_iter()
            .min_by_key(|&(pid, start_time)| (start_time, pid)) 
        {
            modules::logging::agent_logger("info", "check_process", 
            &format!(
                r#"{{
                    "message": "Found running process with PID",
                    "pid": {}
                }}"#,
                oldest_pid
            ));
            writeln!(file, "{}", oldest_pid).expect("Failed to write to PID file");
            process::exit(0);
        } else {
            writeln!(file, "{}", *current_pid).expect("Failed to write to PID file");
        }

    } else {
        let content = fs::read_to_string(pid_file).expect("Failed to read PID file");
        let old_pid = match content.trim().parse::<u32>() {
            Ok(pid) => pid,
            Err(_) => {
                fs::remove_file(pid_file).expect("Failed to delete invalid PID file");
                process::exit(1);
            }
        };

        if system.process(Pid::from_u32(old_pid)).is_some() {
            modules::logging::agent_logger("info", "check_process", 
            &format!(
                r#"{{
                    "message": "Process with PID {} is running",
                    "pid": {}
                }}"#,
                old_pid, old_pid
            ));
            process::exit(0);
        } else {
            modules::logging::agent_logger("info", "check_process", 
            &format!(
                r#"{{
                    "message": "Process with PID {} is not running",
                    "pid": {}
                }}"#,
                old_pid, old_pid
            ));
            let mut file = OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(pid_file)
                .expect("Failed to open PID file");
            let current_pid = process::id();
            writeln!(file, "{}", current_pid).expect("Failed to write to PID file");
            modules::logging::agent_logger("info", "check_process", 
            &format!(
                r#"{{
                    "message": "PID {} is written to file.",
                    "pid": {}
                }}"#,
                current_pid, current_pid
            ));
        }
    }
}   



fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut input = String::new();
    
    if args.len() < 2 {
        modules::logging::agent_logger("error", "main", 
        r#"{
                "message": "No arguments provided"
            }"#);
        println!("No arguments provided!\n
        Possible arguments are: agent, startup, storewatch, hostinfo");
        process::exit(1);
    }

    let configmap = modules::config::get_configmap(&args[1]);
    
    let mut hostname = get_splunk_hostname(&configmap.root_folder);
    if hostname == "no_host" {
        hostname = gethostname().to_string_lossy().to_string();
    }
    
    let running_module = &args[1];

    let current_pid = process::id();
    let mut splunk_pid = modules::config::get_splunk_pid(&configmap.root_folder);
    if splunk_pid == 0 {
        splunk_pid = current_pid;
    }

    let signalfx_client = if !configmap.signalfx_uri.is_empty() {
        Some(modules::signalfx::get_signalfx_client().unwrap())
    } else {
        None
    };

    let signalfx_token = if !configmap.signalfx_uri.is_empty() {
        modules::decryptor::decrypt_password(&configmap.password)
    } else {
        None
    };

    if running_module == "agent" {
        check_running_process(&configmap.bin_folder, &current_pid);
    }

    if configmap.log_type == "file" 
    {
        if running_module == "agent" {
            let mut sys = System::new_all();
            let mut networks = Networks::new_with_refreshed_list();
            let interval = configmap.interval;
            let agent_path = configmap.log_folder;
            let agent_file = agent_path.join(configmap.file_name);

            let agent_starttime = sys.process(Pid::from_u32(splunk_pid)).unwrap().start_time();
            
            let mut log_writer = BufWriter::new(OpenOptions::new()
                .create(true)
                .append(true)
                .open(agent_file.clone())
                .expect("Failed to open log file"));
            let mut log_entry = modules::log_entry::LogEntry::new(hostname.clone(), running_module.clone(), agent_starttime);
            log_entry.calculate_baseline(&networks);

            loop {
                log_entry.timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("Time went backwards")
                    .as_secs();
                log_entry.uptime = System::uptime();
        
                for _ in 0..interval {
                    sys.refresh_all();
                    networks.refresh();
                    log_entry.update(&sys, &networks);
                    std::thread::sleep(std::time::Duration::from_secs(1));
                }
                
                log_entry.finalize(interval);

                if !configmap.signalfx_uri.is_empty() {
                    let signalfx_client = signalfx_client.clone();
                    let signalfx_uri = configmap.signalfx_uri.clone();
                    let signalfx_token = signalfx_token.clone();
                    let gauge_json = modules::signalfx::generate_agent_gauge(&log_entry, &configmap.rmtag);

                    std::thread::spawn(move || {
                        let _ = modules::signalfx::send_gauge(&signalfx_client.unwrap(), &signalfx_uri, &gauge_json, signalfx_token.as_ref().unwrap(),3);
                    });
                }
        
                log_entry.write_json(&mut log_writer).expect("Failed to write to log file");
    
                log_writer.write_all(b"\n").expect("Failed to write newline");
                log_writer.flush().expect("Failed to flush log file");
                log_entry.reset();
        
                modules::startup::check_stopswitch(&configmap.bin_folder);
                modules::log_entry::check_log_file_size(agent_file.as_ref());
            }
        } else if running_module == "startup" {
            let startup_string = modules::startup::startup_log(&hostname, &configmap.app_folder);
            
            let startup_path = configmap.log_folder;
            let startup_file = startup_path.join(configmap.file_name);

            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(startup_file)
                .expect("Failed to open PID file");

            writeln!(file, "{}", startup_string.unwrap().as_json()).expect("Failed to write to PID file");
            file.flush().expect("Failed to flush log file");
            process::exit(0);
        } else if running_module == "storewatch" {
            let storewatch_path = configmap.log_folder;
            let storewatch_file = storewatch_path.join(configmap.file_name);

            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(storewatch_file)
                .expect("Failed to open storewatch log file");

            if OS != "windows" {
                let storewatch_entry = modules::storewatch::get_storage_linux(&hostname);
                
                for entry in &storewatch_entry {
                    let json_string = serde_json::to_string(&entry).expect("Failed to serialize storewatch entry");
                    
                    writeln!(file, "{}", json_string).expect("Failed to write to log file");
                }

                if !configmap.signalfx_uri.is_empty() {
                    let signalfx_client = signalfx_client.clone();
                    let signalfx_uri = configmap.signalfx_uri.clone();
                    let signalfx_token = signalfx_token.clone();
                    let gauge_json = modules::signalfx::generate_storage_gauge(&storewatch_entry, &configmap.rmtag);

                    let _ = modules::signalfx::send_gauge(&signalfx_client.unwrap(), &signalfx_uri, &gauge_json, signalfx_token.as_ref().unwrap(),1);
                }
            } else {
                let storewatch_entry = modules::storewatch::get_storage_windows(&hostname);

                for entry in storewatch_entry {
                    let json_string = serde_json::to_string(&entry).expect("Failed to serialize storewatch entry");
                    writeln!(file, "{}", json_string).expect("Failed to write to log file");
                } 
            }
            file.flush().expect("Failed to flush log file");
        } else if running_module == "hostinfo" {
            std::io::stdin().read_line(&mut input).unwrap();
            let splunk_info = modules::hostinfo::get_splunkinfo(configmap.localapi.clone(), input);

            let hostinfo_path = configmap.log_folder;
            let hostinfo_file = hostinfo_path.join(configmap.file_name);

            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(hostinfo_file)
                .expect("Failed to open hostinfo log file");

            writeln!(file, "{}", splunk_info.unwrap().as_json()).expect("Failed to write to log file");
            file.flush().expect("Failed to flush log file");
            process::exit(0);
            
        }
        
    } else if configmap.log_type == "udp" 
    {
        let udp_host = configmap.host.clone();
        let udp_port = configmap.port;
        let socket = UdpSocket::bind("0.0.0.0:0").expect("Couldn't bind to address");
        let add_wrapper = configmap.add_wrapper;

        if running_module == "agent" {
            let mut sys = System::new_all();
            let mut networks = Networks::new_with_refreshed_list();
            let interval = configmap.interval;

            let agent_starttime = sys.process(Pid::from_u32(splunk_pid)).unwrap().start_time();

            let mut log_entry = modules::log_entry::LogEntry::new(hostname.clone(), running_module.clone(), agent_starttime);
            log_entry.calculate_baseline(&networks);
            
            loop {
                log_entry.timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs();
            log_entry.uptime = System::uptime();
    
            for _ in 0..interval {
                sys.refresh_all();
                networks.refresh();
                log_entry.update(&sys, &networks);
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
    
            log_entry.finalize(interval);

            if !configmap.signalfx_uri.is_empty() {
                let signalfx_client = signalfx_client.clone();
                let signalfx_uri = configmap.signalfx_uri.clone();
                let signalfx_token = signalfx_token.clone();
                let gauge_json = modules::signalfx::generate_agent_gauge(&log_entry, &configmap.rmtag);

                std::thread::spawn(move || {
                    let _ = modules::signalfx::send_gauge(&signalfx_client.unwrap(), &signalfx_uri, &gauge_json, signalfx_token.as_ref().unwrap(),3);
                });
            }

            let json_string = if add_wrapper {
                log_entry.add_wrapper(&configmap.index, &configmap.source, &configmap.sourcetype, hostname.clone())
            } else {
                let mut json_buffer = Vec::new();
                log_entry.write_json(&mut json_buffer).expect("Failed to serialize log entry");
                String::from_utf8(json_buffer).expect("Failed to convert JSON buffer to string")
            };

            // Resolve the hostname to an IP address before each send
            let udp_address = format!("{}:{}", udp_host, udp_port);
            let resolved_address = udp_address.to_socket_addrs()
                .expect("Failed to resolve hostname")
                .next()
                .expect("No addresses found for hostname");

            socket.send_to(json_string.as_bytes(), resolved_address).expect("Failed to send UDP message");
            log_entry.reset();
            modules::startup::check_stopswitch(&configmap.bin_folder);
            }

        } else if running_module == "startup" {
            let startup_string = modules::startup::startup_log(&hostname, &configmap.app_folder);

            let startup_data = if add_wrapper {
                startup_string.unwrap().add_wrapper(&configmap.index, &configmap.source, &configmap.sourcetype, hostname.clone())
            } else {
                startup_string.unwrap().as_json()
            };

            let udp_address = format!("{}:{}", udp_host, udp_port);
            let resolved_address = udp_address.to_socket_addrs()
                .expect("Failed to resolve hostname")
                .next()
                .expect("No addresses found for hostname");

            socket.send_to(startup_data.as_bytes(), resolved_address)
                .expect("Failed to send UDP message");

            process::exit(0);
        } else if running_module == "storewatch" {
            let udp_address = format!("{}:{}", udp_host, udp_port);
                let resolved_address = udp_address.to_socket_addrs()
                    .expect("Failed to resolve hostname")
                    .next()
                    .expect("No addresses found for hostname");

            if OS != "windows" {
                let storewatch_entry = modules::storewatch::get_storage_linux(&hostname);
                
                if add_wrapper {
                    for entry in &storewatch_entry {
                        let json_string = entry.add_wrapper(&configmap.index, &configmap.source, &configmap.sourcetype, hostname.clone());
                        socket.send_to(json_string.as_bytes(), resolved_address)
                            .expect("Failed to send UDP message");
                    }

                    if !configmap.signalfx_uri.is_empty() {
                        let signalfx_client = signalfx_client.clone();
                        let signalfx_uri = configmap.signalfx_uri.clone();
                        let signalfx_token = signalfx_token.clone();
                        let gauge_json = modules::signalfx::generate_storage_gauge(&storewatch_entry, &configmap.rmtag);
    
                        let _ = modules::signalfx::send_gauge(&signalfx_client.unwrap(), &signalfx_uri, &gauge_json, signalfx_token.as_ref().unwrap(),1);
                    }
                } else {
                    for entry in &storewatch_entry {

                        let json_string = serde_json::to_string(&entry).expect("Failed to serialize storewatch entry");
                        
                        socket.send_to(json_string.as_bytes(), resolved_address)
                            .expect("Failed to send UDP message");
                    }

                    if !configmap.signalfx_uri.is_empty() {
                        let signalfx_client = signalfx_client.clone();
                        let signalfx_uri = configmap.signalfx_uri.clone();
                        let signalfx_token = signalfx_token.clone();
                        let gauge_json = modules::signalfx::generate_storage_gauge(&storewatch_entry, &configmap.rmtag);
    
                        let _ = modules::signalfx::send_gauge(&signalfx_client.unwrap(), &signalfx_uri, &gauge_json, signalfx_token.as_ref().unwrap(),1);
                    }
                };

            } else {
                let storewatch_entry = modules::storewatch::get_storage_windows(&hostname);

                if add_wrapper {
                    for entry in storewatch_entry {
                        let json_string = entry.add_wrapper(&configmap.index, &configmap.source, &configmap.sourcetype, hostname.clone());
                        socket.send_to(json_string.as_bytes(), resolved_address)
                            .expect("Failed to send UDP message");
                    }
                } else {
                    for entry in storewatch_entry {
                        let json_string = serde_json::to_string(&entry).expect("Failed to serialize storewatch entry");
                        socket.send_to(json_string.as_bytes(), resolved_address)
                            .expect("Failed to send UDP message");
                    }
                };   
            }
        } else if running_module == "hostinfo" {
            std::io::stdin().read_line(&mut input).unwrap();
            let splunk_info = if add_wrapper {
                modules::hostinfo::get_splunkinfo(configmap.localapi.clone(), input).unwrap().add_wrapper(&configmap.index, &configmap.source, &configmap.sourcetype, hostname.clone())
            } else {
                modules::hostinfo::get_splunkinfo(configmap.localapi.clone(), input).unwrap().as_json()
            };

            let udp_address = format!("{}:{}", udp_host, udp_port);
            let resolved_address = udp_address.to_socket_addrs()
                .expect("Failed to resolve hostname")
                .next()
                .expect("No addresses found for hostname");
            
            
            socket.send_to(splunk_info.as_bytes(), resolved_address)
                .expect("Failed to send UDP message");

            process::exit(0);
            
        }

    } else if configmap.log_type == "tcp" 
    {
            let tcp_host = configmap.host.clone();
            let tcp_port = configmap.port;
            let add_wrapper = configmap.add_wrapper;
    
            if running_module == "agent" {
                let mut sys = System::new_all();
                let mut networks = Networks::new_with_refreshed_list();
                let interval = configmap.interval;
    
                let agent_starttime = sys.process(Pid::from_u32(splunk_pid)).unwrap().start_time();
    
                let mut log_entry = modules::log_entry::LogEntry::new(hostname.clone(), running_module.clone(), agent_starttime);
                log_entry.calculate_baseline(&networks);
                
                loop {
                    log_entry.timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("Time went backwards")
                    .as_secs();
                    log_entry.uptime = System::uptime();
        
                    for _ in 0..interval {
                        sys.refresh_all();
                        networks.refresh();
                        log_entry.update(&sys, &networks);
                        std::thread::sleep(std::time::Duration::from_secs(1));
                    }
        
                    log_entry.finalize(interval);

                    if !configmap.signalfx_uri.is_empty() {
                        let signalfx_client = signalfx_client.clone();
                        let signalfx_uri = configmap.signalfx_uri.clone();
                        let signalfx_token = signalfx_token.clone();
                        let gauge_json = modules::signalfx::generate_agent_gauge(&log_entry, &configmap.rmtag);
    
                        std::thread::spawn(move || {
                            let _ = modules::signalfx::send_gauge(&signalfx_client.unwrap(), &signalfx_uri, &gauge_json, signalfx_token.as_ref().unwrap(),3);
                        });
                    }
    
                    let json_string = if add_wrapper {
                        log_entry.add_wrapper(&configmap.index, &configmap.source, &configmap.sourcetype, hostname.clone())
                    } else {
                        let mut json_buffer = Vec::new();
                        log_entry.write_json(&mut json_buffer).expect("Failed to serialize log entry");
                        String::from_utf8(json_buffer).expect("Failed to convert JSON buffer to string")
                    };
    
                    // Connect to the TCP server
                    let tcp_address = format!("{}:{}", tcp_host, tcp_port);
                    let mut stream = TcpStream::connect(tcp_address).expect("Failed to connect to TCP server");
    
                    stream.write_all(json_string.as_bytes()).expect("Failed to send TCP message");
                    log_entry.reset();
                    modules::startup::check_stopswitch(&configmap.bin_folder);
                }
    
            } else if running_module == "startup" {
                let startup_string = modules::startup::startup_log(&hostname, &configmap.app_folder);
    
                let startup_data = if add_wrapper {
                    startup_string.unwrap().add_wrapper(&configmap.index, &configmap.source, &configmap.sourcetype, hostname.clone())
                } else {
                    startup_string.unwrap().as_json()
                };
    
                let tcp_address = format!("{}:{}", tcp_host, tcp_port);
                let mut stream = TcpStream::connect(tcp_address).expect("Failed to connect to TCP server");
    
                stream.write_all(startup_data.as_bytes()).expect("Failed to send TCP message");
    
                process::exit(0);
            } else if running_module == "storewatch" {
                let tcp_address = format!("{}:{}", tcp_host, tcp_port);
                let mut stream = TcpStream::connect(tcp_address).expect("Failed to connect to TCP server");
    
                if OS != "windows" {
                    let storewatch_entry = modules::storewatch::get_storage_linux(&hostname);
                    
                    if add_wrapper {
                        for entry in &storewatch_entry {
                            
                            let json_string = entry.add_wrapper(&configmap.index, &configmap.source, &configmap.sourcetype, hostname.clone());
                            stream.write_all(json_string.as_bytes()).expect("Failed to send TCP message");
                        }

                        if !configmap.signalfx_uri.is_empty() {
                            let signalfx_client = signalfx_client.clone();
                            let signalfx_uri = configmap.signalfx_uri.clone();
                            let signalfx_token = signalfx_token.clone();
                            let gauge_json = modules::signalfx::generate_storage_gauge(&storewatch_entry, &configmap.rmtag);
        
                            let _ = modules::signalfx::send_gauge(&signalfx_client.unwrap(), &signalfx_uri, &gauge_json, signalfx_token.as_ref().unwrap(),1);
                        }
                    } else {
                        for entry in &storewatch_entry {

                            let json_string = serde_json::to_string(&entry).expect("Failed to serialize storewatch entry");
                            stream.write_all(json_string.as_bytes()).expect("Failed to send TCP message");
                        }

                        if !configmap.signalfx_uri.is_empty() {
                            let signalfx_client = signalfx_client.clone();
                            let signalfx_uri = configmap.signalfx_uri.clone();
                            let signalfx_token = signalfx_token.clone();
                            let gauge_json = modules::signalfx::generate_storage_gauge(&storewatch_entry, &configmap.rmtag);
        
                            let _ = modules::signalfx::send_gauge(&signalfx_client.unwrap(), &signalfx_uri, &gauge_json, signalfx_token.as_ref().unwrap(),1);
                        }
                    };
    
                } else {
                    let storewatch_entry = modules::storewatch::get_storage_windows(&hostname);
    
                    if add_wrapper {
                        
                        for entry in storewatch_entry {
                            let json_string = entry.add_wrapper(&configmap.index, &configmap.source, &configmap.sourcetype, hostname.clone());
                            stream.write_all(json_string.as_bytes()).expect("Failed to send TCP message");
                        }
                    } else {
                        
                        for entry in storewatch_entry {
                            let json_string = serde_json::to_string(&entry).expect("Failed to serialize storewatch entry");
                            stream.write_all(json_string.as_bytes()).expect("Failed to send TCP message");
                        }
                    };   
                }
        } else if running_module == "hostinfo" {
            std::io::stdin().read_line(&mut input).unwrap();
            let splunk_info = if add_wrapper {
                modules::hostinfo::get_splunkinfo(configmap.localapi.clone(), input).unwrap().add_wrapper(&configmap.index, &configmap.source, &configmap.sourcetype, hostname.clone())
            } else {
                modules::hostinfo::get_splunkinfo(configmap.localapi.clone(), input).unwrap().as_json()
            };

            let tcp_address = format!("{}:{}", tcp_host, tcp_port);
            let mut stream = TcpStream::connect(tcp_address).expect("Failed to connect to TCP server");
            
            stream.write_all(splunk_info.as_bytes()).expect("Failed to send TCP message");
            process::exit(0);
            
        }

    } else if configmap.log_type == "splunkapi" 
    {
        let client = ClientBuilder::new()
            .danger_accept_invalid_certs(true)
            .build()
            .expect("Failed to build client");
        let api_url = &configmap.api;

        if running_module == "agent" {
            let mut sys = System::new_all();
            let mut networks = Networks::new_with_refreshed_list();
            let interval = configmap.interval;

            let params = [
            ("source", configmap.source.as_str()),
            ("sourcetype", configmap.sourcetype.as_str()),
            ("index", configmap.index.as_str()),
            ("host", hostname.as_str()),
            ];

            let agent_starttime = sys.process(Pid::from_u32(splunk_pid)).unwrap().start_time();

            let mut log_entry = modules::log_entry::LogEntry::new(hostname.clone(), running_module.clone(), agent_starttime);
            log_entry.calculate_baseline(&networks);

            loop {
                log_entry.timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs();
                log_entry.uptime = System::uptime();
    
                for _ in 0..interval {
                    sys.refresh_all();
                    networks.refresh();
                    log_entry.update(&sys, &networks);
                    std::thread::sleep(std::time::Duration::from_secs(1));
                }
    
                log_entry.finalize(interval);

                if !configmap.signalfx_uri.is_empty() {
                    let signalfx_client = signalfx_client.clone();
                    let signalfx_uri = configmap.signalfx_uri.clone();
                    let signalfx_token = signalfx_token.clone();
                    let gauge_json = modules::signalfx::generate_agent_gauge(&log_entry, &configmap.rmtag);

                    std::thread::spawn(move || {
                        let _ = modules::signalfx::send_gauge(&signalfx_client.unwrap(), &signalfx_uri, &gauge_json, signalfx_token.as_ref().unwrap(),3);
                    });
                }
                
                let mut json_buffer = Vec::new();
                log_entry.write_json(&mut json_buffer).expect("Failed to serialize log entry");
                let payload = String::from_utf8(json_buffer).expect("Failed to convert JSON buffer to string");
                
                match client.post(api_url)
                .query(&params)
                .body(payload)
                .timeout(std::time::Duration::from_secs(5))
                .send() {
                    Ok(_) => {
                    }
                Err(err) => {
                    modules::logging::agent_logger("error", "agent", 
                    &format!(
                        r#"{{
                            "message": "Error sending request",
                            "error": "{}"
                        }}"#,
                        err
                    ));
                }
            }
                log_entry.reset();
                modules::startup::check_stopswitch(&configmap.bin_folder);
            }

        } else if running_module == "startup" {
            let params = [
            ("source", configmap.source.as_str()),
            ("sourcetype", configmap.sourcetype.as_str()),
            ("index", configmap.index.as_str()),
            ("host", hostname.as_str()),
            ];

            let startup_string = modules::startup::startup_log(&hostname, &configmap.app_folder);

            let payload = startup_string.unwrap();

            match client.post(api_url)
            .query(&params)
            .body(payload.as_json())
            .timeout(std::time::Duration::from_secs(5))
            .send() {
                Ok(_) => {
                }
                Err(err) => {
                    modules::logging::agent_logger("error", "startup", 
                    &format!(
                        r#"{{
                            "message": "Error sending request",
                            "error": "{}"
                        }}"#,
                        err
                    ));
                }
            }
            process::exit(0);
        } else if running_module == "storewatch" {
            let params = [
            ("source", configmap.source.as_str()),
            ("sourcetype", configmap.sourcetype.as_str()),
            ("index", configmap.index.as_str()),
            ("host", hostname.as_str()),
            ];

            if OS != "windows" {
                let storewatch_entry = modules::storewatch::get_storage_linux(&hostname);
                
                for entry in &storewatch_entry {
                    
                    let json_string = serde_json::to_string(&entry).expect("Failed to serialize storewatch entry");
                    let payload = json_string;
                    match client.post(api_url)
                    .query(&params)
                    .body(payload)
                    .timeout(std::time::Duration::from_secs(5))
                    .send() {
                        Ok(_) => {
                        }
                        Err(err) => {
                            modules::logging::agent_logger("error", "storewatch", 
                            &format!(
                                r#"{{
                                    "message": "Error sending request",
                                    "error": "{}"
                                }}"#,
                                err
                            ));
                        }
                    }
                }

                if !configmap.signalfx_uri.is_empty() {
                    let signalfx_client = signalfx_client.clone();
                    let signalfx_uri = configmap.signalfx_uri.clone();
                    let signalfx_token = signalfx_token.clone();
                    let gauge_json = modules::signalfx::generate_storage_gauge(&storewatch_entry, &configmap.rmtag);

                    let _ = modules::signalfx::send_gauge(&signalfx_client.unwrap(), &signalfx_uri, &gauge_json, signalfx_token.as_ref().unwrap(),1);
                }
            } else {
                let storewatch_entry = modules::storewatch::get_storage_windows(&hostname);

                for entry in storewatch_entry {
                    let json_string = serde_json::to_string(&entry).expect("Failed to serialize storewatch entry");
                    let payload = json_string;
                    match client.post(api_url)
                    .query(&params)
                    .body(payload)
                    .timeout(std::time::Duration::from_secs(5))
                    .send() {
                        Ok(_) => {
                        }
                        Err(err) => {
                            modules::logging::agent_logger("error", "storewatch", 
                            &format!(
                                r#"{{
                                    "message": "Error sending request",
                                    "error": "{}"
                                }}"#,
                                err
                            ));
                        }
                    }
                } 
            }
            process::exit(0);
        } else if running_module == "hostinfo" {
            let params = [
            ("source", configmap.source.as_str()),
            ("sourcetype", configmap.sourcetype.as_str()),
            ("index", configmap.index.as_str()),
            ("host", hostname.as_str()),
            ];
            std::io::stdin().read_line(&mut input).unwrap();
            let splunk_info = modules::hostinfo::get_splunkinfo(configmap.localapi.clone(), input);
            let payload = splunk_info.unwrap();

            match client.post(api_url)
            .query(&params)
            .body(payload.as_json())
            .timeout(std::time::Duration::from_secs(5))
            .send() {
                Ok(_) => {
                }
                Err(err) => {
                    modules::logging::agent_logger("error", "hostinfo", 
                    &format!(
                        r#"{{
                            "message": "Error sending request",
                            "error": "{}"
                        }}"#,
                        err
                    ));
                }
            }
            process::exit(0);
            
        }

    }

}
