use std::{env, fs::{self, OpenOptions}, path::{Path, PathBuf}, process, thread, time::Duration};
use std::io::Write;
use gethostname::gethostname;
mod modules {
    pub mod startup;
    pub mod config;
}
use procfs::process::all_processes;
use sysinfo::{System, Pid};


fn check_running_process(exe: &Path, pid: &u32) {
    let pid_file_path = exe.join(".agent.pid");
    let executable = std::env::current_exe().unwrap();
    let pid_file = pid_file_path.to_str().unwrap();

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

        let mut found_running_process = false;
        let mut old_pid: i32 = 0;

        if let Ok(processes) = all_processes() {
            for process_result in processes {
                match process_result {
                    Ok(process) => {
                        if let Ok(process_exe) = process.exe() {
                            if executable == process_exe && *pid != process.pid() as u32 {
                                if let Ok(cmdline) = process.cmdline() {
                                    if let Some(first_arg) = cmdline.get(1) {
                                        if first_arg == "splunkagent" {
                                            found_running_process = true;
                                            old_pid = process.pid();
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to get process: {}", e);
                    }
                }
            }
        }

        if found_running_process {
            println!("Found running process with PID: {}", old_pid);
            writeln!(file, "{}", old_pid).expect("Failed to write to PID file");
            process::exit(0);
        } else {    
            let current_pid = process::id();
            writeln!(file, "{}", current_pid).expect("Failed to write to PID file");
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
            println!("Process with PID {} is running", old_pid);
            process::exit(0);
        } else {
            println!("Process with PID {} is not running", old_pid);
            let mut file = OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(pid_file)
                .expect("Failed to open PID file");
            let current_pid = process::id();
            writeln!(file, "{}", current_pid).expect("Failed to write to PID file");
            println!("PID {} is written to file.", current_pid);
        }
    }
}   



fn main() {
    let args: Vec<String> = std::env::args().collect();
    let configmap = modules::config::get_configmap();

    if args.len() > 1 {
        if args[1] == "startup" {
            let hostname = gethostname().to_string_lossy().to_string();
            let startup_entry = modules::startup::startup_log(hostname, &configmap.root_folder, &configmap.app_folder);
            let startup_path = configmap.root_folder.join(&configmap.location);
            let startup_file = startup_path.join("startup_splunkd.log");

            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(startup_file)
                .expect("Failed to open PID file");
            writeln!(file, "{}", startup_entry.unwrap()).expect("Failed to write to PID file");
            process::exit(0);
        } else if args[1] == "splunkagent" {
            let current_pid = process::id();
            check_running_process(&configmap.bin_folder, &current_pid);
        }
    } else {
        println!("No arguments provided");
        process::exit(1);
    }
    loop {
        println!("Sleepy");
        thread::sleep(Duration::from_secs(1));
    }

    

    
    
}
