use std::collections::BTreeMap;
use std::fs::read_dir;
use std::io::Result;
use std::path::Path;
use std::process::Command;
use std::{env, fs};

use libredox::flag::{O_RDONLY, O_WRONLY};

fn switch_stdio(stdio: &str) -> Result<()> {
    let stdin = libredox::Fd::open(stdio, O_RDONLY, 0)?;
    let stdout = libredox::Fd::open(stdio, O_WRONLY, 0)?;
    let stderr = libredox::Fd::open(stdio, O_WRONLY, 0)?;

    stdin.dup2(0, &[])?;
    stdout.dup2(1, &[])?;
    stderr.dup2(2, &[])?;

    Ok(())
}

struct InitConfig {
    pub log_debug: bool,
    pub skip_cmd: Vec<String>,
}

impl InitConfig {
    pub fn new() -> Self {
        let log_level = env::var("INIT_LOG_LEVEL").unwrap_or("INFO".into());
        let log_debug = matches!(log_level.as_str(), "DEBUG" | "TRACE");
        let skip_cmd: Vec<String> = match env::var("INIT_SKIP") {
            Ok(v) if v.len() > 0 => v.split(',').map(|s| s.to_string()).collect(),
            _ => Vec::new(),
        };

        Self {
            log_debug,
            skip_cmd,
        }
    }
}

pub fn run(file: &Path, config: &InitConfig) -> Result<()> {
    for line_raw in fs::read_to_string(file)?.lines() {
        let line = line_raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if config.log_debug {
            eprintln!("init: running: {:?}", line);
        }
        run_command(line, config);
    }

    Ok(())
}

fn run_command(line: &str, config: &InitConfig) {
    let mut args = line.split(' ').map(|arg| {
        if arg.starts_with('$') {
            env::var(&arg[1..]).unwrap_or(String::new())
        } else {
            arg.to_string()
        }
    });

    if let Some(cmd) = args.next() {
        match cmd.as_str() {
            "cd" => {
                let Some(dir) = args.next() else {
                    eprintln!("init: failed to cd: no argument");
                    return;
                };
                if let Err(err) = env::set_current_dir(&dir) {
                    eprintln!("init: failed to cd to '{}': {}", dir, err);
                }
            }
            "echo" => {
                println!("{}", args.collect::<Vec<_>>().join(" "));
            }
            "export" => {
                let Some(var) = args.next() else {
                    eprintln!("init: failed to export: no argument");
                    return;
                };
                let mut value = String::new();
                if let Some(arg) = args.next() {
                    value.push_str(&arg);
                }
                for arg in args {
                    value.push(' ');
                    value.push_str(&arg);
                }
                unsafe { env::set_var(var, value) };
            }
            "run" => {
                let Some(new_file) = args.next() else {
                    eprintln!("init: failed to run: no argument");
                    return;
                };
                if let Err(err) = run(&Path::new(&new_file), config) {
                    eprintln!("init: failed to run '{}': {}", new_file, err);
                }
            }
            "run.d" => {
                // This must be a BTreeMap to iterate in sorted order.
                let mut entries = BTreeMap::new();
                let mut missing_arg = true;

                for new_dir in args {
                    if !Path::new(&new_dir).exists() {
                        // Skip non-existent dirs
                        continue;
                    }
                    missing_arg = false;

                    let list = match read_dir(&new_dir) {
                        Ok(list) => list,
                        Err(err) => {
                            eprintln!("init: failed to run.d: '{}': {}", new_dir, err);
                            continue;
                        }
                    };
                    for entry_res in list {
                        match entry_res {
                            Ok(entry) => {
                                // This intentionally overwrites older entries with
                                // the same filename to allow overriding entries in
                                // one search dir with those in a later search dir.
                                entries.insert(entry.file_name(), entry.path());
                            }
                            Err(err) => {
                                eprintln!("init: failed to run.d: '{}': {}", new_dir, err);
                            }
                        }
                    }
                }

                if missing_arg {
                    eprintln!("init: failed to run.d: no argument or all dirs are non-existent");
                    return;
                }

                // This takes advantage of BTreeMap iterating in sorted order.
                for (_, entry_path) in entries {
                    if let Err(err) = run(&entry_path, config) {
                        eprintln!("init: failed to run '{}': {}", entry_path.display(), err);
                    }
                }
            }
            "stdio" => {
                let Some(stdio) = args.next() else {
                    eprintln!("init: failed to set stdio: no argument");
                    return;
                };
                if let Err(err) = switch_stdio(&stdio) {
                    eprintln!("init: failed to switch stdio to '{}': {}", stdio, err);
                }
            }
            "unset" => {
                for arg in args {
                    unsafe { env::remove_var(&arg) };
                }
            }
            "nowait" => {
                let Some(cmd) = args.next() else {
                    eprintln!("init: failed to run nowait: no argument");
                    return;
                };
                let mut command = Command::new(cmd);

                for arg in args {
                    command.arg(arg);
                }

                match command.spawn() {
                    Ok(_child) => {}
                    Err(err) => eprintln!("init: failed to execute '{}': {}", line, err),
                }
            }
            _ => {
                let mut command = Command::new(cmd.clone());
                for arg in args {
                    command.arg(arg);
                }

                if config.skip_cmd.contains(&cmd) {
                    eprintln!("init: skipping '{}'", line);
                    return;
                }

                let mut child = match command.spawn() {
                    Ok(child) => child,
                    Err(err) => {
                        eprintln!("init: failed to execute '{}': {}", line, err);
                        return;
                    }
                };
                match child.wait() {
                    Ok(exit_status) => {
                        if !exit_status.success() {
                            eprintln!("{cmd} failed with {exit_status}");
                        }
                    }
                    Err(err) => {
                        eprintln!("init: failed to wait for '{}': {}", line, err)
                    }
                }
            }
        }
    }
}

pub fn main() {
    let init_path = Path::new("/scheme/initfs/etc/init.rc");
    let init_config = InitConfig::new();
    if let Err(err) = run(&init_path, &init_config) {
        eprintln!("init: failed to run {:?}: {}", init_path, err);
    }

    libredox::call::setrens(0, 0).expect("init: failed to enter null namespace");

    loop {
        let mut status = 0;
        libredox::call::waitpid(0, &mut status, 0).unwrap();
    }
}
