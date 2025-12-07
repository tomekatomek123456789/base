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

pub fn run(file: &Path) -> Result<()> {
    for line in fs::read_to_string(file)?.lines() {
        run_command(line);
    }

    Ok(())
}

fn run_command(line_raw: &str) {
    let line = line_raw.trim();
    if line.is_empty() || line.starts_with('#') {
        return;
    }
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
                    println!("init: failed to cd: no argument");
                    return;
                };
                if let Err(err) = env::set_current_dir(&dir) {
                    println!("init: failed to cd to '{}': {}", dir, err);
                }
            }
            "echo" => {
                println!("{}", args.collect::<Vec<_>>().join(" "));
            }
            "export" => {
                let Some(var) = args.next() else {
                    println!("init: failed to export: no argument");
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
                    println!("init: failed to run: no argument");
                    return;
                };
                if let Err(err) = run(&Path::new(&new_file)) {
                    println!("init: failed to run '{}': {}", new_file, err);
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
                            println!("init: failed to run.d: '{}': {}", new_dir, err);
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
                                println!("init: failed to run.d: '{}': {}", new_dir, err);
                            }
                        }
                    }
                }

                if missing_arg {
                    println!("init: failed to run.d: no argument or all dirs are non-existent");
                    return;
                }

                // This takes advantage of BTreeMap iterating in sorted order.
                for (_, entry_path) in entries {
                    if let Err(err) = run(&entry_path) {
                        println!("init: failed to run '{}': {}", entry_path.display(), err);
                    }
                }
            }
            "stdio" => {
                let Some(stdio) = args.next() else {
                    println!("init: failed to set stdio: no argument");
                    return;
                };
                if let Err(err) = switch_stdio(&stdio) {
                    println!("init: failed to switch stdio to '{}': {}", stdio, err);
                }
            }
            "unset" => {
                for arg in args {
                    unsafe { env::remove_var(&arg) };
                }
            }
            "nowait" => {
                let Some(cmd) = args.next() else {
                    println!("init: failed to run nowait: no argument");
                    return;
                };
                let mut command = Command::new(cmd);

                for arg in args {
                    command.arg(arg);
                }

                match command.spawn() {
                    Ok(_child) => {}
                    Err(err) => println!("init: failed to execute '{}': {}", line, err),
                }
            }
            _ => {
                let mut command = Command::new(cmd.clone());
                for arg in args {
                    command.arg(arg);
                }

                let mut child = match command.spawn() {
                    Ok(child) => child,
                    Err(err) => {
                        println!("init: failed to execute '{}': {}", line, err);
                        return;
                    }
                };
                match child.wait() {
                    Ok(exit_status) => {
                        if !exit_status.success() {
                            println!("{cmd} failed with {exit_status}");
                        }
                    }
                    Err(err) => {
                        println!("init: failed to wait for '{}': {}", line, err)
                    }
                }
            }
        }
    }
}

pub fn main() {
    let config = "/scheme/initfs/etc/init.rc";
    if let Err(err) = run(&Path::new(config)) {
        println!("init: failed to run {}: {}", config, err);
    }

    libredox::call::setrens(0, 0).expect("init: failed to enter null namespace");

    loop {
        let mut status = 0;
        libredox::call::waitpid(0, &mut status, 0).unwrap();
    }
}
