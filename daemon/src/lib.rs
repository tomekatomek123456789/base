#![feature(never_type)]

use std::io::{self, PipeWriter, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::process::Command;

#[must_use = "Daemon::ready must be called"]
pub struct Daemon {
    write_pipe: PipeWriter,
}

impl Daemon {
    pub fn new<F: FnOnce(Daemon) -> !>(f: F) -> ! {
        let write_pipe = unsafe {
            io::PipeWriter::from_raw_fd(std::env::var("INIT_NOTIFY").unwrap().parse().unwrap())
        };

        f(Daemon { write_pipe })
    }

    pub fn ready(mut self) {
        self.write_pipe.write_all(&[0]).unwrap();
    }

    pub fn spawn(mut cmd: Command) {
        let (mut read_pipe, write_pipe) = io::pipe().unwrap();

        // Pass pipe to child
        if unsafe { libc::fcntl(write_pipe.as_raw_fd(), libc::F_SETFD, 0) } == -1 {
            eprintln!(
                "daemon: failed to unset CLOEXEC flag for pipe: {}",
                io::Error::last_os_error()
            );
            return;
        }
        cmd.env("INIT_NOTIFY", format!("{}", write_pipe.as_raw_fd()));

        if let Err(err) = cmd.spawn() {
            eprintln!("daemon: failed to execute {cmd:?}: {err}");
            return;
        }
        drop(write_pipe);

        let mut data = [0];
        match read_pipe.read_exact(&mut data) {
            Ok(()) => {
                if data[0] != 0 {
                    eprintln!("daemon: {cmd:?} failed with {}", data[0]);
                }
            }
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => {
                eprintln!("daemon: {cmd:?} exited without notifying readiness");
            }
            Err(err) => {
                eprintln!("daemon: failed to wait for {cmd:?}: {err}");
            }
        }
    }
}
