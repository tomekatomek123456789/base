use redox_scheme::{RequestKind, SignalBehavior, Socket};
use std::io::{Read, Write};
use std::process;

use crate::scheme::LogScheme;

mod scheme;

fn daemon(daemon: redox_daemon::Daemon) -> ! {
    let socket = Socket::create("log").expect("logd: failed to create log scheme");

    std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--internal-copy-kernel-log")
        .spawn()
        .unwrap();

    eprintln!("logd: ready for logging on log:");

    daemon.ready().expect("logd: failed to notify parent");

    let mut scheme = LogScheme::new();

    while let Some(request) = socket
        .next_request(SignalBehavior::Restart)
        .expect("logd: failed to read events from log scheme")
    {
        let request = match request.kind() {
            RequestKind::Call(call) => call,
            RequestKind::OnClose { id } => {
                scheme.on_close(id);
                continue;
            }
            _ => continue,
        };

        let response = request.handle_sync(&mut scheme);
        socket
            .write_responses(&[response], SignalBehavior::Restart)
            .expect("logd: failed to write responses to log scheme");
    }
    process::exit(0);
}

fn main() {
    if std::env::args().nth(1).as_deref() == Some("--internal-copy-kernel-log") {
        let mut debug_file = std::fs::File::open("/scheme/sys/log").unwrap();
        let mut log_file = std::fs::OpenOptions::new()
            .write(true)
            .open("/scheme/log/kernel")
            .unwrap();
        let mut buf = [0; 4096];
        loop {
            let n = debug_file.read(&mut buf).unwrap();
            assert!(n != 0); // FIXME currently fails as /scheme/log/kernel presents a snapshot of the log queue
            log_file.write_all(&buf[..n]).unwrap();
        }
    }

    redox_daemon::Daemon::new(daemon).expect("logd: failed to daemonize");
}
