use redox_scheme::{RequestKind, SignalBehavior, Socket};
use std::env;
use std::fs::OpenOptions;
use std::process;

use crate::scheme::LogScheme;

mod scheme;

fn daemon(daemon: redox_daemon::Daemon) -> ! {
    let mut files = Vec::new();
    for arg in env::args().skip(1) {
        eprintln!("logd: opening {:?}", arg);
        match OpenOptions::new().write(true).open(&arg) {
            Ok(file) => files.push(file),
            Err(err) => eprintln!("logd: failed to open {:?}: {:?}", arg, err),
        }
    }

    let socket = Socket::create("log").expect("logd: failed to create log scheme");

    eprintln!("logd: ready for logging on log:");

    daemon.ready().expect("logd: failed to notify parent");

    let mut scheme = LogScheme::new(files);

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
    redox_daemon::Daemon::new(daemon).expect("logd: failed to daemonize");
}
