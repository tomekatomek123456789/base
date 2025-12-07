use redox_scheme::{RequestKind, SignalBehavior, Socket};
use std::process;

use crate::scheme::LogScheme;

mod scheme;

fn daemon(daemon: daemon::Daemon) -> ! {
    let socket = Socket::create("log").expect("logd: failed to create log scheme");

    daemon.ready();

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
    daemon::Daemon::new(daemon);
}
