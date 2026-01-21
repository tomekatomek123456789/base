use redox_scheme::{
    scheme::{register_sync_scheme, SchemeSync},
    RequestKind, Response, SignalBehavior, Socket,
};
use std::process;

use crate::scheme::LogScheme;

mod scheme;

fn daemon(daemon: daemon::Daemon) -> ! {
    let socket = Socket::create().expect("logd: failed to create log scheme");

    let mut scheme = LogScheme::new(&socket);

    register_sync_scheme(&socket, "log", &mut scheme)
        .expect("logd: failed to register scheme to namespace");

    libredox::call::setrens(0, 0).expect("logd: failed to enter null namespace");

    daemon.ready();

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
            RequestKind::SendFd(sendfd_request) => {
                let result = scheme.on_sendfd(&sendfd_request);
                let resp = Response::new(result, sendfd_request);
                socket
                    .write_response(resp, SignalBehavior::Restart)
                    .expect("logd: failed to write responses to log scheme");
                continue;
            }
            _ => continue,
        };

        let response = request.handle_sync(&mut scheme);
        socket
            .write_response(response, SignalBehavior::Restart)
            .expect("logd: failed to write responses to log scheme");
    }
    process::exit(0);
}

fn main() {
    daemon::Daemon::new(daemon);
}
