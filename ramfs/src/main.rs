use std::{env, process};

mod filesystem;
mod scheme;

use redox_scheme::{RequestKind, SignalBehavior};

use self::scheme::Scheme;

fn main() {
    daemon::Daemon::new(daemon);
}

fn daemon(daemon: daemon::Daemon) -> ! {
    let scheme_name = env::args().nth(1).expect("Usage:\n\tramfs SCHEME_NAME");

    let socket = redox_scheme::Socket::create().expect("ramfs: failed to create socket");

    let mut scheme = Scheme::new(scheme_name.clone()).expect("ramfs: failed to initialize scheme");

    redox_scheme::scheme::register_sync_scheme(&socket, &scheme_name, &mut scheme)
        .expect("ramfs: failed to register to namespace");
    daemon.ready();
    libredox::call::setrens(0, 0).expect("ramfs: failed to enter null namespace");

    loop {
        let Some(request) = socket
            .next_request(SignalBehavior::Restart)
            .expect("ramfs: failed to get next scheme request")
        else {
            break;
        };
        match request.kind() {
            RequestKind::Call(call) => {
                let response = call.handle_sync(&mut scheme);

                socket
                    .write_response(response, SignalBehavior::Restart)
                    .expect("ramfs: failed to write next scheme response");
            }
            RequestKind::OnClose { id } => {
                scheme.on_close(id);
            }
            _ => (),
        }
    }

    process::exit(0);
}
