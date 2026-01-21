use redox_scheme::{scheme::register_sync_scheme, RequestKind, SignalBehavior, Socket};

use scheme::ZeroScheme;

mod scheme;

enum Ty {
    Null,
    Zero,
}

fn main() {
    daemon::Daemon::new(daemon);
}

fn daemon(daemon: daemon::Daemon) -> ! {
    let ty = match &*std::env::args().next().unwrap() {
        "nulld" => Ty::Null,
        "zerod" => Ty::Zero,
        _ => panic!("needs to be called as either nulld or zerod"),
    };

    let name = match ty {
        Ty::Null => "null",
        Ty::Zero => "zero",
    };
    let socket = Socket::create().expect("zerod: failed to create zero scheme");
    let mut zero_scheme = ZeroScheme(ty);

    register_sync_scheme(&socket, name, &mut zero_scheme)
        .expect("zerod: failed to register scheme to namespace");

    daemon.ready();

    libredox::call::setrens(0, 0).expect("zerod: failed to enter null namespace");

    loop {
        let Some(request) = socket
            .next_request(SignalBehavior::Restart)
            .expect("zerod: failed to read events from zero scheme")
        else {
            std::process::exit(0);
        };
        match request.kind() {
            RequestKind::Call(request) => {
                let response = request.handle_sync(&mut zero_scheme);

                socket
                    .write_response(response, SignalBehavior::Restart)
                    .expect("zerod: failed to write responses to zero scheme");
            }
            _ => (),
        }
    }
}
