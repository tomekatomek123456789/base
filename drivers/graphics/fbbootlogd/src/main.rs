//! Fbbootlogd renders the boot log and presents it on VT1.
//!
//! While fbbootlogd is superficially similar to fbcond, the major difference is:
//!
//! * Fbbootlogd doesn't accept input coming from the keyboard. It only allows getting written to.
//!
//! In the future fbbootlogd may also pull from logd as opposed to have logd push logs to it. And it
//! it could display a boot splash like plymouth instead of a boot log when booting in quiet mode.

use std::io::Write;
use std::os::fd::AsRawFd;

use event::EventQueue;
use inputd::ConsumerHandleEvent;
use libredox::errno::EAGAIN;
use orbclient::Event;
use redox_scheme::{scheme::register_sync_scheme, RequestKind, SignalBehavior, Socket};

use crate::scheme::FbbootlogScheme;

mod scheme;

fn main() {
    daemon::Daemon::new(daemon);
}
fn daemon(daemon: daemon::Daemon) -> ! {
    let event_queue = EventQueue::new().expect("fbbootlogd: failed to create event queue");

    event::user_data! {
        enum Source {
            Scheme,
            Input,
        }
    }

    let socket = Socket::nonblock().expect("fbbootlogd: failed to create fbbootlog scheme");

    let mut scheme = FbbootlogScheme::new();

    event_queue
        .subscribe(
            socket.inner().raw(),
            Source::Scheme,
            event::EventFlags::READ,
        )
        .expect("fbbootlogd: failed to subscribe to scheme events");

    event_queue
        .subscribe(
            scheme.input_handle.event_handle().as_raw_fd() as usize,
            Source::Input,
            event::EventFlags::READ,
        )
        .expect("fbbootlogd: failed to subscribe to scheme events");

    {
        let log_fd = socket
            .create_this_scheme_fd(0, 0, 0, 0)
            .expect("fbbootlogd: failed to create log fd");
        // Add ourself as log sink
        let mut log_file = libredox::Fd::open(
            "/scheme/log/add_sink",
            libredox::flag::O_WRONLY | libredox::flag::O_CLOEXEC,
            0,
        )
        .expect("fbbootlogd: failed to open log/add_sink");
        log_file
            .call_wo(&log_fd.to_ne_bytes(), syscall::CallFlags::FD, &[])
            .expect("fbbootlogd: failed to send log fd to log scheme.");
    }

    register_sync_scheme(&socket, "fbbootlog", &mut scheme)
        .expect("fbbootlog: failed to register scheme to namespace");

    // This is not possible for now as fbbootlogd needs to open new displays at runtime for graphics
    // driver handoff. In the future inputd may directly pass a handle to the display instead.
    //libredox::call::setrens(0, 0).expect("fbbootlogd: failed to enter null namespace");

    daemon.ready();

    for event in event_queue {
        match event.expect("fbbootlogd: failed to get event").user_data {
            Source::Scheme => {
                loop {
                    let request = match socket.next_request(SignalBehavior::Restart) {
                        Ok(Some(request)) => request,
                        Ok(None) => {
                            // Scheme likely got unmounted
                            std::process::exit(0);
                        }
                        Err(err) if err.errno == EAGAIN => break,
                        Err(err) => panic!("fbbootlogd: failed to read display scheme: {err:?}"),
                    };

                    match request.kind() {
                        RequestKind::Call(call) => {
                            let response = call.handle_sync(&mut scheme);

                            socket
                                .write_response(response, SignalBehavior::Restart)
                                .expect("pcid: failed to write next scheme response");
                        }
                        RequestKind::OnClose { id } => {
                            scheme.on_close(id);
                        }
                        _ => (),
                    }
                }
            }
            Source::Input => {
                let mut events = [Event::new(); 16];
                loop {
                    match scheme
                        .input_handle
                        .read_events(&mut events)
                        .expect("fbbootlogd: error while reading events")
                    {
                        ConsumerHandleEvent::Events(&[]) => break,
                        ConsumerHandleEvent::Events(events) => {
                            for event in events {
                                scheme.handle_input(&event);
                            }
                        }
                        ConsumerHandleEvent::Handoff => {
                            eprintln!("fbbootlogd: handoff requested");
                            scheme.handle_handoff();
                        }
                    }
                }
            }
        }
    }

    std::process::exit(0);
}
