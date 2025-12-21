use std::cell::RefCell;

use event::{user_data, EventFlags, EventQueue};
use libredox::{flag, Fd};

use redox_scheme::wrappers::ReadinessBased;
use redox_scheme::{Response, SignalBehavior, Socket};
use syscall::data::TimeSpec;

mod controlterm;
mod pgrp;
mod pty;
mod resource;
mod scheme;
mod subterm;
mod termios;
mod winsize;

use scheme::PtyScheme;

fn main() {
    daemon::Daemon::new(daemon);
}

fn daemon(daemon: daemon::Daemon) -> ! {
    user_data! {
        enum EventSource {
            Socket,
            Time,
        }
    }

    let event_queue = EventQueue::<EventSource>::new().expect("pty: failed to open event:");

    let time_path = format!("/scheme/time/{}", flag::CLOCK_MONOTONIC);
    let mut time_file =
        Fd::open(&time_path, flag::O_NONBLOCK, 0).expect("pty: failed to open time:");

    let socket = redox_scheme::Socket::nonblock("pty").expect("pty: failed to create pty scheme");
    let mut handler = ReadinessBased::new(&socket, 16);

    libredox::call::setrens(0, 0).expect("ptyd: failed to enter null namespace");

    event_queue
        .subscribe(socket.inner().raw(), EventSource::Socket, EventFlags::READ)
        .expect("pty: failed to watch events on pty:");
    event_queue
        .subscribe(time_file.raw(), EventSource::Time, EventFlags::READ)
        .expect("pty: failed to watch events on time:");

    daemon.ready();

    //TODO: do not set timeout if not necessary
    timeout(&mut time_file).expect("pty: failed to set timeout");

    let scheme = RefCell::new(PtyScheme::new());
    let mut timeout_count = 0u64;

    scan_requests(&mut handler, &scheme).expect("pty: could not scan requests");
    issue_events(&socket, &mut *scheme.borrow_mut());

    for event_res in event_queue {
        let event = event_res.expect("pty: failed to read from event queue");

        match event.user_data {
            EventSource::Socket => {
                if scan_requests(&mut handler, &scheme).is_err() {
                    break;
                }
            }
            EventSource::Time => {
                timeout(&mut time_file).expect("pty: failed to set timeout");

                timeout_count = timeout_count.wrapping_add(1);

                for (_id, handle) in scheme.borrow_mut().handles.iter_mut() {
                    handle.timeout(timeout_count);
                }

                handler
                    .poll_all_requests(|| scheme.borrow_mut())
                    .expect("ihdad: failed to poll requests");
            }
        }

        issue_events(&socket, &mut *scheme.borrow_mut());
    }

    std::process::exit(0);
}

fn scan_requests(
    handler: &mut ReadinessBased<'_>,
    scheme: &RefCell<PtyScheme>,
) -> libredox::error::Result<()> {
    // 1. Read requests
    match handler
        .read_requests()
        .expect("pty: failed to read from socket")
    {
        true => {} // Read requests success
        false => {
            panic!("pty: channel EOF")
        }
    }

    // 2. Process requests
    handler.process_requests(|| scheme.borrow_mut());

    // 3. Poll all blocking requests
    handler
        .poll_all_requests(|| scheme.borrow_mut())
        .expect("pty: error occured in poll_all_requests");

    // 4. Write responses
    match handler
        .write_responses()
        .expect("pty: failed to write to socket")
    {
        true => {} // Write requests success
        false => {
            panic!("pty: channel EOF")
        }
    }
    Ok(())
}

fn issue_events(socket: &Socket, scheme: &mut PtyScheme) {
    for (id, handle) in scheme.handles.iter_mut() {
        let events = handle.events();
        if events != syscall::EventFlags::empty() {
            socket
                .write_response(
                    Response::post_fevent(*id, events.bits()),
                    SignalBehavior::Restart,
                )
                .expect("pty: failed to send scheme event");
        }
    }
}

fn timeout(time_file: &mut Fd) -> libredox::error::Result<()> {
    let mut time = TimeSpec::default();
    time_file.read(&mut time)?;

    time.tv_nsec += 100_000_000;
    while time.tv_nsec >= 1_000_000_000 {
        time.tv_sec += 1;
        time.tv_nsec -= 1_000_000_000;
    }

    time_file.write(&time)?;
    Ok(())
}
