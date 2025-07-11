#![feature(int_roundings, let_chains)]

use event::{EventFlags, EventQueue};
use redox_scheme::{wrappers::ReadinessBased, Socket};
use std::sync::Mutex;

mod chan;
mod shm;

use self::chan::ChanScheme;
use self::shm::ShmScheme;

fn main() {
    redox_daemon::Daemon::new(move |daemon| {
        // TODO: Better error handling
        match inner(daemon) {
            Ok(()) => std::process::exit(0),
            Err(error) => {
                println!("ipcd failed: {error}");
                std::process::exit(1);
            }
        }
    })
    .expect("ipcd: failed to daemonize");
}

fn inner(daemon: redox_daemon::Daemon) -> anyhow::Result<()> {
    event::user_data! {
        enum EventSource {
            ChanSocket,
            ShmSocket,
        }
    }

    // Prepare chan scheme
    let chan_socket = Socket::nonblock("chan")
        .map_err(|e| anyhow::anyhow!("failed to create chan scheme: {e}"))?;
    let chan = Mutex::new(ChanScheme::new(&chan_socket));
    let mut chan_handler = ReadinessBased::new(&chan_socket, 16);

    // Prepare shm scheme
    let shm_socket =
        Socket::nonblock("shm").map_err(|e| anyhow::anyhow!("failed to create shm socket: {e}"))?;
    let shm = Mutex::new(ShmScheme::new());
    let mut shm_handler = ReadinessBased::new(&shm_socket, 16);

    daemon.ready().unwrap();

    // Create event listener for both files
    let mut event_queue = EventQueue::<EventSource>::new()
        .map_err(|e| anyhow::anyhow!("failed to create event queue: {e}"))?;
    event_queue
        .subscribe(
            chan_socket.inner().raw(),
            EventSource::ChanSocket,
            EventFlags::READ,
        )
        .map_err(|e| anyhow::anyhow!("failed to subscribe chan socket: {e}"))?;
    event_queue
        .subscribe(
            shm_socket.inner().raw(),
            EventSource::ShmSocket,
            EventFlags::READ,
        )
        .map_err(|e| anyhow::anyhow!("failed to subscribe shm socket: {e}"))?;

    libredox::call::setrens(0, 0)?;

    // EOF flags
    let mut chan_eof = false;
    let mut shm_eof = false;
    while !(chan_eof && shm_eof) {
        let Some(event_res) = event_queue.next() else {
            break;
        };
        let event = event_res.map_err(|e| anyhow::anyhow!("error occured in event queue: {e}"))?;

        match event.user_data {
            EventSource::ChanSocket => {
                // Channel scheme
                if !chan_eof {
                    // 1. Read requests
                    match chan_handler.read_requests() {
                        Ok(true) => {} // Read requests success
                        Ok(false) => {
                            // EOF
                            chan_eof = true;
                        }
                        Err(err) => return Err(anyhow::anyhow!("{err}")),
                    }
                }

                // 2. Process requests
                chan_handler.process_requests(|| chan.lock().unwrap());

                // 3.Poll all blocking requests
                chan_handler
                    .poll_all_requests(|| chan.lock().unwrap())
                    .map_err(|e| anyhow::anyhow!("error occured in poll_all_requests: {e}"))?;

                // 3. Write responses
                // write_responses returns a Result<bool>, but currently only returns true.
                match chan_handler.write_responses() {
                    Ok(true) => {} // Read requests success
                    Ok(false) => {
                        // EOF
                        chan_eof = true;
                    }
                    Err(err) => return Err(anyhow::anyhow!("{err}")),
                }
            }
            EventSource::ShmSocket => {
                // Shared memory scheme
                if !shm_eof {
                    // 1. Read requests
                    match shm_handler.read_requests() {
                        Ok(true) => {} // Read requests success
                        Ok(false) => {
                            // EOF
                            shm_eof = true;
                        }
                        Err(err) => return Err(anyhow::anyhow!("{err}")),
                    }
                }

                // 2. Process requests
                shm_handler.process_requests(|| shm.lock().unwrap());

                // shm is not a blocking scheme

                // 3. Write responses
                // write_responses returns a Result<bool>, but currently only returns true.
                match shm_handler.write_responses() {
                    Ok(true) => {} // Read requests success
                    Ok(false) => {
                        // EOF
                        shm_eof = true;
                    }
                    Err(err) => return Err(anyhow::anyhow!("{err}")),
                }
            }
        }
    }
    Ok(())
}
