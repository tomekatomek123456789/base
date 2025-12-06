#![feature(int_roundings, let_chains)]

use event::{EventFlags, EventQueue};
use redox_scheme::{wrappers::ReadinessBased, Socket};
use std::sync::Mutex;

mod chan;
mod shm;
mod uds;

use self::chan::ChanScheme;
use self::shm::ShmScheme;
use self::uds::dgram::UdsDgramScheme;
use self::uds::stream::UdsStreamScheme;

fn main() {
    daemon::Daemon::new(daemon_runner);
}

fn daemon_runner(daemon: daemon::Daemon) -> ! {
    // TODO: Better error handling
    match inner(daemon) {
        Ok(()) => std::process::exit(0),
        Err(error) => {
            println!("ipcd failed: {error}");
            std::process::exit(1);
        }
    }
}

fn inner(daemon: daemon::Daemon) -> anyhow::Result<()> {
    event::user_data! {
        enum EventSource {
            ChanSocket,
            ShmSocket,
            UdsStreamSocket,
            UdsDgramSocket,
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

    // Prepare uds stream scheme
    let uds_stream_socket = Socket::nonblock("uds_stream")
        .map_err(|e| anyhow::anyhow!("failed to create uds stream scheme: {e}"))?;
    let uds_stream = Mutex::new(
        UdsStreamScheme::new(&uds_stream_socket)
            .map_err(|e| anyhow::anyhow!("failed to create uds stream scheme: {e}"))?,
    );
    let mut uds_stream_handler = ReadinessBased::new(&uds_stream_socket, 16);

    // Prepare uds dgram scheme
    let uds_dgram_socket = Socket::nonblock("uds_dgram")
        .map_err(|e| anyhow::anyhow!("failed to create uds dgram scheme: {e}"))?;
    let uds_dgram = Mutex::new(
        UdsDgramScheme::new(&uds_dgram_socket)
            .map_err(|e| anyhow::anyhow!("failed to create uds dgram scheme: {e}"))?,
    );
    let mut uds_dgram_handler = ReadinessBased::new(&uds_dgram_socket, 16);

    daemon.ready();

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
    event_queue
        .subscribe(
            uds_stream_socket.inner().raw(),
            EventSource::UdsStreamSocket,
            EventFlags::READ,
        )
        .map_err(|e| anyhow::anyhow!("failed to subscribe uds stream socket: {e}"))?;
    event_queue
        .subscribe(
            uds_dgram_socket.inner().raw(),
            EventSource::UdsDgramSocket,
            EventFlags::READ,
        )
        .map_err(|e| anyhow::anyhow!("failed to subscribe uds dgram socket: {e}"))?;

    libredox::call::setrens(0, 0)?;

    // EOF flags
    let mut chan_eof = false;
    let mut shm_eof = false;
    let mut uds_stream_eof = false;
    let mut uds_dgram_eof = false;
    while !(chan_eof && shm_eof && uds_stream_eof && uds_dgram_eof) {
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
            EventSource::UdsStreamSocket => {
                // Unix Domain Socket Stream scheme
                if !uds_stream_eof {
                    // 1. Read requests
                    match uds_stream_handler.read_requests() {
                        Ok(true) => {} // Read requests success
                        Ok(false) => {
                            // EOF
                            uds_stream_eof = true;
                        }
                        Err(err) => return Err(anyhow::anyhow!("{err}")),
                    }
                }

                // 2. Process requests
                uds_stream_handler.process_requests(|| uds_stream.lock().unwrap());

                // 3.Poll all blocking requests
                uds_stream_handler
                    .poll_all_requests(|| uds_stream.lock().unwrap())
                    .map_err(|e| anyhow::anyhow!("error occured in poll_all_requests: {e}"))?;

                // 3. Write responses
                // write_responses returns a Result<bool>, but currently only returns true.
                match uds_stream_handler.write_responses() {
                    Ok(true) => {} // Read requests success
                    Ok(false) => {
                        // EOF
                        uds_stream_eof = true;
                    }
                    Err(err) => return Err(anyhow::anyhow!("{err}")),
                }
            }
            EventSource::UdsDgramSocket => {
                // Unix Domain Socket Dgram scheme
                if !uds_dgram_eof {
                    // 1. Read requests
                    match uds_dgram_handler.read_requests() {
                        Ok(true) => {} // Read requests success
                        Ok(false) => {
                            // EOF
                            uds_dgram_eof = true;
                        }
                        Err(err) => return Err(anyhow::anyhow!("{err}")),
                    }
                }

                // 2. Process requests
                uds_dgram_handler.process_requests(|| uds_dgram.lock().unwrap());

                // 3.Poll all blocking requests
                uds_dgram_handler
                    .poll_all_requests(|| uds_dgram.lock().unwrap())
                    .map_err(|e| anyhow::anyhow!("error occured in poll_all_requests: {e}"))?;

                // 3. Write responses
                // write_responses returns a Result<bool>, but currently only returns true.
                match uds_dgram_handler.write_responses() {
                    Ok(true) => {} // Read requests success
                    Ok(false) => {
                        // EOF
                        uds_dgram_eof = true;
                    }
                    Err(err) => return Err(anyhow::anyhow!("{err}")),
                }
            }
        }
    }
    Ok(())
}
