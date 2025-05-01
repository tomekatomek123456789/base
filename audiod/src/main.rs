use std::mem::MaybeUninit;
use std::ptr::addr_of_mut;
use std::sync::{Arc, Mutex};
use std::{mem, process, slice, thread};

use anyhow::Context;
use ioslice::IoSlice;
use libredox::flag;
use libredox::{error::Result, Fd};

use redox_scheme::wrappers::ReadinessBased;
use redox_scheme::Socket;

use redox_daemon::Daemon;

use self::scheme::AudioScheme;

mod scheme;

extern "C" fn sigusr_handler(_sig: usize) {}

fn thread(scheme: Arc<Mutex<AudioScheme>>, pid: usize, hw_file: Fd) -> Result<()> {
    loop {
        let buffer = scheme.lock().unwrap().buffer();
        let buffer_u8 = unsafe {
            slice::from_raw_parts(buffer.as_ptr() as *const u8, mem::size_of_val(&buffer))
        };

        // Wake up the scheme thread
        libredox::call::kill(pid, libredox::flag::SIGUSR1 as u32)?;

        hw_file.write(&buffer_u8)?;
    }
}

fn daemon(daemon: Daemon) -> anyhow::Result<()> {
    // Handle signals from the hw thread

    let new_sigaction = unsafe {
        let mut sigaction = MaybeUninit::<libc::sigaction>::uninit();
        addr_of_mut!((*sigaction.as_mut_ptr()).sa_flags).write(0);
        libc::sigemptyset(addr_of_mut!((*sigaction.as_mut_ptr()).sa_mask));
        addr_of_mut!((*sigaction.as_mut_ptr()).sa_sigaction).write(sigusr_handler as usize);
        sigaction.assume_init()
    };
    libredox::call::sigaction(flag::SIGUSR1, Some(&new_sigaction), None)?;

    let pid = libredox::call::getpid()?;

    let hw_file = Fd::open("/scheme/audiohw", flag::O_WRONLY | flag::O_CLOEXEC, 0)?;

    let socket = Socket::create("audio").context("failed to create scheme")?;

    let scheme = Arc::new(Mutex::new(AudioScheme::new()));

    // Enter a constrained namespace
    let ns = libredox::call::mkns(&[
        //IoSlice::new(b"memory"), TODO: already included, uncommenting gives EEXIST
        IoSlice::new(b"rand"), // for HashMap
    ]).context("failed to make namespace")?;
    libredox::call::setrens(ns, ns).context("failed to set namespace")?;

    // Spawn a thread to mix and send audio data
    let scheme_thread = scheme.clone();
    let _thread = thread::spawn(move || {
        libredox::call::setrens(ns, ns).unwrap();
        thread(scheme_thread, pid, hw_file)
    });

    // The scheme is now ready to accept requests, notify the original process
    daemon.ready().unwrap();

    let mut readiness = ReadinessBased::new(&socket, 16);

    loop {
        if !readiness.read_requests()? {
            break;
        }
        readiness.process_requests(|| scheme.lock().unwrap());
        readiness.poll_all_requests(|| scheme.lock().unwrap())?;
        if !readiness.write_responses()? {
            break;
        };
    }

    Ok(())
}

fn main() -> anyhow::Result<()> {
    let Err(err) = Daemon::new(|x| match daemon(x) {
        Ok(()) => {
            process::exit(0);
        }
        Err(err) => {
            eprintln!("audiod: {}", err);
            process::exit(1);
        }
    });

    eprintln!("audiod: {}", err);
    process::exit(1);
}
