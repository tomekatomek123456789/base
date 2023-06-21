extern crate syscall;

use std::mem::MaybeUninit;
use std::ptr::addr_of_mut;
use std::{fs, io, mem, process, slice, thread};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

use syscall::data::Packet;
use syscall::scheme::SchemeBlockMut;

use redox_daemon::Daemon;

use self::scheme::AudioScheme;

mod scheme;

fn from_syscall_error(error: syscall::Error) -> io::Error {
    io::Error::from_raw_os_error(error.errno as i32)
}

extern "C" fn sigusr_handler(_sig: usize) {}

fn thread(scheme: Arc<Mutex<AudioScheme>>, pid: usize, mut hw_file: fs::File) -> io::Result<()> {
    // Enter null namespace
    syscall::setrens(0, 0).map_err(from_syscall_error)?;

    loop {
        let buffer = scheme.lock().unwrap().buffer();
        let buffer_u8 = unsafe {
            slice::from_raw_parts(
                buffer.as_ptr() as *const u8,
                mem::size_of_val(&buffer)
            )
        };

        // Wake up the scheme thread
        syscall::kill(pid, syscall::SIGUSR1).map_err(from_syscall_error)?;

        hw_file.write(&buffer_u8)?;
    }
}

fn daemon(daemon: Daemon) -> io::Result<()> {
    // Handle signals from the hw thread

    unsafe {
        let mut sigaction = MaybeUninit::<libc::sigaction>::uninit();
        addr_of_mut!((*sigaction.as_mut_ptr()).sa_flags).write(0);
        libc::sigemptyset(addr_of_mut!((*sigaction.as_mut_ptr()).sa_mask));
        addr_of_mut!((*sigaction.as_mut_ptr()).sa_sigaction).write(sigusr_handler as usize);

        match libc::sigaction(libc::SIGUSR1, sigaction.as_ptr(), core::ptr::null_mut()) {
            0 => (),
            -1 => return Err(io::Error::last_os_error()),
            _ => unreachable!(),
        }
    }

    let pid = syscall::getpid().map_err(from_syscall_error)?;

    let hw_file = fs::OpenOptions::new().write(true).open("audiohw:")?;

    let mut scheme_file = fs::OpenOptions::new().create(true).read(true).write(true).open(":audio")?;

    let scheme = Arc::new(Mutex::new(AudioScheme::new()));

    // Spawn a thread to mix and send audio data
    let scheme_thread = scheme.clone();
    let _thread = thread::spawn(move || thread(scheme_thread, pid, hw_file));

    // Enter the null namespace - done after thread is created so
    // memory: can be accessed for stack allocation
    syscall::setrens(0, 0).map_err(from_syscall_error)?;

    // The scheme is now ready to accept requests, notify the original process
    daemon.ready().map_err(from_syscall_error)?;

    let mut todo = Vec::new();
    loop {
        let mut packet = Packet::default();
        let count = match scheme_file.read(&mut packet) {
            Ok(ok) => ok,
            Err(err) => if err.kind() == io::ErrorKind::Interrupted {
                0
            } else {
                return Err(err);
            }
        };

        if count > 0 {
            if let Some(a) = scheme.lock().unwrap().handle(&mut packet) {
                packet.a = a;
                scheme_file.write(&packet)?;
            } else {
                todo.push(packet);
            }
        }

        let mut i = 0;
        while i < todo.len() {
            if let Some(a) = scheme.lock().unwrap().handle(&mut todo[i]) {
                let mut packet = todo.remove(i);
                packet.a = a;
                scheme_file.write(&packet)?;
            } else {
                i += 1;
            }
        }
    }
}

fn main() {
    if let Err(err) = Daemon::new(|x| {
        match daemon(x) {
            Ok(()) => {
                process::exit(0);
            },
            Err(err) => {
                eprintln!("audiod: {}", err);
                process::exit(1);
            }
        }
    }) {
        eprintln!("audiod: {}", err);
        process::exit(1);
    }
}
