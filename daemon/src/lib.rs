#![feature(never_type)]

use std::io;

#[must_use = "Daemon::ready must be called"]
pub struct Daemon {
    write_pipe: libc::c_int,
}

fn errno() -> io::Error {
    io::Error::last_os_error()
}

impl Daemon {
    pub fn new<F: FnOnce(Daemon) -> !>(f: F) -> io::Result<!> {
        let mut pipes = [0; 2];

        match unsafe { libc::pipe(pipes.as_mut_ptr()) } {
            0 => (),
            -1 => return Err(errno()),
            _ => unreachable!(),
        }

        let [read_pipe, write_pipe] = pipes;

        match unsafe { libc::fork() } {
            0 => {
                let _ = unsafe { libc::close(read_pipe) };

                f(Daemon { write_pipe })
            }
            -1 => return Err(errno()),
            _pid => {
                let _ = unsafe { libc::close(write_pipe) };

                let mut data = [0];

                let res = loop {
                    match unsafe { libc::read(read_pipe, data.as_mut_ptr().cast(), data.len()) } {
                        -1 if errno().kind() == io::ErrorKind::Interrupted => continue,
                        -1 => break Err(errno()),

                        count => break Ok(count as usize),
                    }
                };

                let _ = unsafe { libc::close(read_pipe) };

                if res? == 1 {
                    unsafe { libc::_exit(data[0].into()) };
                } else {
                    Err(io::Error::from_raw_os_error(libc::EIO))
                }
            }
        }
    }

    pub fn ready(self) -> io::Result<()> {
        let res;

        unsafe {
            let src = [0_u8];
            res = loop {
                match libc::write(self.write_pipe, src.as_ptr().cast(), src.len()) {
                    -1 if errno().kind() == io::ErrorKind::Interrupted => continue,
                    -1 => break Err(errno()),
                    count => break Ok(count),
                }
            };
            let _ = libc::close(self.write_pipe);
        }

        if res? == 1 {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(libc::EIO))
        }
    }
}
