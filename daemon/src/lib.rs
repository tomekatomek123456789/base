#![feature(never_type)]

use std::io::{self, PipeWriter, Read, Write};

#[must_use = "Daemon::ready must be called"]
pub struct Daemon {
    write_pipe: PipeWriter,
}

fn errno() -> io::Error {
    io::Error::last_os_error()
}

impl Daemon {
    pub fn new<F: FnOnce(Daemon) -> !>(f: F) -> io::Result<!> {
        let (mut read_pipe, write_pipe) = std::io::pipe()?;

        match unsafe { libc::fork() } {
            0 => {
                drop(read_pipe);

                f(Daemon { write_pipe })
            }
            -1 => return Err(errno()),
            _pid => {
                drop(write_pipe);

                let mut data = [0];

                read_pipe.read_exact(&mut data)?;

                unsafe { libc::_exit(data[0].into()) };
            }
        }
    }

    pub fn ready(mut self) -> io::Result<()> {
        self.write_pipe.write_all(&[0])?;

        Ok(())
    }
}
