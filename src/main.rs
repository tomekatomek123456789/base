#![feature(try_reserve)]

use std::fs::File;
use std::io::prelude::*;
use std::{env, io, process};

use syscall::{Packet, SchemeMut};

mod filesystem;
mod scheme;

use self::scheme::Scheme;

fn main() {
    let scheme_name = env::args().nth(1).expect("Usage:\n\tramfs SCHEME_NAME");

    redox_daemon::Daemon::new(move |daemon| {
        let mut socket =
            File::create(format!(":{}", scheme_name)).expect("ramfs: failed to create socket");

        let mut scheme = Scheme::new(scheme_name).expect("ramfs: failed to initialize scheme");

        syscall::setrens(0, 0).expect("ramfs: failed to enter null namespace");

        daemon.ready().expect("ramfs: failed to mark daemon as ready");

        'packet_loop: loop {
            let mut packet = Packet::default();

            match socket.read(&mut packet) {
                Ok(0) => break 'packet_loop,
                Ok(_) => (),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue 'packet_loop,
                Err(error) => panic!("ramfs: failed to read from socket: {:?}", error),
            }

            scheme.handle(&mut packet);

            match socket.write(&packet) {
                Ok(_) => (),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue 'packet_loop,
                Err(error) => panic!("ramfs: failed to write to socket: {:?}", error),
            }
        }

        process::exit(0);
    }).expect("ramfs: failed to create daemon");
}
