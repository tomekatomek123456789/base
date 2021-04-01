#![feature(try_reserve)]

use std::fs::File;
use std::io::prelude::*;
use std::{env, io};

use syscall::{CloneFlags, Packet, SchemeMut};

mod filesystem;
mod scheme;

use self::scheme::Scheme;

fn main() {
    let scheme_name = env::args().nth(1).expect("Usage:\n\tramfs SCHEME_NAME");

    if unsafe { syscall::clone(CloneFlags::empty()) }.expect("ramfs: failed to fork") != 0 {
        return;
    }

    let mut socket =
        File::create(format!(":{}", scheme_name)).expect("ramfs: failed to create socket");
    let mut scheme = Scheme::new(scheme_name).expect("ramfs: failed to initialize scheme");

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
}
