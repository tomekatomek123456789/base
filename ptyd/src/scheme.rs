use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;
use std::str;

use redox_scheme::scheme::SchemeSync;
use redox_scheme::{CallerCtx, OpenResult};
use syscall::data::Stat;
use syscall::error::{Error, Result, EBADF, EINVAL, ENOENT};
use syscall::flag::{EventFlags, MODE_CHR};
use syscall::schemev2::NewFdFlags;

use crate::controlterm::PtyControlTerm;
use crate::pgrp::PtyPgrp;
use crate::pty::Pty;
use crate::resource::Resource;
use crate::subterm::PtySubTerm;
use crate::termios::PtyTermios;
use crate::winsize::PtyWinsize;

pub struct PtyScheme {
    next_id: usize,
    pub handles: BTreeMap<usize, Box<dyn Resource>>,
}

impl PtyScheme {
    pub fn new() -> Self {
        PtyScheme {
            next_id: 0,
            handles: BTreeMap::new(),
        }
    }
}

impl SchemeSync for PtyScheme {
    fn open(&mut self, path: &str, flags: usize, _ctx: &CallerCtx) -> Result<OpenResult> {
        let path = path.trim_matches('/');

        if path.is_empty() {
            let id = self.next_id;
            self.next_id += 1;

            let pty = Rc::new(RefCell::new(Pty::new(id)));
            self.handles
                .insert(id, Box::new(PtyControlTerm::new(pty, flags)));

            Ok(OpenResult::ThisScheme {
                number: id,
                flags: NewFdFlags::empty(),
            })
        } else {
            let control_term_id = path.parse::<usize>().or(Err(Error::new(EINVAL)))?;
            let pty = {
                let handle = self
                    .handles
                    .get(&control_term_id)
                    .ok_or(Error::new(ENOENT))?;
                handle.pty()
            };

            let id = self.next_id;
            self.next_id += 1;

            self.handles
                .insert(id, Box::new(PtySubTerm::new(pty, flags)));

            Ok(OpenResult::ThisScheme {
                number: id,
                flags: NewFdFlags::empty(),
            })
        }
    }

    fn dup(&mut self, old_id: usize, buf: &[u8], _ctx: &CallerCtx) -> Result<OpenResult> {
        let handle: Box<dyn Resource> = {
            let old_handle = self.handles.get(&old_id).ok_or(Error::new(EBADF))?;

            if buf == b"pgrp" {
                Box::new(PtyPgrp::new(old_handle.pty(), old_handle.flags()))
            } else if buf == b"termios" {
                Box::new(PtyTermios::new(old_handle.pty(), old_handle.flags()))
            } else if buf == b"winsize" {
                Box::new(PtyWinsize::new(old_handle.pty(), old_handle.flags()))
            } else {
                return Err(Error::new(EINVAL));
            }
        };

        let id = self.next_id;
        self.next_id += 1;
        self.handles.insert(id, handle);

        Ok(OpenResult::ThisScheme {
            number: id,
            flags: NewFdFlags::empty(),
        })
    }

    fn read(
        &mut self,
        id: usize,
        buf: &mut [u8],
        _offset: u64,
        _fcntl_flags: u32,
        _ctx: &CallerCtx,
    ) -> Result<usize> {
        let handle = self.handles.get_mut(&id).ok_or(Error::new(EBADF))?;
        handle.read(buf)
    }

    fn write(
        &mut self,
        id: usize,
        buf: &[u8],
        _offset: u64,
        _fcntl_flags: u32,
        _ctx: &CallerCtx,
    ) -> Result<usize> {
        let handle = self.handles.get_mut(&id).ok_or(Error::new(EBADF))?;
        handle.write(buf)
    }

    fn fcntl(&mut self, id: usize, cmd: usize, arg: usize, _ctx: &CallerCtx) -> Result<usize> {
        let handle = self.handles.get_mut(&id).ok_or(Error::new(EBADF))?;
        handle.fcntl(cmd, arg)
    }

    fn fevent(&mut self, id: usize, _flags: EventFlags, _ctx: &CallerCtx) -> Result<EventFlags> {
        let handle = self.handles.get_mut(&id).ok_or(Error::new(EBADF))?;
        handle.fevent()
    }

    fn fpath(&mut self, id: usize, buf: &mut [u8], _ctx: &CallerCtx) -> Result<usize> {
        let handle = self.handles.get_mut(&id).ok_or(Error::new(EBADF))?;
        handle.path(buf)
    }

    fn fstat(&mut self, id: usize, stat: &mut Stat, _ctx: &CallerCtx) -> Result<()> {
        let _handle = self.handles.get(&id).ok_or(Error::new(EBADF))?;

        *stat = Stat {
            st_mode: MODE_CHR | 0o666,
            ..Default::default()
        };

        Ok(())
    }

    fn fsync(&mut self, id: usize, _ctx: &CallerCtx) -> Result<()> {
        let handle = self.handles.get_mut(&id).ok_or(Error::new(EBADF))?;
        handle.sync()
    }

    fn on_close(&mut self, id: usize) {
        self.handles.remove(&id);
    }
}
