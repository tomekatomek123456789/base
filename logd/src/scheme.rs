use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::mem;
use std::path::PathBuf;
use std::sync::mpsc::{self, Sender};

use redox_scheme::scheme::SchemeSync;
use redox_scheme::{CallerCtx, OpenResult};
use syscall::error::*;
use syscall::schemev2::NewFdFlags;

pub enum LogHandle {
    Log {
        context: Box<str>,
        bufs: BTreeMap<usize, Vec<u8>>,
    },
    AddSink,
}

pub struct LogScheme {
    next_id: usize,
    output_tx: Sender<OutputCmd>,
    handles: BTreeMap<usize, LogHandle>,
}

enum OutputCmd {
    Log(Vec<u8>),
    AddSink(PathBuf),
}

impl LogScheme {
    pub fn new(mut files: Vec<File>) -> Self {
        let (output_tx, output_rx) = mpsc::channel::<OutputCmd>();

        std::thread::spawn(move || {
            for cmd in output_rx {
                match cmd {
                    OutputCmd::Log(line) => {
                        for file in &mut files {
                            let _ = file.write(&line);
                            let _ = file.flush();
                        }
                    }
                    OutputCmd::AddSink(sink_path) => {
                        match OpenOptions::new().write(true).open(&sink_path) {
                            Ok(file) => files.push(file),
                            Err(err) => {
                                eprintln!("logd: failed to open {:?}: {:?}", sink_path, err)
                            }
                        }
                    }
                }
            }
        });

        LogScheme {
            next_id: 0,
            output_tx,
            handles: BTreeMap::new(),
        }
    }
}

impl SchemeSync for LogScheme {
    fn open(&mut self, path: &str, _flags: usize, _ctx: &CallerCtx) -> Result<OpenResult> {
        let id = self.next_id;
        self.next_id += 1;

        if path == "add_sink" {
            self.handles.insert(id, LogHandle::AddSink);
        } else {
            self.handles.insert(
                id,
                LogHandle::Log {
                    context: path.to_string().into_boxed_str(),
                    bufs: BTreeMap::new(),
                },
            );
        }

        Ok(OpenResult::ThisScheme {
            number: id,
            flags: NewFdFlags::empty(),
        })
    }

    fn read(
        &mut self,
        id: usize,
        _buf: &mut [u8],
        _offset: u64,
        _flags: u32,
        _ctx: &CallerCtx,
    ) -> Result<usize> {
        let _handle = self.handles.get(&id).ok_or(Error::new(EBADF))?;

        // TODO

        Ok(0)
    }

    fn write(
        &mut self,
        id: usize,
        buf: &[u8],
        _offset: u64,
        _flags: u32,
        ctx: &CallerCtx,
    ) -> Result<usize> {
        let (context, bufs) = match self.handles.get_mut(&id).ok_or(Error::new(EBADF))? {
            LogHandle::Log { context, bufs } => (context, bufs),
            LogHandle::AddSink => {
                // FIXME maybe check if root

                let sink_path = PathBuf::from(
                    String::from_utf8(buf.to_owned()).map_err(|_| Error::new(EINVAL))?,
                );

                self.output_tx.send(OutputCmd::AddSink(sink_path)).unwrap();

                return Ok(buf.len());
            }
        };

        let handle_buf = bufs.entry(ctx.pid).or_insert_with(|| Vec::new());

        let mut i = 0;
        while i < buf.len() {
            let b = buf[i];

            if handle_buf.is_empty() && !context.is_empty() {
                handle_buf.extend_from_slice(context.as_bytes());
                handle_buf.extend_from_slice(b": ");
            }

            handle_buf.push(b);

            if b == b'\n' {
                self.output_tx
                    .send(OutputCmd::Log(mem::take(handle_buf)))
                    .unwrap();
            }

            i += 1;
        }

        Ok(i)
    }

    fn fcntl(&mut self, id: usize, _cmd: usize, _arg: usize, _ctx: &CallerCtx) -> Result<usize> {
        let _handle = self.handles.get(&id).ok_or(Error::new(EBADF))?;

        Ok(0)
    }

    fn fpath(&mut self, id: usize, buf: &mut [u8], _ctx: &CallerCtx) -> Result<usize> {
        let handle = self.handles.get(&id).ok_or(Error::new(EBADF))?;

        let scheme_path = b"/scheme/log/";

        let mut i = 0;
        while i < buf.len() && i < scheme_path.len() {
            buf[i] = scheme_path[i];
            i += 1;
        }

        let path_bytes = match handle {
            LogHandle::Log { context, .. } => context.as_bytes(),
            LogHandle::AddSink => b"add_sink",
        };
        let mut j = 0;
        while i < buf.len() && j < path_bytes.len() {
            buf[i] = path_bytes[j];
            i += 1;
            j += 1;
        }

        Ok(i)
    }

    fn fsync(&mut self, id: usize, _ctx: &CallerCtx) -> Result<()> {
        let _handle = self.handles.get(&id).ok_or(Error::new(EBADF))?;

        //TODO: flush remaining data?

        Ok(())
    }
}

impl LogScheme {
    pub fn on_close(&mut self, id: usize) {
        self.handles.remove(&id);
    }
}
