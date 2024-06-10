use core::convert::TryFrom;
#[allow(deprecated)]
use core::hash::{BuildHasherDefault, SipHasher};
use core::str;

use alloc::string::String;

use hashbrown::HashMap;
use redox_initfs::{InitFs, InodeStruct, Inode, InodeDir, InodeKind, types::Timespec};

use redox_scheme::OpenResult;
use redox_scheme::RequestKind;
use redox_scheme::SchemeV2;

use redox_scheme::SignalBehavior;
use redox_scheme::Socket;
use redox_scheme::V2;
use syscall::data::Stat;
use syscall::error::*;
use syscall::flag::*;

struct Handle {
    inode: Inode,
    seek: usize,
    // TODO: Any better way to implement fpath? Or maybe work around it, e.g. by giving paths such
    // as `initfs:__inodes__/<inode>`?
    filename: String,
}
pub struct InitFsScheme {
    #[allow(deprecated)]
    handles: HashMap<usize, Handle, BuildHasherDefault<SipHasher>>,
    next_id: usize,
    fs: InitFs<'static>,
}
impl InitFsScheme {
    pub fn new(bytes: &'static [u8]) -> Self {
        Self {
            handles: HashMap::default(),
            next_id: 0,
            fs: InitFs::new(bytes).expect("failed to parse initfs"),
        }
    }

    fn get_inode(fs: &InitFs<'static>, inode: Inode) -> Result<InodeStruct<'static>> {
        fs.get_inode(inode).ok_or_else(|| Error::new(EIO))
    }
    fn next_id(&mut self) -> usize {
        assert_ne!(self.next_id, usize::MAX, "usize overflow in initfs scheme");
        self.next_id += 1;
        self.next_id
    }
}


struct Iter {
    dir: InodeDir<'static>,
    idx: u32,
}
impl Iterator for Iter {
    type Item = Result<redox_initfs::Entry<'static>>;

    fn next(&mut self) -> Option<Self::Item> {
        let entry = self.dir.get_entry(self.idx).map_err(|_| Error::new(EIO));
        self.idx += 1;
        entry.transpose()
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        match self.dir.entry_count().ok() {
            Some(size) => {
                let size = usize::try_from(size).expect("expected u32 to be convertible into usize");
                (size, Some(size))
            }
            None => (0, None),
        }
    }
}

fn inode_len(inode: InodeStruct<'static>) -> Result<usize> {
    Ok(match inode.kind() {
        InodeKind::File(file) => file.data().map_err(|_| Error::new(EIO))?.len(),
        InodeKind::Dir(dir) => (Iter { dir, idx: 0 })
            .fold(0, |len, entry| len + entry.and_then(|entry| entry.name().map_err(|_| Error::new(EIO))).map_or(0, |name| name.len() + 1)),
        InodeKind::Unknown => return Err(Error::new(EIO)),
    })
}

impl SchemeV2 for InitFsScheme {
    fn open(&mut self, path: &str, _flags: usize) -> Result<OpenResult> {
        let mut components = path
            // trim leading and trailing slash
            .trim_matches('/')
            // divide into components
            .split('/')
            // filter out double slashes (e.g. /usr//bin/...)
            .filter(|c| !c.is_empty());

        let mut current_inode = InitFs::ROOT_INODE;

        while let Some(component) = components.next() {
            match component {
                "." => continue,
                ".." => {
                    let _ = components.next_back();
                    continue
                }

                _ => (),
            }

            let current_inode_struct = Self::get_inode(&self.fs, current_inode)?;

            let dir = match current_inode_struct.kind() {
                InodeKind::Dir(dir) => dir,

                // If we still have more components in the path, and the file tree for that
                // particular branch is not all directories except the last, then that file cannot
                // exist.
                InodeKind::File(_) | InodeKind::Unknown => return Err(Error::new(ENOENT)),
            };

            let mut entries = Iter {
                dir,
                idx: 0,
            };

            current_inode = loop {
                let entry_res = match entries.next() {
                    Some(e) => e,
                    None => return Err(Error::new(ENOENT)),
                };
                let entry = entry_res?;
                let name = entry.name().map_err(|_| Error::new(EIO))?;
                if name == component.as_bytes() {
                    break entry.inode();
                }
            };
        }

        let id = self.next_id();
        let old = self.handles.insert(id, Handle {
            inode: current_inode,
            seek: 0_usize,
            filename: path.into(),
        });
        assert!(old.is_none());

        Ok(OpenResult::ThisScheme { number: id })
    }

    fn read(&mut self, id: usize, mut buffer: &mut [u8]) -> Result<usize> {
        let handle = self.handles.get_mut(&id).ok_or(Error::new(EBADF))?;

        match Self::get_inode(&self.fs, handle.inode)?.kind() {
            InodeKind::Dir(dir) => {
                let mut bytes_read = 0;
                let mut total_to_skip = handle.seek;

                for entry_res in (Iter { dir, idx: 0 }) {
                    let entry = entry_res?;
                    let name = entry.name().map_err(|_| Error::new(EIO))?;

                    let to_skip = core::cmp::min(total_to_skip, name.len() + 1);
                    if to_skip == name.len() + 1 { continue; }

                    let name = &name[to_skip..];

                    let to_copy = core::cmp::min(name.len(), buffer.len());
                    buffer[..to_copy].copy_from_slice(&name[..to_copy]);
                    bytes_read += to_copy;
                    buffer = &mut buffer[to_copy..];

                    if !buffer.is_empty() {
                        buffer[0] = b'\n';
                        bytes_read += 1;
                        buffer = &mut buffer[1..];
                    }

                    total_to_skip -= to_skip;
                }

                handle.seek = handle.seek.saturating_add(bytes_read);

                Ok(bytes_read)
            }
            InodeKind::File(file) => {
                let data = file.data().map_err(|_| Error::new(EIO))?;
                let src_buf = &data[core::cmp::min(handle.seek, data.len())..];

                let to_copy = core::cmp::min(src_buf.len(), buffer.len());
                buffer[..to_copy].copy_from_slice(&src_buf[..to_copy]);

                handle.seek = handle.seek.checked_add(to_copy).ok_or(Error::new(EOVERFLOW))?;

                Ok(to_copy)
            }
            InodeKind::Unknown => return Err(Error::new(EIO)),
        }
    }

    fn seek(&mut self, id: usize, pos: i64, whence: usize) -> Result<u64> {
        let handle = self.handles.get_mut(&id).ok_or(Error::new(EBADF))?;

        let new_offset = redox_scheme::calc_seek_offset_usize(handle.seek, pos as isize, whence, inode_len(Self::get_inode(&self.fs, handle.inode)?)?)?;
        handle.seek = new_offset as usize;
        Ok(new_offset as u64)
    }

    fn fcntl(&mut self, id: usize, _cmd: usize, _arg: usize) -> Result<usize> {
        let _handle = self.handles.get(&id).ok_or(Error::new(EBADF))?;

        Ok(0)
    }

    fn fpath(&mut self, id: usize, buf: &mut [u8]) -> Result<usize> {
        let handle = self.handles.get(&id).ok_or(Error::new(EBADF))?;

        // TODO: Copy scheme part in kernel
        let scheme_path = b"initfs:";
        let scheme_bytes = core::cmp::min(scheme_path.len(), buf.len());
        buf[..scheme_bytes].copy_from_slice(&scheme_path[..scheme_bytes]);

        let source = handle.filename.as_bytes();
        let path_bytes = core::cmp::min(buf.len() - scheme_bytes, source.len());
        buf[scheme_bytes..scheme_bytes + path_bytes].copy_from_slice(&source[..path_bytes]);

        Ok(scheme_bytes + path_bytes)
    }

    fn fstat(&mut self, id: usize, stat: &mut Stat) -> Result<usize> {
        let handle = self.handles.get(&id).ok_or(Error::new(EBADF))?;

        let Timespec { sec, nsec } = self.fs.image_creation_time();

        let inode = Self::get_inode(&self.fs, handle.inode)?;

        stat.st_mode = inode.mode() | match inode.kind() { InodeKind::Dir(_) => MODE_DIR, InodeKind::File(_) => MODE_FILE, _ => 0 };
        stat.st_uid = inode.uid();
        stat.st_gid = inode.gid();
        stat.st_size = u64::try_from(inode_len(inode)?).unwrap_or(u64::MAX);

        stat.st_ctime = sec.get();
        stat.st_ctime_nsec = nsec.get();
        stat.st_mtime = sec.get();
        stat.st_mtime_nsec = nsec.get();

        Ok(0)
    }

    fn fsync(&mut self, id: usize) -> Result<()> {
        if !self.handles.contains_key(&id) {
            return Err(Error::new(EBADF));
        }

        Ok(())
    }

    fn close(&mut self, id: usize) -> Result<()> {
        let _ = self.handles.remove(&id).ok_or(Error::new(EBADF))?;
        Ok(())
    }
}

pub fn run(bytes: &'static [u8], sync_pipe: usize) -> ! {
    let mut scheme = InitFsScheme::new(bytes);

    let socket = Socket::<V2>::create("initfs")
        .expect("failed to open initfs scheme socket");

    let _ = syscall::write(sync_pipe, &[0]);
    let _ = syscall::close(sync_pipe);

    loop {
        let RequestKind::Call(req) = (match socket.next_request(SignalBehavior::Restart).expect("bootstrap: failed to read scheme request from kernel") {
            Some(req) => req.kind(),
            None => break,
        }) else {
            continue;
        };
        let resp = req.handle_scheme_mut(&mut scheme);

        if !socket.write_response(resp, SignalBehavior::Restart).expect("bootstrap: failed to write scheme response to kernel") {
            break;
        }
    }

    syscall::exit(0).expect("initfs: failed to exit");
    unreachable!()
}

// TODO: Restructure bootstrap so it calls into relibc, or a split-off derivative without the C
// parts, such as "redox-rt".

#[no_mangle]
pub unsafe extern "C" fn redox_read_v1(fd: usize, ptr: *mut u8, len: usize) -> isize {
    Error::mux(syscall::read(fd, core::slice::from_raw_parts_mut(ptr, len))) as isize
}

#[no_mangle]
pub unsafe extern "C" fn redox_write_v1(fd: usize, ptr: *const u8, len: usize) -> isize {
    Error::mux(syscall::write(fd, core::slice::from_raw_parts(ptr, len))) as isize
}

#[no_mangle]
pub unsafe extern "C" fn redox_open_v1(ptr: *const u8, len: usize, flags: usize) -> isize {
    Error::mux(syscall::open(core::str::from_raw_parts(ptr, len), flags)) as isize
}

#[no_mangle]
pub extern "C" fn redox_close_v1(fd: usize) -> isize {
    Error::mux(syscall::close(fd)) as isize
}
