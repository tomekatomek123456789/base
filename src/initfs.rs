use core::convert::TryFrom;
#[allow(deprecated)]
use core::hash::{BuildHasherDefault, SipHasher};
use core::str;

use alloc::string::String;

use hashbrown::HashMap;
use redox_initfs::{types::Timespec, InitFs, Inode, InodeDir, InodeKind, InodeStruct};

use redox_path::canonicalize_to_standard;
use redox_scheme::{scheme::SchemeSync, CallerCtx, OpenResult, RequestKind};

use redox_scheme::{SignalBehavior, Socket};
use syscall::data::Stat;
use syscall::dirent::DirEntry;
use syscall::dirent::DirentBuf;
use syscall::dirent::DirentKind;
use syscall::error::*;
use syscall::flag::*;
use syscall::schemev2::NewFdFlags;

struct Handle {
    inode: Inode,
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
                let size =
                    usize::try_from(size).expect("expected u32 to be convertible into usize");
                (size, Some(size))
            }
            None => (0, None),
        }
    }
}

fn inode_len(inode: InodeStruct<'static>) -> Result<usize> {
    Ok(match inode.kind() {
        InodeKind::File(file) => file.data().map_err(|_| Error::new(EIO))?.len(),
        InodeKind::Dir(dir) => (Iter { dir, idx: 0 }).fold(0, |len, entry| {
            len + entry
                .and_then(|entry| entry.name().map_err(|_| Error::new(EIO)))
                .map_or(0, |name| name.len() + 1)
        }),
        InodeKind::Link(link) => link.data().map_err(|_| Error::new(EIO))?.len(),
        InodeKind::Unknown => return Err(Error::new(EIO)),
    })
}

impl SchemeSync for InitFsScheme {
    fn open(&mut self, path: &str, flags: usize, _ctx: &CallerCtx) -> Result<OpenResult> {
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
                    continue;
                }

                _ => (),
            }

            let current_inode_struct = Self::get_inode(&self.fs, current_inode)?;

            let dir = match current_inode_struct.kind() {
                InodeKind::Dir(dir) => dir,

                // TODO: Support symlinks in other position than xopen target
                InodeKind::Link(_) => {
                    return Err(Error::new(EOPNOTSUPP));
                }

                // If we still have more components in the path, and the file tree for that
                // particular branch is not all directories except the last, then that file cannot
                // exist.
                InodeKind::File(_) | InodeKind::Unknown => return Err(Error::new(ENOENT)),
            };

            let mut entries = Iter { dir, idx: 0 };

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

        // xopen target is link -- return EXDEV so that the file is opened as a link.
        // TODO: Maybe follow initfs-local symlinks here? Would be faster
        let is_link = matches!(
            Self::get_inode(&self.fs, current_inode)?.kind(),
            InodeKind::Link(_)
        );
        let o_symlink = flags & O_SYMLINK != 0;
        if is_link && !o_symlink {
            return Err(Error::new(EXDEV));
        }

        let id = self.next_id();
        let old = self.handles.insert(
            id,
            Handle {
                inode: current_inode,
                filename: path.into(),
            },
        );
        assert!(old.is_none());

        Ok(OpenResult::ThisScheme {
            number: id,
            flags: NewFdFlags::POSITIONED,
        })
    }

    fn read(
        &mut self,
        id: usize,
        buffer: &mut [u8],
        offset: u64,
        _fcntl_flags: u32,
        _ctx: &CallerCtx,
    ) -> Result<usize> {
        let Ok(offset) = usize::try_from(offset) else {
            return Ok(0);
        };

        let handle = self.handles.get_mut(&id).ok_or(Error::new(EBADF))?;

        match Self::get_inode(&self.fs, handle.inode)?.kind() {
            InodeKind::File(file) => {
                let data = file.data().map_err(|_| Error::new(EIO))?;
                let src_buf = &data[core::cmp::min(offset, data.len())..];

                let to_copy = core::cmp::min(src_buf.len(), buffer.len());
                buffer[..to_copy].copy_from_slice(&src_buf[..to_copy]);

                Ok(to_copy)
            }
            InodeKind::Dir(_) => Err(Error::new(EISDIR)),
            InodeKind::Link(link) => {
                let link_data = link.data().map_err(|_| Error::new(EIO))?;
                let path = core::str::from_utf8(link_data).map_err(|_| Error::new(ENOENT))?;
                let cannonical =
                    canonicalize_to_standard(Some("/"), path).ok_or_else(|| Error::new(ENOENT))?;
                let data = cannonical.as_bytes();

                let src_buf = &data[core::cmp::min(offset, data.len())..];

                let to_copy = core::cmp::min(src_buf.len(), buffer.len());
                buffer[..to_copy].copy_from_slice(&src_buf[..to_copy]);

                Ok(to_copy)
            }
            InodeKind::Unknown => Err(Error::new(EIO)),
        }
    }
    fn getdents<'buf>(
        &mut self,
        id: usize,
        mut buf: DirentBuf<&'buf mut [u8]>,
        opaque_offset: u64,
    ) -> Result<DirentBuf<&'buf mut [u8]>> {
        let Ok(offset) = u32::try_from(opaque_offset) else {
            return Ok(buf);
        };
        let handle = self.handles.get(&id).ok_or(Error::new(EBADF))?;
        let InodeKind::Dir(dir) = Self::get_inode(&self.fs, handle.inode)?.kind() else {
            return Err(Error::new(ENOTDIR));
        };
        let iter = Iter { dir, idx: offset };
        for (index, entry) in iter.enumerate() {
            let entry = entry?;
            buf.entry(DirEntry {
                // TODO: Add getter
                //inode: entry.inode(),
                inode: 0,

                name: entry
                    .name()
                    .ok()
                    .and_then(|utf8| core::str::from_utf8(utf8).ok())
                    .ok_or(Error::new(EIO))?,
                next_opaque_id: index as u64 + 1,
                kind: DirentKind::Unspecified,
            })?;
        }
        Ok(buf)
    }

    fn fsize(&mut self, id: usize, _ctx: &CallerCtx) -> Result<u64> {
        let handle = self.handles.get_mut(&id).ok_or(Error::new(EBADF))?;

        Ok(inode_len(Self::get_inode(&self.fs, handle.inode)?)? as u64)
    }

    fn fcntl(&mut self, id: usize, _cmd: usize, _arg: usize, _ctx: &CallerCtx) -> Result<usize> {
        let _handle = self.handles.get(&id).ok_or(Error::new(EBADF))?;

        Ok(0)
    }

    fn fpath(&mut self, id: usize, buf: &mut [u8], _ctx: &CallerCtx) -> Result<usize> {
        let handle = self.handles.get(&id).ok_or(Error::new(EBADF))?;

        // TODO: Copy scheme part in kernel
        let scheme_path = b"/scheme/initfs";
        let scheme_bytes = core::cmp::min(scheme_path.len(), buf.len());
        buf[..scheme_bytes].copy_from_slice(&scheme_path[..scheme_bytes]);

        let source = handle.filename.as_bytes();
        let path_bytes = core::cmp::min(buf.len() - scheme_bytes, source.len());
        buf[scheme_bytes..scheme_bytes + path_bytes].copy_from_slice(&source[..path_bytes]);

        Ok(scheme_bytes + path_bytes)
    }

    fn fstat(&mut self, id: usize, stat: &mut Stat, _ctx: &CallerCtx) -> Result<()> {
        let handle = self.handles.get(&id).ok_or(Error::new(EBADF))?;

        let Timespec { sec, nsec } = self.fs.image_creation_time();

        let inode = Self::get_inode(&self.fs, handle.inode)?;

        stat.st_mode = inode.mode()
            | match inode.kind() {
                InodeKind::Dir(_) => MODE_DIR,
                InodeKind::File(_) => MODE_FILE,
                _ => 0,
            };
        stat.st_uid = inode.uid();
        stat.st_gid = inode.gid();
        stat.st_size = u64::try_from(inode_len(inode)?).unwrap_or(u64::MAX);

        stat.st_ctime = sec.get();
        stat.st_ctime_nsec = nsec.get();
        stat.st_mtime = sec.get();
        stat.st_mtime_nsec = nsec.get();

        Ok(())
    }

    fn fsync(&mut self, id: usize, _ctx: &CallerCtx) -> Result<()> {
        if !self.handles.contains_key(&id) {
            return Err(Error::new(EBADF));
        }

        Ok(())
    }
}

pub fn run(bytes: &'static [u8], sync_pipe: usize) -> ! {
    let mut scheme = InitFsScheme::new(bytes);

    let socket = Socket::create("initfs").expect("failed to open initfs scheme socket");

    let _ = syscall::write(sync_pipe, &[0]);
    let _ = syscall::close(sync_pipe);

    loop {
        let Some(req) = socket
            .next_request(SignalBehavior::Restart)
            .expect("bootstrap: failed to read scheme request from kernel")
        else {
            break;
        };
        match req.kind() {
            RequestKind::Call(req) => {
                let resp = req.handle_sync(&mut scheme);

                if !socket
                    .write_response(resp, SignalBehavior::Restart)
                    .expect("bootstrap: failed to write scheme response to kernel")
                {
                    break;
                }
            }
            RequestKind::OnClose { id } => {
                scheme.handles.remove(&id);
            }
            _ => (),
        }
    }

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
