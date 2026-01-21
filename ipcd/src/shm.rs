use redox_scheme::{scheme::SchemeSync, CallerCtx, OpenResult};
use std::{
    cmp,
    collections::{hash_map::Entry, HashMap},
    rc::Rc,
};
use syscall::{
    data::Stat, error::*, schemev2::NewFdFlags, Error, Map, MapFlags, Result, MAP_PRIVATE,
    PAGE_SIZE, PROT_READ, PROT_WRITE,
};

enum Handle {
    Shm(Rc<str>),
    SchemeRoot,
}
impl Handle {
    fn as_shm(&self) -> Option<&Rc<str>> {
        match self {
            Self::Shm(path) => Some(path),
            Self::SchemeRoot => None,
        }
    }
}

// TODO: Move to relibc
const AT_REMOVEDIR: usize = 0x200;

#[derive(Default)]
pub struct ShmHandle {
    buffer: Option<MmapGuard>,
    refs: usize,
    unlinked: bool,
}
pub struct ShmScheme {
    maps: HashMap<Rc<str>, ShmHandle>,
    handles: HashMap<usize, Handle>,
    next_id: usize,
}
impl ShmScheme {
    pub fn new() -> Self {
        Self {
            maps: HashMap::new(),
            handles: HashMap::new(),
            next_id: 0,
        }
    }
}

impl SchemeSync for ShmScheme {
    fn scheme_root(&mut self) -> Result<usize> {
        let id = self.next_id;
        self.next_id += 1;

        self.handles.insert(id, Handle::SchemeRoot);
        Ok(id)
    }
    //FIXME: Handle O_RDONLY/O_WRONLY/O_RDWR
    fn openat(
        &mut self,
        dirfd: usize,
        path: &str,
        flags: usize,
        _fcntl_flags: u32,
        _ctx: &CallerCtx,
    ) -> Result<OpenResult> {
        let handle = self.handles.get(&dirfd).ok_or(Error::new(EBADF))?;
        if !matches!(handle, Handle::SchemeRoot) {
            return Err(Error::new(EACCES));
        }

        let path = Rc::from(path);
        let entry = match self.maps.entry(Rc::clone(&path)) {
            Entry::Occupied(e) => {
                if flags & syscall::O_EXCL != 0 && flags & syscall::O_CREAT != 0 {
                    return Err(Error::new(EEXIST));
                }
                e.into_mut()
            }
            Entry::Vacant(e) => {
                if flags & syscall::O_CREAT == 0 {
                    return Err(Error::new(ENOENT));
                }
                e.insert(ShmHandle::default())
            }
        };
        entry.refs += 1;
        self.handles.insert(self.next_id, Handle::Shm(path));

        let id = self.next_id;
        self.next_id += 1;
        Ok(OpenResult::ThisScheme {
            number: id,
            flags: NewFdFlags::POSITIONED,
        })
    }
    fn fpath(&mut self, id: usize, buf: &mut [u8], _ctx: &CallerCtx) -> Result<usize> {
        // Write scheme name
        const PREFIX: &[u8] = b"/scheme/shm/";
        let len = cmp::min(PREFIX.len(), buf.len());
        buf[..len].copy_from_slice(&PREFIX[..len]);
        if len < PREFIX.len() {
            return Ok(len);
        }

        // Write path
        let path = self
            .handles
            .get(&id)
            .and_then(Handle::as_shm)
            .ok_or(Error::new(EBADF))?;
        let len = cmp::min(path.len(), buf.len() - PREFIX.len());
        buf[PREFIX.len()..][..len].copy_from_slice(&path.as_bytes()[..len]);

        Ok(PREFIX.len() + len)
    }
    fn on_close(&mut self, id: usize) {
        let Handle::Shm(path) = self.handles.remove(&id).unwrap() else {
            return;
        };
        let mut entry = match self.maps.entry(path) {
            Entry::Occupied(entry) => entry,
            Entry::Vacant(_) => panic!("handle pointing to nothing"),
        };
        entry.get_mut().refs -= 1;
        if entry.get().refs == 0 && entry.get().unlinked {
            // There is no other reference to this entry, drop
            entry.remove_entry();
        }
    }
    fn unlinkat(&mut self, dirfd: usize, path: &str, flags: usize, _ctx: &CallerCtx) -> Result<()> {
        let handle = self.handles.get(&dirfd).ok_or(Error::new(EBADF))?;
        if !matches!(handle, Handle::SchemeRoot) {
            return Err(Error::new(EACCES));
        }
        if flags & AT_REMOVEDIR == AT_REMOVEDIR {
            return Err(Error::new(ENOTDIR));
        }
        let path = Rc::from(path);
        let mut entry = match self.maps.entry(Rc::clone(&path)) {
            Entry::Occupied(e) => e,
            Entry::Vacant(_) => return Err(Error::new(ENOENT)),
        };

        entry.get_mut().unlinked = true;
        if entry.get().refs == 0 {
            // There is no other reference to this entry, drop
            entry.remove_entry();
        }
        Ok(())
    }
    fn fstat(&mut self, id: usize, stat: &mut Stat, _ctx: &CallerCtx) -> Result<()> {
        let path = self
            .handles
            .get(&id)
            .and_then(Handle::as_shm)
            .ok_or(Error::new(EBADF))?;
        let size = match self
            .maps
            .get(path)
            .expect("handle pointing to nothing")
            .buffer
        {
            Some(ref map) => map.len(),
            None => 0,
        };

        //TODO: fill in more items?
        *stat = Stat {
            st_mode: syscall::MODE_FILE,
            st_size: size as _,
            ..Default::default()
        };

        Ok(())
    }
    fn ftruncate(&mut self, id: usize, len: u64, _ctx: &CallerCtx) -> Result<()> {
        let path = self
            .handles
            .get(&id)
            .and_then(Handle::as_shm)
            .ok_or(Error::new(EBADF))?;
        match self
            .maps
            .get_mut(path)
            .expect("handle pointing to nothing")
            .buffer
        {
            Some(_) => {
                //TODO: Reallocating is unsafe here as we are mixing ftruncate with mmap
                //      which requires the memory to be contiguous.
                Err(Error::new(EIO))
            }
            ref mut buf @ None => {
                *buf = Some(MmapGuard::alloc(len as usize)?);
                Ok(())
            }
        }
    }
    fn mmap_prep(
        &mut self,
        id: usize,
        offset: u64,
        size: usize,
        _flags: MapFlags,
        _ctx: &CallerCtx,
    ) -> Result<usize> {
        let path = self
            .handles
            .get(&id)
            .and_then(Handle::as_shm)
            .ok_or(Error::new(EBADF))?;
        let total_size = offset as usize + size;
        match self
            .maps
            .get_mut(path)
            .expect("handle pointing to nothing")
            .buffer
        {
            Some(ref mut buf) => {
                if total_size > buf.len() {
                    return Err(Error::new(ERANGE));
                }
                Ok(buf.as_ptr() + offset as usize)
            }
            //TODO: this should be only handled by ftruncate
            ref mut buf @ None => {
                *buf = Some(MmapGuard::alloc(size)?);
                Ok(buf.as_mut().unwrap().as_ptr() + offset as usize)
            }
        }
    }
    fn read(
        &mut self,
        id: usize,
        buf: &mut [u8],
        offset: u64,
        _fcntl_flags: u32,
        _ctx: &CallerCtx,
    ) -> Result<usize> {
        let path = self
            .handles
            .get(&id)
            .and_then(Handle::as_shm)
            .ok_or(Error::new(EBADF))?;
        match self
            .maps
            .get_mut(path)
            .expect("handle pointing to nothing")
            .buffer
        {
            Some(ref mut map) => map.read(offset as usize, buf),
            None => Err(Error::new(ERANGE)),
        }
    }
    fn write(
        &mut self,
        id: usize,
        buf: &[u8],
        offset: u64,
        _fcntl_flags: u32,
        _ctx: &CallerCtx,
    ) -> Result<usize> {
        let path = self
            .handles
            .get(&id)
            .and_then(Handle::as_shm)
            .ok_or(Error::new(EBADF))?;
        match self
            .maps
            .get_mut(path)
            .expect("handle pointing to nothing")
            .buffer
        {
            Some(ref mut map) => map.write(offset as usize, buf),
            None => Err(Error::new(ERANGE)),
        }
    }
}

pub struct MmapGuard {
    base: usize,
    size: usize,
    // user specified, non-aligned size
    len: usize,
}
impl MmapGuard {
    pub fn alloc(len: usize) -> Result<Self> {
        let page_count = len.div_ceil(PAGE_SIZE);
        let size = page_count * PAGE_SIZE;
        let base = unsafe {
            syscall::fmap(
                !0,
                &Map {
                    offset: 0,
                    size,
                    flags: MAP_PRIVATE | PROT_READ | PROT_WRITE,
                    address: 0,
                },
            )
        }?;

        Ok(Self { base, size, len })
    }
    pub fn len(&self) -> usize {
        self.size
    }
    pub fn as_ptr(&self) -> usize {
        self.base
    }
    pub fn read(&self, offset: usize, buf: &mut [u8]) -> Result<usize> {
        let read_len = buf.len();
        let end = offset
            .checked_add(read_len)
            .ok_or_else(|| Error::new(ERANGE))
            .map(|f| cmp::min(f, self.len))?;

        if offset > self.len {
            return Err(Error::new(EINVAL));
        }

        unsafe {
            let src_ptr = (self.base as *const u8).add(offset);
            let dst_ptr = buf.as_mut_ptr();
            core::ptr::copy_nonoverlapping(src_ptr, dst_ptr, end - offset);
        }

        Ok(end - offset)
    }
    pub fn write(&mut self, offset: usize, buf: &[u8]) -> Result<usize> {
        let write_len = buf.len();
        let end = offset
            .checked_add(write_len)
            .ok_or_else(|| Error::new(ERANGE))?;

        if end > self.len {
            return Err(Error::new(EINVAL));
        }

        unsafe {
            let src_ptr = buf.as_ptr();
            let dst_ptr = (self.base as *mut u8).add(offset);
            core::ptr::copy_nonoverlapping(src_ptr, dst_ptr, write_len);
        }

        Ok(write_len)
    }
}
impl Drop for MmapGuard {
    fn drop(&mut self) {
        if self.size == 0 {
            return;
        }
        let _ = unsafe { syscall::funmap(self.base, self.size) };
    }
}
