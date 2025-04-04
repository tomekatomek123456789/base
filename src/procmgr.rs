use core::cell::RefCell;
use core::cmp;
use core::hash::BuildHasherDefault;
use core::mem::size_of;
use core::num::{NonZeroU8, NonZeroUsize};
use core::ops::Deref;
use core::ptr::NonNull;
use core::sync::atomic::Ordering;
use core::task::Poll;
use core::task::Poll::*;

use alloc::collections::btree_map::BTreeMap;
use alloc::collections::VecDeque;
use alloc::rc::{Rc, Weak};
use alloc::vec;
use alloc::vec::Vec;

use hashbrown::hash_map::{Entry, OccupiedEntry, VacantEntry};
use hashbrown::{DefaultHashBuilder, HashMap, HashSet};

use redox_rt::proc::FdGuard;
use redox_rt::protocol::{ProcCall, ProcKillTarget, ProcMeta, ThreadCall, WaitFlags};
use redox_scheme::scheme::{IntoTag, Op, OpCall};
use redox_scheme::{
    CallerCtx, Id, OpenResult, Request, RequestKind, Response, SendFdRequest, SignalBehavior,
    Socket, Tag,
};
use slab::Slab;
use syscall::schemev2::NewFdFlags;
use syscall::{
    sig_bit, ContextStatus, ContextVerb, Error, Event, EventFlags, FobtainFdFlags, MapFlags,
    ProcSchemeAttrs, Result, RtSigInfo, SenderInfo, SetSighandlerData, SigProcControl, Sigcontrol,
    EAGAIN, EBADF, EBADFD, ECHILD, EEXIST, EINTR, EINVAL, EIO, ENOENT, ENOSYS, EOPNOTSUPP, EPERM,
    ESRCH, EWOULDBLOCK, O_CLOEXEC, O_CREAT, PAGE_SIZE, SIGCHLD, SIGCONT, SIGKILL, SIGSTOP, SIGTSTP,
    SIGTTIN, SIGTTOU,
};

pub fn run(write_fd: usize, auth: &FdGuard) {
    let socket = Socket::nonblock("proc").expect("failed to open proc scheme socket");

    // TODO?
    let socket_ident = socket.inner().raw();

    let queue = RawEventQueue::new().expect("failed to create event queue");

    queue
        .subscribe(socket.inner().raw(), socket_ident, EventFlags::EVENT_READ)
        .expect("failed to listen to scheme socket events");

    let mut scheme = ProcScheme::new(auth, &queue);

    log::info!("process manager started");
    let _ = syscall::write(write_fd, &[0]);
    let _ = syscall::close(write_fd);

    let mut states = HashMap::<Id, PendingState, DefaultHashBuilder>::new();
    let mut awoken = VecDeque::<Id>::new();
    let mut new_awoken = VecDeque::new();

    'outer: loop {
        log::trace!("AWOKEN {awoken:#?}");
        while !awoken.is_empty() || !new_awoken.is_empty() {
            awoken.append(&mut new_awoken);
            for awoken in awoken.drain(..) {
                //log::trace!("ALL STATES {states:#?}, AWOKEN {awoken:#?}");
                let Entry::Occupied(state) = states.entry(awoken) else {
                    continue;
                };
                match scheme.work_on(state, &mut new_awoken) {
                    Ready(resp) => {
                        loop {
                            match socket.write_response(resp, SignalBehavior::Interrupt) {
                                Ok(false) => break 'outer,
                                Ok(_) => break,
                                Err(err) if err.errno == EINTR => continue,
                                Err(err) => {
                                    panic!("bootstrap: failed to write scheme response to kernel: {err}")
                                }
                            }
                        }
                    }
                    Pending => continue,
                }
            }
        }
        // TODO: multiple events?
        let event = queue.next_event().expect("failed to get next event");

        if event.data == socket_ident {
            'reqs: loop {
                let req = loop {
                    match socket.next_request(SignalBehavior::Interrupt) {
                        Ok(None) => break 'outer,
                        Ok(Some(req)) => break req,
                        Err(e) if e.errno == EINTR => continue,
                        // spurious event
                        Err(e) if e.errno == EWOULDBLOCK || e.errno == EAGAIN => break 'reqs,
                        Err(other) => {
                            panic!("bootstrap: failed to read scheme request from kernel: {other}")
                        }
                    }
                };
                log::trace!("REQ{req:#?}");
                let Ready(resp) =
                    handle_scheme(req, &socket, &mut scheme, &mut states, &mut awoken)
                else {
                    continue 'reqs;
                };
                loop {
                    match socket.write_response(resp, SignalBehavior::Interrupt) {
                        Ok(false) => break 'outer,
                        Ok(_) => break,
                        Err(err) if err.errno == EINTR => continue,
                        Err(err) => {
                            panic!("bootstrap: failed to write scheme response to kernel: {err}")
                        }
                    }
                }
            }
        } else if let Some(thread) = scheme.thread_lookup.get(&event.data) {
            let Some(thread_rc) = thread.upgrade() else {
                log::trace!("DEAD THREAD EVENT FROM {}", event.data,);
                continue;
            };
            let thread = thread_rc.borrow();
            let Some(proc_rc) = scheme.processes.get(&thread.pid) else {
                // TODO?
                continue;
            };
            let mut proc = proc_rc.borrow_mut();
            log::trace!("THREAD EVENT FROM {}, {}", event.data, thread.pid.0);
            let mut buf = 0_usize.to_ne_bytes();
            let _ = syscall::read(*thread.status_hndl, &mut buf).unwrap();
            let status = usize::from_ne_bytes(buf);

            log::trace!("STATUS {status}");

            if status != ContextStatus::Dead as usize {
                // spurious event
                continue;
            }
            scheme.thread_lookup.remove(&event.data);
            proc.threads.retain(|rc| !Rc::ptr_eq(rc, &thread_rc));

            if matches!(proc.status, ProcessStatus::Exiting { .. }) {
                log::trace!("WAKING UP {}", proc.awaiting_threads_term.len(),);
                awoken.extend(proc.awaiting_threads_term.drain(..)); // TODO: inefficient
            } else {
                todo!("handle proc termination without explicit exit");
            }
        } else {
            log::warn!("TODO: UNKNOWN EVENT");
        }
    }

    unreachable!()
}
fn handle_scheme<'a>(
    req: Request,
    socket: &'a Socket,
    scheme: &mut ProcScheme<'a>,
    states: &mut HashMap<Id, PendingState>,
    awoken: &mut VecDeque<Id>,
) -> Poll<Response> {
    match req.kind() {
        RequestKind::Call(req) => {
            let req_id = req.request_id();
            let op = match req.op() {
                Ok(op) => op,
                Err(req) => return Response::ready_err(ENOSYS, req),
            };
            match op {
                Op::Open(op) => Ready(Response::open_dup_like(
                    scheme.on_open(op.path(), op.flags),
                    op,
                )),
                Op::Dup(op) => Ready(Response::open_dup_like(scheme.on_dup(op.fd, op.buf()), op)),
                Op::Read(mut op) => Ready(Response::new(scheme.on_read(op.fd, op.buf()), op)),
                Op::Call(op) => scheme.on_call(
                    {
                        // TODO: cleanup
                        states.remove(&req_id);
                        if let Entry::Vacant(entry) = states.entry(req_id) {
                            entry
                        } else {
                            unreachable!()
                        }
                    },
                    op,
                    awoken,
                ),
                _ => {
                    log::trace!("UNKNOWN: {op:?}");
                    Ready(Response::new(Err(Error::new(ENOSYS)), op))
                }
            }
        }
        RequestKind::SendFd(req) => Ready(scheme.on_sendfd(socket, req)),

        // ignore
        _ => Pending,
    }
}
#[derive(Debug)]
enum PendingState {
    AwaitingStatusChange {
        waiter: ProcessId,
        target: WaitpidTarget,
        flags: WaitFlags,
        op: OpCall,
    },
    AwaitingThreadsTermination(ProcessId, Tag),
    Placeholder,
}
impl IntoTag for PendingState {
    fn into_tag(self) -> Tag {
        match self {
            Self::AwaitingThreadsTermination(_, tag) => tag,
            Self::AwaitingStatusChange { op, .. } => op.into_tag(),
            Self::Placeholder => unreachable!(),
        }
    }
}

#[derive(Debug)]
pub struct Page<T> {
    ptr: NonNull<T>,
    off: u16,
}
impl<T> Page<T> {
    pub fn map(fd: &FdGuard, req_offset: usize, displacement: u16) -> Result<Self> {
        Ok(Self {
            off: displacement,
            ptr: NonNull::new(unsafe {
                syscall::fmap(
                    **fd,
                    &syscall::Map {
                        offset: req_offset,
                        size: PAGE_SIZE,
                        flags: MapFlags::PROT_READ | MapFlags::PROT_WRITE | MapFlags::MAP_SHARED,
                        address: 0,
                    },
                )? as *mut T
            })
            .unwrap(),
        })
    }
}
impl<T> Deref for Page<T> {
    type Target = T;

    fn deref(&self) -> &T {
        unsafe { &*self.ptr.as_ptr().byte_add(self.off.into()) }
    }
}
impl<T> Drop for Page<T> {
    fn drop(&mut self) {
        unsafe {
            let _ = syscall::funmap(self.ptr.as_ptr() as usize, PAGE_SIZE);
        }
    }
}

#[derive(Debug)]
struct Process {
    threads: Vec<Rc<RefCell<Thread>>>,
    ppid: ProcessId,
    pgid: ProcessId,
    sid: ProcessId,

    ruid: u32,
    euid: u32,
    suid: u32,
    rgid: u32,
    egid: u32,
    sgid: u32,
    rns: u32,
    ens: u32,

    status: ProcessStatus,

    awaiting_threads_term: Vec<Id>,

    waitpid: BTreeMap<WaitpidKey, (ProcessId, WaitpidStatus)>,
    waitpid_waiting: VecDeque<Id>,

    sig_pctl: Option<Page<SigProcControl>>,
    rtqs: Vec<VecDeque<RtSigInfo>>,
}
#[derive(Copy, Clone, Debug)]
pub struct WaitpidKey {
    pub pid: Option<ProcessId>,
    pub pgid: Option<ProcessId>,
}

// TODO: Is this valid? (transitive?)
impl Ord for WaitpidKey {
    fn cmp(&self, other: &WaitpidKey) -> cmp::Ordering {
        // If both have pid set, compare that
        if let Some(s_pid) = self.pid {
            if let Some(o_pid) = other.pid {
                return s_pid.cmp(&o_pid);
            }
        }

        // If both have pgid set, compare that
        if let Some(s_pgid) = self.pgid {
            if let Some(o_pgid) = other.pgid {
                return s_pgid.cmp(&o_pgid);
            }
        }

        // If either has pid set, it is greater
        if self.pid.is_some() {
            return cmp::Ordering::Greater;
        }

        if other.pid.is_some() {
            return cmp::Ordering::Less;
        }

        // If either has pgid set, it is greater
        if self.pgid.is_some() {
            return cmp::Ordering::Greater;
        }

        if other.pgid.is_some() {
            return cmp::Ordering::Less;
        }

        // If all pid and pgid are None, they are equal
        cmp::Ordering::Equal
    }
}

impl PartialOrd for WaitpidKey {
    fn partial_cmp(&self, other: &WaitpidKey) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for WaitpidKey {
    fn eq(&self, other: &WaitpidKey) -> bool {
        self.cmp(other) == cmp::Ordering::Equal
    }
}

impl Eq for WaitpidKey {}
#[derive(Debug, Clone, Copy)]
enum ProcessStatus {
    PossiblyRunnable,
    Stopped(usize),
    Exiting {
        signal: Option<NonZeroU8>,
        status: u8,
    },
    Exited {
        signal: Option<NonZeroU8>,
        status: u8,
    },
}
#[derive(Debug)]
struct Thread {
    fd: FdGuard,
    status_hndl: FdGuard,
    pid: ProcessId,
    sig_ctrl: Option<Page<Sigcontrol>>,
}
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct ProcessId(usize);

const INIT_PID: ProcessId = ProcessId(1);

struct ProcScheme<'a> {
    processes: HashMap<ProcessId, Rc<RefCell<Process>>, DefaultHashBuilder>,
    sessions: HashSet<ProcessId, DefaultHashBuilder>,
    handles: Slab<Handle>,

    thread_lookup: HashMap<usize, Weak<RefCell<Thread>>>,

    init_claimed: bool,
    next_id: ProcessId,

    queue: &'a RawEventQueue,
    auth: &'a FdGuard,
}
#[derive(Clone, Copy, Debug)]
enum WaitpidStatus {
    Continued,
    Stopped {
        signal: NonZeroU8,
    },
    Terminated {
        signal: Option<NonZeroU8>,
        status: u8,
    },
}

#[derive(Debug)]
enum Handle {
    Init,
    Proc(ProcessId),
    Thread(Rc<RefCell<Thread>>),
}

#[derive(Clone, Copy, Debug)]
enum WaitpidTarget {
    SingleProc(ProcessId),
    ProcGroup(ProcessId),
    AnyChild,
    AnyGroupMember,
}
// TODO: Add 'syscall' backend for redox-event so it can act both as library-ABI frontend and
// backend
struct RawEventQueue(FdGuard);
impl RawEventQueue {
    pub fn new() -> Result<Self> {
        syscall::open("/scheme/event", O_CREAT)
            .map(FdGuard::new)
            .map(Self)
    }
    pub fn subscribe(&self, fd: usize, ident: usize, flags: EventFlags) -> Result<()> {
        let _ = syscall::write(
            *self.0,
            &Event {
                id: fd,
                data: ident,
                flags,
            },
        )?;
        Ok(())
    }
    pub fn next_event(&self) -> Result<Event> {
        let mut event = Event::default();
        let read = syscall::read(*self.0, &mut event)?;
        assert_eq!(
            read,
            size_of::<Event>(),
            "event queue EOF currently undefined"
        );
        Ok(event)
    }
}

impl<'a> ProcScheme<'a> {
    pub fn new(auth: &'a FdGuard, queue: &'a RawEventQueue) -> ProcScheme<'a> {
        ProcScheme {
            processes: HashMap::new(),
            sessions: HashSet::new(),
            thread_lookup: HashMap::new(),
            handles: Slab::new(),
            init_claimed: false,
            next_id: ProcessId(2),
            queue,
            auth,
        }
    }
    fn new_id(&mut self) -> ProcessId {
        let id = self.next_id;
        self.next_id.0 += 1;
        id
    }
    fn on_sendfd(&mut self, socket: &Socket, req: SendFdRequest) -> Response {
        match self.handles[req.id()] {
            ref mut st @ Handle::Init => {
                let mut fd_out = usize::MAX;
                if let Err(e) = req.obtain_fd(socket, FobtainFdFlags::empty(), Err(&mut fd_out)) {
                    return Response::new(Err(e), req);
                };
                let fd = FdGuard::new(fd_out);

                // TODO: Use global thread id etc. rather than reusing fd for identifier?
                self.queue
                    .subscribe(*fd, fd_out, EventFlags::EVENT_READ)
                    .expect("TODO");
                let status_hndl = FdGuard::new(
                    syscall::dup(
                        *fd,
                        alloc::format!("auth-{}-status", **self.auth).as_bytes(),
                    )
                    .expect("TODO"),
                );

                let thread = Rc::new(RefCell::new(Thread {
                    fd,
                    status_hndl,
                    pid: INIT_PID,
                    sig_ctrl: None,
                }));
                let thread_weak = Rc::downgrade(&thread);
                self.processes.insert(
                    INIT_PID,
                    Rc::new(RefCell::new(Process {
                        threads: vec![thread],
                        ppid: INIT_PID,
                        sid: INIT_PID,
                        pgid: INIT_PID,
                        ruid: 0,
                        euid: 0,
                        suid: 0,
                        rgid: 0,
                        egid: 0,
                        sgid: 0,
                        rns: 1,
                        ens: 1,

                        status: ProcessStatus::PossiblyRunnable,
                        awaiting_threads_term: Vec::new(),
                        waitpid: BTreeMap::new(),
                        waitpid_waiting: VecDeque::new(),

                        sig_pctl: None,
                        rtqs: Vec::new(),
                    })),
                );
                self.sessions.insert(INIT_PID);

                self.thread_lookup.insert(fd_out, thread_weak);

                *st = Handle::Proc(INIT_PID);
                Response::ok(0, req)
            }
            _ => Response::err(EBADF, req),
        }
    }
    fn fork(&mut self, parent_pid: ProcessId) -> Result<ProcessId> {
        let child_pid = self.new_id();

        let proc_guard = self.processes.get(&parent_pid).ok_or(Error::new(EBADFD))?;

        let Process {
            pgid,
            sid,
            ruid,
            euid,
            suid,
            rgid,
            egid,
            sgid,
            ens,
            rns,
            ..
        } = *proc_guard.borrow();

        let new_ctxt_fd = FdGuard::new(syscall::dup(**self.auth, b"new-context")?);
        let attr_fd = FdGuard::new(syscall::dup(
            *new_ctxt_fd,
            alloc::format!("auth-{}-attrs", **self.auth).as_bytes(),
        )?);
        let _ = syscall::write(
            *attr_fd,
            &ProcSchemeAttrs {
                pid: child_pid.0 as u32,
                euid,
                egid,
                ens,
            },
        )?;
        let status_fd = FdGuard::new(syscall::dup(
            *new_ctxt_fd,
            alloc::format!("auth-{}-status", **self.auth).as_bytes(),
        )?);

        self.queue
            .subscribe(*new_ctxt_fd, *new_ctxt_fd, EventFlags::EVENT_READ)
            .expect("TODO");

        let thread_ident = *new_ctxt_fd;
        let thread = Rc::new(RefCell::new(Thread {
            fd: new_ctxt_fd,
            status_hndl: status_fd,
            pid: child_pid,
            sig_ctrl: None, // TODO
        }));
        let thread_weak = Rc::downgrade(&thread);

        self.processes.insert(
            child_pid,
            Rc::new(RefCell::new(Process {
                threads: vec![thread],
                ppid: parent_pid,
                pgid,
                sid,
                ruid,
                euid,
                suid,
                rgid,
                egid,
                sgid,
                rns,
                ens,

                status: ProcessStatus::PossiblyRunnable,
                awaiting_threads_term: Vec::new(),

                waitpid: BTreeMap::new(),
                waitpid_waiting: VecDeque::new(),

                sig_pctl: None, // TODO
                rtqs: Vec::new(),
            })),
        );
        self.thread_lookup.insert(thread_ident, thread_weak);
        Ok(child_pid)
    }
    fn new_thread(&mut self, pid: ProcessId) -> Result<Rc<RefCell<Thread>>> {
        // TODO: deduplicate code with fork
        let proc_rc = self.processes.get_mut(&pid).ok_or(Error::new(EBADFD))?;
        let mut proc = proc_rc.borrow_mut();

        let ctxt_fd = FdGuard::new(syscall::dup(**self.auth, b"new-context")?);

        let attr_fd = FdGuard::new(syscall::dup(
            *ctxt_fd,
            alloc::format!("auth-{}-attrs", **self.auth).as_bytes(),
        )?);
        let _ = syscall::write(
            *attr_fd,
            &ProcSchemeAttrs {
                pid: pid.0 as u32,
                euid: proc.euid,
                egid: proc.egid,
                ens: proc.ens,
            },
        )?;

        let status_hndl = FdGuard::new(syscall::dup(
            *ctxt_fd,
            alloc::format!("auth-{}-status", **self.auth).as_bytes(),
        )?);

        self.queue
            .subscribe(*ctxt_fd, *status_hndl, EventFlags::EVENT_READ)
            .expect("TODO");

        let ident = *ctxt_fd;
        let thread = Rc::new(RefCell::new(Thread {
            fd: ctxt_fd,
            status_hndl,
            pid,
            sig_ctrl: None,
        }));
        let thread_weak = Rc::downgrade(&thread);
        proc.threads.push(Rc::clone(&thread));
        self.thread_lookup.insert(ident, thread_weak);
        Ok(thread)
    }
    fn on_open(&mut self, path: &str, flags: usize) -> Result<OpenResult> {
        if path == "init" {
            if core::mem::replace(&mut self.init_claimed, true) {
                return Err(Error::new(EEXIST));
            }
            return Ok(OpenResult::ThisScheme {
                number: self.handles.insert(Handle::Init),
                flags: NewFdFlags::empty(),
            });
        }
        Err(Error::new(ENOENT))
    }
    fn on_read(&mut self, id: usize, buf: &mut [u8]) -> Result<usize> {
        match self.handles[id] {
            Handle::Proc(pid) => {
                let proc_rc = self.processes.get(&pid).ok_or(Error::new(EBADFD))?;
                let process = proc_rc.borrow();
                let metadata = ProcMeta {
                    pid: pid.0 as u32,
                    pgid: process.pgid.0 as u32,
                    ppid: process.ppid.0 as u32,
                    ruid: process.ruid,
                    euid: process.euid,
                    suid: process.suid,
                    rgid: process.rgid,
                    egid: process.egid,
                    sgid: process.sgid,
                    ens: process.ens,
                    rns: process.rns,
                };
                *buf.get_mut(..size_of::<ProcMeta>())
                    .and_then(|b| plain::from_mut_bytes(b).ok())
                    .ok_or(Error::new(EINVAL))? = metadata;
                Ok(size_of::<ProcMeta>())
            }
            Handle::Init | Handle::Thread(_) => return Err(Error::new(EBADF)),
        }
    }
    fn on_dup(&mut self, old_id: usize, buf: &[u8]) -> Result<OpenResult> {
        log::trace!("Dup request");
        match self.handles[old_id] {
            Handle::Proc(pid) => match buf {
                b"fork" => {
                    log::trace!("Forking {pid:?}");
                    let child_pid = self.fork(pid)?;
                    Ok(OpenResult::ThisScheme {
                        number: self.handles.insert(Handle::Proc(child_pid)),
                        flags: NewFdFlags::empty(),
                    })
                }
                b"new-thread" => {
                    let thread = self.new_thread(pid)?;
                    Ok(OpenResult::ThisScheme {
                        number: self.handles.insert(Handle::Thread(thread)),
                        flags: NewFdFlags::empty(),
                    })
                }
                w if w.starts_with(b"thread-") => {
                    let idx = core::str::from_utf8(&w["thread-".len()..])
                        .ok()
                        .and_then(|s| s.parse::<usize>().ok())
                        .ok_or(Error::new(EINVAL))?;
                    let process = self.processes.get(&pid).ok_or(Error::new(EBADFD))?.borrow();
                    let thread = Rc::clone(process.threads.get(idx).ok_or(Error::new(ENOENT))?);

                    return Ok(OpenResult::ThisScheme {
                        number: self.handles.insert(Handle::Thread(thread)),
                        flags: NewFdFlags::empty(),
                    });
                }
                _ => return Err(Error::new(EINVAL)),
            },
            Handle::Thread(ref thread_rc) => {
                let thread = thread_rc.borrow();

                // By forwarding all dup calls to the kernel, this fd is now effectively the same
                // as the underlying fd since that fd can't do anything itself.
                Ok(OpenResult::OtherScheme {
                    fd: syscall::dup(*thread.fd, buf)?,
                })
            }
            Handle::Init => Err(Error::new(EBADF)),
        }
    }
    pub fn on_call(
        &mut self,
        state: VacantEntry<Id, PendingState, DefaultHashBuilder>,
        mut op: OpCall,
        awoken: &mut VecDeque<Id>,
    ) -> Poll<Response> {
        let id = op.fd;
        let (payload, metadata) = op.payload_and_metadata();
        match self.handles[id] {
            Handle::Init => Response::ready_err(EBADF, op),
            Handle::Thread(ref thr) => {
                let Some(verb) = ThreadCall::try_from_raw(metadata[0] as usize) else {
                    return Response::ready_err(EINVAL, op);
                };
                match verb {
                    ThreadCall::SyncSigTctl => Ready(Response::new(
                        Self::on_sync_sigtctl(&mut *thr.borrow_mut()).map(|()| 0),
                        op,
                    )),
                }
            }
            Handle::Proc(fd_pid) => {
                let Some(verb) = ProcCall::try_from_raw(metadata[0] as usize) else {
                    return Response::ready_err(EINVAL, op);
                };
                fn cvt_u32(u: u32) -> Option<u32> {
                    if u == u32::MAX {
                        None
                    } else {
                        Some(u)
                    }
                }
                match verb {
                    ProcCall::Setrens => Ready(Response::new(
                        self.on_setrens(
                            fd_pid,
                            cvt_u32(metadata[1] as u32),
                            cvt_u32(metadata[2] as u32),
                        )
                        .map(|()| 0),
                        op,
                    )),
                    ProcCall::Exit => {
                        self.on_exit_start(fd_pid, metadata[1] as i32, state, awoken, op.into_tag())
                    }
                    ProcCall::Waitpid | ProcCall::Waitpgid => {
                        let req_pid = ProcessId(metadata[1] as usize);
                        let target = match (verb, metadata[1] == 0) {
                            (ProcCall::Waitpid, true) => WaitpidTarget::AnyChild,
                            (ProcCall::Waitpid, false) => WaitpidTarget::SingleProc(req_pid),
                            (ProcCall::Waitpgid, true) => WaitpidTarget::AnyGroupMember,
                            (ProcCall::Waitpgid, false) => WaitpidTarget::ProcGroup(req_pid),
                            _ => unreachable!(),
                        };
                        let flags = match WaitFlags::from_bits(metadata[2] as usize) {
                            Some(fl) => fl,
                            None => {
                                return Response::ready_err(EINVAL, op);
                            }
                        };
                        let state = state.insert_entry(PendingState::AwaitingStatusChange {
                            waiter: fd_pid,
                            target,
                            flags,
                            op,
                        });
                        self.work_on(state, awoken)
                    }
                    ProcCall::Setpgid => {
                        let target_pid = NonZeroUsize::new(metadata[1] as usize)
                            .map_or(fd_pid, |n| ProcessId(n.get()));

                        let new_pgid = NonZeroUsize::new(metadata[2] as usize)
                            .map_or(target_pid, |n| ProcessId(n.get()));
                        if new_pgid.0 == usize::wrapping_neg(1) {
                            Ready(Response::new(
                                self.on_getpgid(fd_pid, target_pid).map(|ProcessId(p)| p),
                                op,
                            ))
                        } else {
                            Ready(Response::new(
                                self.on_setpgid(fd_pid, target_pid, new_pgid).map(|()| 0),
                                op,
                            ))
                        }
                    }
                    ProcCall::Getsid => {
                        let req_pid = NonZeroUsize::new(metadata[1] as usize)
                            .map_or(fd_pid, |n| ProcessId(n.get()));
                        Ready(Response::new(
                            self.on_getsid(fd_pid, req_pid).map(|ProcessId(s)| s),
                            op,
                        ))
                    }
                    ProcCall::Setsid => {
                        Ready(Response::new(self.on_setsid(fd_pid).map(|()| 0), op))
                    }
                    ProcCall::SetResugid => Ready(Response::new(
                        self.on_setresugid(fd_pid, payload).map(|()| 0),
                        op,
                    )),
                    ProcCall::Kill | ProcCall::Sigq => {
                        let (payload, metadata) = op.payload_and_metadata();
                        let target = ProcKillTarget::from_raw(metadata[1] as usize);
                        let Some(signal) = u8::try_from(metadata[2]).ok().filter(|s| *s <= 64)
                        else {
                            return Response::ready_err(EINVAL, op);
                        };
                        let mut killed_self = false;

                        let mode = match verb {
                            ProcCall::Kill => KillMode::Idempotent,
                            ProcCall::Sigq => KillMode::Queued({
                                let mut buf = RtSigInfo::default();
                                if payload.len() != buf.len() {
                                    return Response::ready_err(EINVAL, op);
                                }
                                buf.copy_from_slice(payload);
                                buf
                            }),
                            _ => unreachable!(),
                        };

                        let is_sigchld_to_parent = false;
                        Ready(Response::new(
                            self.on_kill(fd_pid, target, signal, mode, awoken)
                                .map(|()| 0),
                            op,
                        ))
                    }
                    ProcCall::SyncSigPctl => {
                        Ready(Response::new(self.on_sync_sigpctl(fd_pid).map(|()| 0), op))
                    }
                }
            }
        }
    }
    pub fn on_getpgid(
        &mut self,
        caller_pid: ProcessId,
        target_pid: ProcessId,
    ) -> Result<ProcessId> {
        let caller_proc = self
            .processes
            .get(&caller_pid)
            .ok_or(Error::new(ESRCH))?
            .borrow();
        let target_proc = self
            .processes
            .get(&target_pid)
            .ok_or(Error::new(ESRCH))?
            .borrow();

        // Although not required, POSIX allows the impl to forbid getting the pgid of processes
        // outside of the caller's session.
        if caller_proc.sid != target_proc.sid && caller_proc.euid != 0 {
            return Err(Error::new(EPERM));
        }

        Ok(target_proc.pgid)
    }
    pub fn on_setsid(&mut self, caller_pid: ProcessId) -> Result<()> {
        // TODO: more efficient?
        // POSIX: any other process's pgid matches the caller pid
        if self
            .processes
            .values()
            .any(|p| p.borrow().pgid == caller_pid)
        {
            return Err(Error::new(EPERM));
        }

        let mut caller_proc = self
            .processes
            .get(&caller_pid)
            .ok_or(Error::new(ESRCH))?
            .borrow_mut();

        // POSIX: already a process group leader
        if caller_proc.pgid == caller_pid {
            return Err(Error::new(EPERM));
        }

        caller_proc.pgid = caller_pid;
        caller_proc.sid = caller_pid;

        // TODO: Remove controlling terminal
        Ok(())
    }
    pub fn on_getsid(&mut self, caller_pid: ProcessId, req_pid: ProcessId) -> Result<ProcessId> {
        let caller_proc = self
            .processes
            .get(&caller_pid)
            .ok_or(Error::new(ESRCH))?
            .borrow();
        let requested_proc = self
            .processes
            .get(&req_pid)
            .ok_or(Error::new(ESRCH))?
            .borrow();

        // POSIX allows, but does not require, the implementation to forbid getting the session ID of processes outside
        // the current session.
        if caller_proc.sid != requested_proc.sid && caller_proc.euid != 0 {
            return Err(Error::new(EPERM));
        }

        Ok(requested_proc.sid)
    }
    pub fn on_setpgid(
        &mut self,
        caller_pid: ProcessId,
        target_pid: ProcessId,
        new_pgid: ProcessId,
    ) -> Result<()> {
        let caller_proc = self.processes.get(&caller_pid).ok_or(Error::new(ESRCH))?;

        let proc_rc = self.processes.get(&target_pid).ok_or(Error::new(ESRCH))?;
        let mut proc = proc_rc.borrow_mut();

        // Session leaders cannot have their pgid changed.
        if proc.sid == target_pid {
            return Err(Error::new(EPERM));
        }

        // TODO: other security checks

        proc.pgid = new_pgid;
        Ok(())
    }
    pub fn on_exit_start(
        &mut self,
        pid: ProcessId,
        status: i32,
        mut state: VacantEntry<Id, PendingState, DefaultHashBuilder>,
        awoken: &mut VecDeque<Id>,
        tag: Tag,
    ) -> Poll<Response> {
        let Some(proc_rc) = self.processes.get(&pid) else {
            return Response::ready_err(EBADFD, tag);
        };
        let mut process_guard = proc_rc.borrow_mut();
        let process = &mut *process_guard;

        match process.status {
            ProcessStatus::Stopped(_) | ProcessStatus::PossiblyRunnable => (),
            //ProcessStatus::Exiting => return Pending,
            ProcessStatus::Exiting { .. } => return Response::ready_err(EAGAIN, tag),
            ProcessStatus::Exited { .. } => return Response::ready_err(ESRCH, tag),
        }
        // TODO: status/signal
        process.status = ProcessStatus::Exiting {
            status: status as u8,
            signal: None,
        };
        if !process.threads.is_empty() {
            // terminate all threads (possibly including the caller, resulting in EINTR and a
            // to-be-ignored cancellation request to this scheme).
            for thread in &process.threads {
                let mut thread = thread.borrow_mut();
                if let Err(err) = syscall::write(*thread.status_hndl, &usize::MAX.to_ne_bytes()) {
                    return Response::ready_err(err.errno, tag);
                }
            }

            log::trace!("EXIT PENDING");
            //self.debug();
            // TODO: check?
            process.awaiting_threads_term.push(*state.key());
        }
        drop(process_guard);
        self.work_on(
            state.insert_entry(PendingState::AwaitingThreadsTermination(pid, tag)),
            awoken,
        )
    }
    pub fn on_waitpid(
        &mut self,
        this_pid: ProcessId,
        target: WaitpidTarget,
        flags: WaitFlags,
        req_id: Id,
    ) -> Poll<Result<(usize, i32)>> {
        if matches!(
            target,
            WaitpidTarget::AnyChild | WaitpidTarget::AnyGroupMember
        ) {
            // Check for existence of child.
            // TODO: inefficient, keep refcount?
            if !self.processes.values().any(|p| p.borrow().ppid == this_pid) {
                return Ready(Err(Error::new(ECHILD)));
            }
        }

        let proc_rc = self.processes.get(&this_pid).ok_or(Error::new(ESRCH))?;
        let mut proc_guard = proc_rc.borrow_mut();
        let proc = &mut *proc_guard;

        log::trace!("WAITPID");

        let recv_nonblock = |waitpid: &mut BTreeMap<WaitpidKey, (ProcessId, WaitpidStatus)>,
                             key: &WaitpidKey|
         -> Option<(ProcessId, WaitpidStatus)> {
            if let Some((pid, sts)) = waitpid.get(key).map(|(k, v)| (*k, *v)) {
                waitpid.remove(key);
                Some((pid, sts))
            } else {
                None
            }
        };
        let grim_reaper = |w_pid: ProcessId, status: WaitpidStatus| {
            match status {
                WaitpidStatus::Continued => {
                    // TODO: Handle None, i.e. restart everything until a match is found
                    if flags.contains(WaitFlags::WCONTINUED) {
                        Ready((w_pid.0, 0xffff))
                    } else {
                        Pending
                    }
                }
                WaitpidStatus::Stopped { signal } => {
                    if flags.contains(WaitFlags::WUNTRACED) {
                        Ready((w_pid.0, 0x7f | (i32::from(signal.get()) << 8)))
                    } else {
                        Pending
                    }
                }
                WaitpidStatus::Terminated { signal, status } => {
                    Ready((w_pid.0, signal.map_or(0, NonZeroU8::get).into()))
                }
            }
        };

        match target {
            // TODO: not the same
            WaitpidTarget::AnyChild | WaitpidTarget::AnyGroupMember => {
                if let Some((wid, (w_pid, status))) =
                    proc.waitpid.first_key_value().map(|(k, v)| (*k, *v))
                {
                    let _ = proc.waitpid.remove(&wid);
                    grim_reaper(w_pid, status).map(Ok)
                } else if flags.contains(WaitFlags::WNOHANG) {
                    Ready(Ok((0, 0)))
                } else {
                    proc.waitpid_waiting.push_back(req_id);
                    Pending
                }
            }
            WaitpidTarget::SingleProc(pid) => {
                if this_pid == pid {
                    return Ready(Err(Error::new(EINVAL)));
                }
                let target_proc_rc = self.processes.get(&pid).ok_or(Error::new(ESRCH))?;
                let mut target_proc = target_proc_rc.borrow_mut();

                if target_proc.ppid != this_pid {
                    return Ready(Err(Error::new(ECHILD)));
                }
                let key = WaitpidKey {
                    pid: Some(pid),
                    pgid: None,
                };
                if let ProcessStatus::Exited { status, signal } = target_proc.status {
                    let _ = recv_nonblock(&mut proc.waitpid, &key);
                    grim_reaper(pid, WaitpidStatus::Terminated { signal, status }).map(Ok)
                } else {
                    let res = recv_nonblock(&mut proc.waitpid, &key);
                    if let Some((w_pid, status)) = res {
                        grim_reaper(w_pid, status).map(Ok)
                    } else if flags.contains(WaitFlags::WNOHANG) {
                        Ready(Ok((0, 0)))
                    } else {
                        proc.waitpid_waiting.push_back(req_id);
                        Pending
                    }
                }
            }
            WaitpidTarget::ProcGroup(pgid) => {
                let this_pgid = proc.pgid;
                if !self
                    .processes
                    .iter()
                    .filter(|(pid, _)| **pid != this_pid)
                    .any(|(_, p)| p.borrow().pgid == this_pgid)
                {
                    return Ready(Err(Error::new(ECHILD)));
                }

                let key = WaitpidKey {
                    pid: None,
                    pgid: Some(pgid),
                };
                if let Some(&(w_pid, status)) = proc.waitpid.get(&key) {
                    let _ = proc.waitpid.remove(&key);
                    grim_reaper(w_pid, status).map(Ok)
                } else if flags.contains(WaitFlags::WNOHANG) {
                    Ready(Ok((0, 0)))
                } else {
                    proc.waitpid_waiting.push_back(req_id);
                    Pending
                }
            }
        }
    }
    pub fn on_setresugid(&mut self, pid: ProcessId, raw_buf: &[u8]) -> Result<()> {
        let [new_ruid, new_euid, new_suid, new_rgid, new_egid, new_sgid] = {
            let raw_ids: [u32; 6] = plain::slice_from_bytes::<u32>(raw_buf)
                .unwrap()
                .try_into()
                .map_err(|_| Error::new(EINVAL))?;
            raw_ids.map(|i| if i == u32::MAX { None } else { Some(i) })
        };
        let mut proc = self
            .processes
            .get(&pid)
            .ok_or(Error::new(ESRCH))?
            .borrow_mut();

        if proc.euid != 0 {
            if ![new_ruid, new_euid, new_suid]
                .iter()
                .filter_map(|x| *x)
                .all(|new_id| [proc.ruid, proc.euid, proc.suid].contains(&new_id))
            {
                return Err(Error::new(EPERM));
            }
            if ![new_rgid, new_egid, new_sgid]
                .iter()
                .filter_map(|x| *x)
                .all(|new_id| [proc.rgid, proc.egid, proc.sgid].contains(&new_id))
            {
                return Err(Error::new(EPERM));
            }
        }

        if let Some(new_ruid) = new_ruid {
            proc.ruid = new_ruid;
        }
        if let Some(new_euid) = new_euid {
            proc.euid = new_euid;
        }
        if let Some(new_suid) = new_suid {
            proc.suid = new_suid;
        }
        if let Some(new_rgid) = new_rgid {
            proc.rgid = new_rgid;
        }
        if let Some(new_egid) = new_egid {
            proc.egid = new_egid;
        }
        if let Some(new_sgid) = new_sgid {
            proc.sgid = new_sgid;
        }
        Ok(())
    }
    fn ancestors(&self, pid: ProcessId) -> impl Iterator<Item = ProcessId> + '_ {
        struct Iter<'a> {
            cur: Option<ProcessId>,
            procs: &'a HashMap<ProcessId, Rc<RefCell<Process>>, DefaultHashBuilder>,
        }
        impl Iterator for Iter<'_> {
            type Item = ProcessId;

            fn next(&mut self) -> Option<Self::Item> {
                let proc = self.procs.get(&self.cur?)?;
                let ppid = proc.borrow().ppid;
                self.cur = Some(ppid);
                Some(ppid)
            }
        }
        Iter {
            cur: Some(pid),
            procs: &self.processes,
        }
    }
    fn check_waitpid_queues(
        &mut self,
        waiter: ProcessId,
        target: WaitpidTarget,
        mask: WaitFlags,
    ) -> Option<(ProcessId, i32)> {
        /*match target {
            //WaitpidTarget::SingleProc(target_pid) => ,
        }*/
        todo!()
    }
    pub fn on_setrens(&mut self, pid: ProcessId, rns: Option<u32>, ens: Option<u32>) -> Result<()> {
        let proc_rc = self.processes.get(&pid).ok_or(Error::new(EBADFD))?;
        let mut process = proc_rc.borrow_mut();

        let setrns = if rns.is_none() {
            // Ignore RNS if -1 is passed
            false
        } else if rns == Some(0) {
            // Allow entering capability mode
            true
        } else if process.rns == 0 {
            // Do not allow leaving capability mode
            return Err(Error::new(EPERM));
        } else if process.euid == 0 {
            // Allow setting RNS if root
            true
        } else if rns == Some(process.ens) {
            // Allow setting RNS if used for ENS
            true
        } else if rns == Some(process.rns) {
            // Allow setting RNS if used for RNS
            true
        } else {
            // Not permitted otherwise
            return Err(Error::new(EPERM));
        };

        let setens = if ens.is_none() {
            // Ignore ENS if -1 is passed
            false
        } else if ens == Some(0) {
            // Allow entering capability mode
            true
        } else if process.ens == 0 {
            // Do not allow leaving capability mode
            return Err(Error::new(EPERM));
        } else if process.euid == 0 {
            // Allow setting ENS if root
            true
        } else if ens == Some(process.ens) {
            // Allow setting ENS if used for ENS
            true
        } else if ens == Some(process.rns) {
            // Allow setting ENS if used for RNS
            true
        } else {
            // Not permitted otherwise
            return Err(Error::new(EPERM));
        };

        if setrns {
            process.rns = rns.unwrap();
        }

        if setens {
            process.ens = ens.unwrap();
        }
        Ok(())
    }
    pub fn work_on(
        &mut self,
        mut state_entry: OccupiedEntry<Id, PendingState, DefaultHashBuilder>,
        awoken: &mut VecDeque<Id>,
    ) -> Poll<Response> {
        let req_id = *state_entry.key();
        let mut state = state_entry.get_mut();
        let this_state = core::mem::replace(state, PendingState::Placeholder);
        match this_state {
            PendingState::Placeholder => return Pending, // unreachable!(),
            // TODO
            PendingState::AwaitingThreadsTermination(current_pid, tag) => {
                let Some(proc_rc) = self.processes.get(&current_pid) else {
                    return Response::ready_err(ESRCH, tag);
                };
                let mut proc_guard = proc_rc.borrow_mut();
                let proc = &mut *proc_guard;

                if proc.threads.is_empty() {
                    log::trace!("WORKING ON AWAIT TERM");
                    let (signal, status) = match proc.status {
                        ProcessStatus::Exiting { signal, status } => (signal, status),
                        ProcessStatus::Exited { .. } => return Response::ready_ok(0, tag),
                        _ => return Response::ready_err(ESRCH, tag), // TODO?
                    };
                    // TODO: Properly remove state
                    state_entry.remove();

                    proc.status = ProcessStatus::Exited { signal, status };
                    let (ppid, pgid) = (proc.ppid, proc.pgid);
                    if let Some(parent_rc) = self.processes.get(&ppid) {
                        let mut parent = parent_rc.borrow_mut();
                        // TODO: transfer children to parent, and all of self.waitpid
                        parent.waitpid.insert(
                            WaitpidKey {
                                pid: Some(current_pid),
                                pgid: Some(pgid),
                            },
                            (current_pid, WaitpidStatus::Terminated { signal, status }),
                        );
                        //log::trace!("AWAKING WAITPID {:?}", parent.waitpid_waiting);
                        // TODO: inefficient
                        awoken.extend(parent.waitpid_waiting.drain(..));
                    }
                    Ready(Response::new(Ok(0), tag))
                } else {
                    log::trace!("WAITING AGAIN");
                    proc.awaiting_threads_term.push(req_id);
                    *state = PendingState::AwaitingThreadsTermination(current_pid, tag);
                    Pending
                }
            }
            PendingState::AwaitingStatusChange {
                waiter,
                target,
                flags,
                mut op,
            } => {
                log::trace!("WORKING ON AWAIT STS CHANGE");

                match self.on_waitpid(waiter, target, flags, req_id) {
                    Ready(Ok((pid, status))) => {
                        if let Ok(status_out) = plain::from_mut_bytes::<i32>(op.payload()) {
                            *status_out = status;
                        }
                        Response::ready_ok(pid, op)
                    }
                    Ready(Err(e)) => Response::ready_err(e.errno, op),
                    Pending => {
                        *state = PendingState::AwaitingStatusChange {
                            waiter,
                            target,
                            flags,
                            op,
                        };
                        Pending
                    }
                }
            }
        }
    }
    fn debug(&self) {
        log::trace!("PROCESSES\n{:#?}", self.processes,);
        log::trace!("HANDLES\n{:#?}", self.handles,);
    }
    pub fn on_kill(
        &mut self,
        caller_pid: ProcessId,
        target: ProcKillTarget,
        signal: u8,
        mode: KillMode,
        awoken: &mut VecDeque<Id>,
    ) -> Result<()> {
        log::trace!("KILL(from {caller_pid:?}) TARGET {target:?} {signal} {mode:?}");
        let mut num_succeeded = 0;

        let mut killed_self = false; // TODO
        let is_sigchld_to_parent = false; // TODO

        let match_grp = match target {
            ProcKillTarget::SingleProc(pid) => {
                return self.on_send_sig(
                    caller_pid,
                    KillTarget::Proc(ProcessId(pid)),
                    signal,
                    &mut killed_self,
                    mode,
                    is_sigchld_to_parent,
                    awoken,
                )
            }
            ProcKillTarget::All => None,
            ProcKillTarget::ProcGroup(grp) => Some(ProcessId(grp)),
            ProcKillTarget::ThisGroup => Some(
                self.processes
                    .get(&caller_pid)
                    .ok_or(Error::new(ESRCH))?
                    .borrow()
                    .pgid,
            ),
        };

        for (pid, proc_rc) in self.processes.iter() {
            if match_grp.map_or(false, |g| proc_rc.borrow().pgid != g) {
                continue;
            }
            let res = self.on_send_sig(
                caller_pid,
                KillTarget::Proc(*pid),
                signal,
                &mut killed_self,
                mode,
                is_sigchld_to_parent,
                awoken,
            );
            match res {
                Ok(()) => (),
                Err(err) if num_succeeded > 0 => break,
                Err(err) => return Err(err),
            }
        }

        Ok(())
    }
    pub fn on_send_sig(
        &self,
        caller_pid: ProcessId,
        target: KillTarget,
        signal: u8,
        killed_self: &mut bool,
        mode: KillMode,
        is_sigchld_to_parent: bool,
        awoken: &mut VecDeque<Id>,
    ) -> Result<()> {
        let sig = usize::from(signal);
        debug_assert!(sig <= 64);
        let sig_group = (sig - 1) / 32;
        let sig_idx = sig - 1;

        let target_pid = match target {
            KillTarget::Proc(pid) => pid,
            KillTarget::Thread(ref thread) => thread.borrow().pid,
        };
        let target_proc_rc = self.processes.get(&target_pid).ok_or(Error::new(ESRCH))?;

        let sender = SenderInfo {
            pid: caller_pid.0 as u32,
            ruid: 0, // TODO
        };

        enum SendResult {
            Succeeded,
            SucceededSigchld {
                orig_signal: NonZeroU8,
                ppid: ProcessId,
                pgid: ProcessId,
            },
            SucceededSigcont {
                ppid: ProcessId,
                pgid: ProcessId,
            },
            FullQ,
            Invalid,
        }

        let result = (|| {
            // FIXME
            let is_self = false;
            //let is_self = context::is_current(&context_lock);

            // If sig = 0, test that process exists and can be signalled, but don't send any
            // signal.
            let Some(nz_signal) = NonZeroU8::new(signal) else {
                return SendResult::Succeeded;
            };
            let mut target_proc = target_proc_rc.borrow_mut();
            let target_proc = &mut *target_proc;

            let Some(ref sig_pctl) = target_proc.sig_pctl else {
                log::trace!("No pctl {caller_pid:?}");
                return SendResult::Invalid;
            };

            if sig == SIGCONT
                && let ProcessStatus::Stopped(_sig) = target_proc.status
            {
                // Convert stopped processes to blocked if sending SIGCONT, regardless of whether
                // SIGCONT is blocked or ignored. It can however be controlled whether the process
                // will additionally ignore, defer, or handle that signal.
                target_proc.status = ProcessStatus::PossiblyRunnable;

                if !sig_pctl.signal_will_ign(SIGCONT, false) {
                    sig_pctl
                        .pending
                        .fetch_or(sig_bit(SIGCONT), Ordering::Relaxed);
                }

                // TODO: which threads should become Runnable?
                for thread_rc in target_proc.threads.iter() {
                    let mut thread = thread_rc.borrow_mut();
                    if let Some(ref tctl) = thread.sig_ctrl {
                        tctl.word[0].fetch_and(
                            !(sig_bit(SIGSTOP)
                                | sig_bit(SIGTTIN)
                                | sig_bit(SIGTTOU)
                                | sig_bit(SIGTSTP)),
                            Ordering::Relaxed,
                        );
                    }
                    let _ = syscall::write(
                        *thread.status_hndl,
                        &(ContextVerb::Unstop as usize).to_ne_bytes(),
                    )
                    .expect("TODO");
                }
                // POSIX XSI allows but does not reqiure SIGCHLD to be sent when SIGCONT occurs.
                return SendResult::SucceededSigcont {
                    ppid: target_proc.ppid,
                    pgid: target_proc.pgid,
                };
            }
            if sig == SIGSTOP
                || (matches!(sig, SIGTTIN | SIGTTOU | SIGTSTP)
                    && target_proc
                        .sig_pctl
                        .as_ref()
                        .map_or(false, |proc| proc.signal_will_stop(sig)))
            {
                target_proc.status = ProcessStatus::Stopped(sig);

                for thread in &target_proc.threads {
                    let thread = thread.borrow();
                    let _ = syscall::write(
                        *thread.status_hndl,
                        &(ContextVerb::Stop as usize).to_ne_bytes(),
                    )
                    .expect("TODO");
                    if let Some(ref tctl) = thread.sig_ctrl {
                        tctl.word[0].fetch_and(!sig_bit(SIGCONT), Ordering::Relaxed);
                    }
                }

                // TODO: Actually wait for, or IPI the context first, then clear bit. Not atomically safe otherwise?
                sig_pctl
                    .pending
                    .fetch_and(!sig_bit(SIGCONT), Ordering::Relaxed);

                return SendResult::SucceededSigchld {
                    orig_signal: nz_signal,
                    ppid: target_proc.ppid,
                    pgid: target_proc.pgid,
                };
            }
            if sig == SIGKILL {
                for thread in &target_proc.threads {
                    let thread = thread.borrow();
                    let _ = syscall::write(
                        *thread.status_hndl,
                        &(ContextVerb::ForceKill as usize).to_ne_bytes(),
                    )
                    .expect("TODO");
                }

                *killed_self |= is_self;

                // exit() will signal the parent, rather than immediately in kill()
                return SendResult::Succeeded;
            }
            if !sig_pctl.signal_will_ign(sig, is_sigchld_to_parent) {
                match target {
                    KillTarget::Thread(ref thread_rc) => {
                        let thread = thread_rc.borrow();
                        let Some(ref tctl) = thread.sig_ctrl else {
                            log::trace!("No tctl");
                            return SendResult::Invalid;
                        };

                        tctl.sender_infos[sig_idx].store(sender.raw(), Ordering::Relaxed);

                        let _was_new =
                            tctl.word[sig_group].fetch_or(sig_bit(sig), Ordering::Release);
                        if (tctl.word[sig_group].load(Ordering::Relaxed) >> 32) & sig_bit(sig) != 0
                        {
                            *killed_self |= is_self;
                            let _ = syscall::write(
                                *thread.status_hndl,
                                &(ContextVerb::Interrupt as usize).to_ne_bytes(),
                            )
                            .expect("TODO");
                        }
                    }
                    KillTarget::Proc(proc) => {
                        match mode {
                            KillMode::Queued(arg) => {
                                if sig_group != 1 || sig_idx < 32 || sig_idx >= 64 {
                                    log::trace!("Out of range");
                                    return SendResult::Invalid;
                                }
                                let rtidx = sig_idx - 32;
                                //log::trace!("QUEUEING {arg:?} RTIDX {rtidx}");
                                if rtidx >= target_proc.rtqs.len() {
                                    target_proc.rtqs.resize_with(rtidx + 1, VecDeque::new);
                                }
                                let rtq = target_proc.rtqs.get_mut(rtidx).unwrap();

                                // TODO: configurable limit?
                                if rtq.len() > 32 {
                                    return SendResult::FullQ;
                                }

                                rtq.push_back(arg);
                            }
                            KillMode::Idempotent => {
                                if sig_pctl.pending.load(Ordering::Acquire) & sig_bit(sig) != 0 {
                                    // If already pending, do not send this signal. While possible that
                                    // another thread is concurrently clearing pending, and that other
                                    // spuriously awoken threads would benefit from actually receiving
                                    // this signal, there is no requirement by POSIX for such signals
                                    // not to be mergeable. So unless the signal handler is observed to
                                    // happen-before this syscall, it can be ignored. The pending bits
                                    // would certainly have been cleared, thus contradicting this
                                    // already reached statement.
                                    return SendResult::Succeeded;
                                }

                                if sig_group != 0 {
                                    log::trace!("Invalid sig group");
                                    return SendResult::Invalid;
                                }
                                sig_pctl.sender_infos[sig_idx]
                                    .store(sender.raw(), Ordering::Relaxed);
                            }
                        }

                        sig_pctl.pending.fetch_or(sig_bit(sig), Ordering::Release);

                        for thread in target_proc.threads.iter() {
                            let thread = thread.borrow();
                            let Some(ref tctl) = thread.sig_ctrl else {
                                continue;
                            };
                            if (tctl.word[sig_group].load(Ordering::Relaxed) >> 32) & sig_bit(sig)
                                != 0
                            {
                                let _ = syscall::write(
                                    *thread.status_hndl,
                                    &(ContextVerb::Interrupt as usize).to_ne_bytes(),
                                )
                                .expect("TODO");
                                *killed_self |= is_self;
                                break;
                            }
                        }
                    }
                }
                SendResult::Succeeded
            } else {
                // Discard signals if sighandler is unset. This includes both special contexts such
                // as bootstrap, and child processes or threads that have not yet been started.
                // This is semantically equivalent to having all signals except SIGSTOP and SIGKILL
                // blocked/ignored (SIGCONT can be ignored and masked, but will always continue
                // stopped processes first).
                SendResult::Succeeded
            }
        })();

        match result {
            SendResult::Succeeded => (),
            SendResult::FullQ => return Err(Error::new(EAGAIN)),
            SendResult::Invalid => {
                log::debug!("Invalid signal configuration");
                return Err(Error::new(EINVAL));
            }
            SendResult::SucceededSigchld {
                ppid,
                pgid,
                orig_signal,
            } => {
                {
                    let mut parent = self
                        .processes
                        .get(&ppid)
                        .ok_or(Error::new(ESRCH))?
                        .borrow_mut();
                    parent.waitpid.insert(
                        WaitpidKey {
                            pid: Some(target_pid),
                            pgid: Some(pgid),
                        },
                        (
                            target_pid,
                            WaitpidStatus::Stopped {
                                signal: orig_signal,
                            },
                        ),
                    );
                    awoken.extend(parent.waitpid_waiting.drain(..));
                }
                // TODO: Just ignore EINVAL (missing signal config)
                let _ = self.on_send_sig(
                    // TODO?
                    ProcessId(1),
                    KillTarget::Proc(ppid),
                    SIGCHLD as u8,
                    killed_self,
                    KillMode::Idempotent,
                    true,
                    awoken,
                );
            }
            SendResult::SucceededSigcont { ppid, pgid } => {
                {
                    let mut parent = self
                        .processes
                        .get(&ppid)
                        .ok_or(Error::new(ESRCH))?
                        .borrow_mut();
                    parent.waitpid.insert(
                        WaitpidKey {
                            pid: Some(target_pid),
                            pgid: Some(pgid),
                        },
                        (target_pid, WaitpidStatus::Continued),
                    );
                    awoken.extend(parent.waitpid_waiting.drain(..));
                }
                // POSIX XSI allows but does not require SIGCONT to send signals to the parent.
                // TODO: Just ignore EINVAL (missing signal config)
                let _ = self.on_send_sig(
                    ProcessId(1),
                    KillTarget::Proc(ppid),
                    SIGCHLD as u8,
                    killed_self,
                    KillMode::Idempotent,
                    true,
                    awoken,
                );
            }
        }

        Ok(())
    }
    fn real_tctl_pctl_intra_page_offsets(fd: &FdGuard) -> Result<[u16; 2]> {
        let mut buf = SetSighandlerData::default();
        let _ = syscall::read(**fd, &mut buf)?;
        Ok([
            (buf.thread_control_addr % PAGE_SIZE) as u16,
            (buf.proc_control_addr % PAGE_SIZE) as u16,
        ])
    }
    pub fn on_sync_sigtctl(thread: &mut Thread) -> Result<()> {
        log::trace!("Sync tctl {:?}", thread.pid);
        let sigcontrol_fd = FdGuard::new(syscall::dup(*thread.fd, b"sighandler")?);
        let [tctl_off, _] = Self::real_tctl_pctl_intra_page_offsets(&sigcontrol_fd)?;
        log::trace!("read intra offsets");
        thread
            .sig_ctrl
            .replace(Page::map(&sigcontrol_fd, 0, tctl_off)?);
        Ok(())
    }
    pub fn on_sync_sigpctl(&mut self, pid: ProcessId) -> Result<()> {
        log::trace!("Sync pctl {pid:?}");
        let mut proc = self
            .processes
            .get(&pid)
            .ok_or(Error::new(ESRCH))?
            .borrow_mut();
        let any_thread = proc.threads.first().ok_or(Error::new(EINVAL))?;
        let sigcontrol_fd = FdGuard::new(syscall::dup(*any_thread.borrow().fd, b"sighandler")?);
        let [_, pctl_off] = Self::real_tctl_pctl_intra_page_offsets(&sigcontrol_fd)?;
        proc.sig_pctl
            .replace(Page::map(&sigcontrol_fd, PAGE_SIZE, pctl_off)?);
        Ok(())
    }
}
#[derive(Clone, Copy, Debug)]
pub enum KillMode {
    Idempotent,
    Queued(RtSigInfo),
}
#[derive(Debug)]
pub enum KillTarget {
    Proc(ProcessId),
    Thread(Rc<RefCell<Thread>>),
}
/*
pub fn sigdequeue(out: &mut [u8], sig_idx: u32) -> Result<()> {
    let Some((_tctl, sig_pctl, st)) = current.sigcontrol() else {
        return Err(Error::new(ESRCH));
    };
    if sig_idx >= 32 {
        return Err(Error::new(EINVAL));
    }
    let q = st
        .rtqs
        .get_mut(sig_idx as usize)
        .ok_or(Error::new(EAGAIN))?;
    let Some(front) = q.pop_front() else {
        return Err(Error::new(EAGAIN));
    };
    if q.is_empty() {
        sig_pctl.pending
            .fetch_and(!(1 << (32 + sig_idx as usize)), Ordering::Relaxed);
    }
    out.copy_exactly(&front)?;
    Ok(())
}
*/
