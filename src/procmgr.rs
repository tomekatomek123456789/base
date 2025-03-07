use core::cell::RefCell;
use core::cmp::Ordering;
use core::hash::BuildHasherDefault;
use core::mem::size_of;
use core::num::NonZeroU8;
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
use redox_rt::protocol::{ProcCall, ProcMeta, WaitFlags};
use redox_scheme::scheme::{IntoTag, Op, OpCall};
use redox_scheme::{
    CallerCtx, Id, OpenResult, Request, RequestKind, Response, SendFdRequest, SignalBehavior,
    Socket, Tag,
};
use slab::Slab;
use syscall::schemev2::NewFdFlags;
use syscall::{
    ContextStatus, Error, Event, EventFlags, FobtainFdFlags, ProcSchemeAttrs, Result, EAGAIN,
    EBADF, EBADFD, ECHILD, EEXIST, EINTR, EINVAL, EIO, ENOENT, ENOSYS, EOPNOTSUPP, EPERM, ESRCH,
    EWOULDBLOCK, O_CLOEXEC, O_CREAT,
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

    let _ = syscall::write(1, b"process manager started\n").unwrap();
    let _ = syscall::write(write_fd, &[0]);
    let _ = syscall::close(write_fd);

    let mut states = HashMap::<Id, PendingState, DefaultHashBuilder>::new();
    let mut awoken = VecDeque::<Id>::new();
    let mut new_awoken = VecDeque::new();

    'outer: loop {
        let _ = syscall::write(1, alloc::format!("\n{awoken:#?}\n").as_bytes());
        while !awoken.is_empty() || !new_awoken.is_empty() {
            awoken.append(&mut new_awoken);
            for awoken in awoken.drain(..) {
                //let _ = syscall::write(1, alloc::format!("\nALL STATES {states:#?}, AWOKEN {awoken:#?}\n").as_bytes());
                let Entry::Occupied(state) = states.entry(awoken) else {
                    continue;
                };
                //let _ = syscall::write(1, alloc::format!("\nSTATE {state:#?}\n").as_bytes());
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
            let req = loop {
                match socket.next_request(SignalBehavior::Interrupt) {
                    Ok(None) => break 'outer,
                    Ok(Some(req)) => break req,
                    Err(e) if e.errno == EINTR => continue,
                    // spurious event
                    Err(e) if e.errno == EWOULDBLOCK || e.errno == EAGAIN => continue 'outer,
                    Err(other) => {
                        panic!("bootstrap: failed to read scheme request from kernel: {other}")
                    }
                }
            };
            let Ready(resp) = handle_scheme(req, &socket, &mut scheme, &mut states, &mut awoken)
            else {
                continue 'outer;
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
        } else if let Some(thread) = scheme.thread_lookup.get(&event.data) {
            let Some(thread_rc) = thread.upgrade() else {
                let _ = syscall::write(
                    1,
                    alloc::format!("\nDEAD THREAD EVENT FROM {}\n", event.data).as_bytes(),
                );
                continue;
            };
            let thread = thread_rc.borrow();
            let Some(proc) = scheme.processes.get_mut(&thread.pid) else {
                // TODO?
                continue;
            };
            let _ = syscall::write(
                1,
                alloc::format!("\nTHREAD EVENT FROM {}, {}, \n", event.data, thread.pid.0)
                    .as_bytes(),
            );
            let mut buf = 0_usize.to_ne_bytes();
            let _ = syscall::read(*thread.status_hndl, &mut buf).unwrap();
            let status = usize::from_ne_bytes(buf);

            let _ = syscall::write(1, alloc::format!("\nSTATUS {status}\n",).as_bytes());

            if status != ContextStatus::Dead as usize {
                // spurious event
                continue;
            }
            scheme.thread_lookup.remove(&event.data);
            proc.threads.retain(|rc| !Rc::ptr_eq(rc, &thread_rc));
            let _ = syscall::write(
                1,
                alloc::format!("\nAWAITING {}\n", proc.awaiting_threads_term.len()).as_bytes(),
            );
            awoken.extend(proc.awaiting_threads_term.drain(..)); // TODO: inefficient
        } else {
            let _ = syscall::write(1, b"\nTODO: UNKNOWN EVENT\n");
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
                    let _ = syscall::write(1, alloc::format!("\nUNKNOWN: {op:?}\n").as_bytes());
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
struct Process {
    threads: Vec<Rc<RefCell<Thread>>>,
    ppid: ProcessId,
    pgid: ProcessId,
    sid: ProcessId,

    ruid: u32,
    euid: u32,
    rgid: u32,
    egid: u32,
    rns: u32,
    ens: u32,

    status: ProcessStatus,

    awaiting_threads_term: Vec<Id>,

    waitpid: BTreeMap<WaitpidKey, (ProcessId, WaitpidStatus)>,
    waitpid_waiting: VecDeque<Id>,
}
#[derive(Copy, Clone, Debug)]
pub struct WaitpidKey {
    pub pid: Option<ProcessId>,
    pub pgid: Option<ProcessId>,
}

// TODO: Is this valid? (transitive?)
impl Ord for WaitpidKey {
    fn cmp(&self, other: &WaitpidKey) -> Ordering {
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
            return Ordering::Greater;
        }

        if other.pid.is_some() {
            return Ordering::Less;
        }

        // If either has pgid set, it is greater
        if self.pgid.is_some() {
            return Ordering::Greater;
        }

        if other.pgid.is_some() {
            return Ordering::Less;
        }

        // If all pid and pgid are None, they are equal
        Ordering::Equal
    }
}

impl PartialOrd for WaitpidKey {
    fn partial_cmp(&self, other: &WaitpidKey) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for WaitpidKey {
    fn eq(&self, other: &WaitpidKey) -> bool {
        self.cmp(other) == Ordering::Equal
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
    // sig_ctrl: MmapGuard<...>
}
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct ProcessId(usize);

const INIT_PID: ProcessId = ProcessId(1);

struct ProcScheme<'a> {
    processes: HashMap<ProcessId, Process, DefaultHashBuilder>,
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
                let status_hndl = FdGuard::new(syscall::dup(*fd, b"status").expect("TODO"));

                let thread = Rc::new(RefCell::new(Thread {
                    fd,
                    status_hndl,
                    pid: INIT_PID,
                }));
                let thread_weak = Rc::downgrade(&thread);
                self.processes.insert(
                    INIT_PID,
                    Process {
                        threads: vec![thread],
                        ppid: INIT_PID,
                        sid: INIT_PID,
                        pgid: INIT_PID,
                        ruid: 0,
                        euid: 0,
                        rgid: 0,
                        egid: 0,
                        rns: 1,
                        ens: 1,

                        status: ProcessStatus::PossiblyRunnable,
                        awaiting_threads_term: Vec::new(),
                        waitpid: BTreeMap::new(),
                        waitpid_waiting: VecDeque::new(),
                    },
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

        let Process {
            pgid,
            sid,
            euid,
            ruid,
            egid,
            rgid,
            ens,
            rns,
            ..
        } = *self.processes.get(&parent_pid).ok_or(Error::new(EBADFD))?;

        let new_ctxt_fd = FdGuard::new(syscall::dup(**self.auth, b"new-context")?);
        let attr_fd = FdGuard::new(syscall::dup(
            *new_ctxt_fd,
            alloc::format!("attrs-{}", **self.auth).as_bytes(),
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
        let status_fd = FdGuard::new(syscall::dup(*new_ctxt_fd, b"status")?);

        self.queue
            .subscribe(*new_ctxt_fd, *new_ctxt_fd, EventFlags::EVENT_READ)
            .expect("TODO");

        let thread_ident = *new_ctxt_fd;
        let thread = Rc::new(RefCell::new(Thread {
            fd: new_ctxt_fd,
            status_hndl: status_fd,
            pid: child_pid,
        }));
        let thread_weak = Rc::downgrade(&thread);

        self.processes.insert(
            child_pid,
            Process {
                threads: vec![thread],
                ppid: parent_pid,
                pgid,
                sid,
                ruid,
                rgid,
                euid,
                egid,
                rns,
                ens,

                status: ProcessStatus::PossiblyRunnable,
                awaiting_threads_term: Vec::new(),

                waitpid: BTreeMap::new(),
                waitpid_waiting: VecDeque::new(),
            },
        );
        self.thread_lookup.insert(thread_ident, thread_weak);
        Ok(child_pid)
    }
    fn new_thread(&mut self, pid: ProcessId) -> Result<FdGuard> {
        let proc = self.processes.get_mut(&pid).ok_or(Error::new(EBADFD))?;
        let fd: FdGuard = todo!();
        let status_hndl = todo!();
        let ident = *fd;
        let thread = Rc::new(RefCell::new(Thread {
            fd,
            status_hndl,
            pid,
        }));
        let thread_weak = Rc::downgrade(&thread);
        proc.threads.push(thread);
        self.thread_lookup.insert(ident, thread_weak);
        Ok(fd)
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
                let process = self.processes.get(&pid).ok_or(Error::new(EBADFD))?;
                let metadata = ProcMeta {
                    pid: pid.0 as u32,
                    pgid: process.pgid.0 as u32,
                    ppid: process.ppid.0 as u32,
                    euid: process.euid,
                    egid: process.egid,
                    ruid: process.ruid,
                    rgid: process.rgid,
                    ens: process.ens,
                    rns: process.rns,
                };
                *buf.get_mut(..size_of::<ProcMeta>())
                    .and_then(|b| plain::from_mut_bytes(b).ok())
                    .ok_or(Error::new(EINVAL))? = metadata;
                Ok(size_of::<ProcMeta>())
            }
            Handle::Init => return Err(Error::new(EBADF)),
        }
    }
    fn on_dup(&mut self, old_id: usize, buf: &[u8]) -> Result<OpenResult> {
        match self.handles[old_id] {
            Handle::Proc(pid) => match buf {
                b"fork" => {
                    let child_pid = self.fork(pid)?;
                    Ok(OpenResult::ThisScheme {
                        number: self.handles.insert(Handle::Proc(child_pid)),
                        flags: NewFdFlags::empty(),
                    })
                }
                b"new-thread" => Ok(OpenResult::OtherScheme {
                    fd: self.new_thread(pid)?.take(),
                }),
                w if w.starts_with(b"thread-") => {
                    let idx = core::str::from_utf8(&w["thread-".len()..])
                        .ok()
                        .and_then(|s| s.parse::<usize>().ok())
                        .ok_or(Error::new(EINVAL))?;
                    let process = self.processes.get(&pid).ok_or(Error::new(EBADFD))?;
                    let thread = process.threads.get(idx).ok_or(Error::new(ENOENT))?.borrow();

                    return Ok(OpenResult::OtherScheme {
                        fd: syscall::dup(*thread.fd, &[])?,
                    });
                }
                _ => return Err(Error::new(EINVAL)),
            },
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
                }
            }
        }
    }
    pub fn on_exit_start(
        &mut self,
        pid: ProcessId,
        status: i32,
        mut state: VacantEntry<Id, PendingState, DefaultHashBuilder>,
        awoken: &mut VecDeque<Id>,
        tag: Tag,
    ) -> Poll<Response> {
        let Some(process) = self.processes.get_mut(&pid) else {
            return Response::ready_err(EBADFD, tag);
        };
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

            let _ = syscall::write(1, b"\nEXIT PENDING\n");
            //self.debug();
            // TODO: check?
            process.awaiting_threads_term.push(*state.key());
        }
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
            if !self.processes.values().any(|p| p.ppid == this_pid) {
                return Ready(Err(Error::new(ECHILD)));
            }
        }

        let proc = self.processes.get_mut(&this_pid).ok_or(Error::new(ESRCH))?;
        let _ = syscall::write(1, b"\nWAITPID\n");

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
                let [Some(proc), Some(target_proc)] =
                    self.processes.get_many_mut([&this_pid, &pid])
                else {
                    return Ready(Err(Error::new(ESRCH)));
                };
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
                if !self.processes.values().any(|p| p.pgid == this_pgid) {
                    return Ready(Err(Error::new(ECHILD)));
                }

                // reborrow proc
                let proc = self.processes.get_mut(&this_pid).ok_or(Error::new(ESRCH))?;

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
    fn ancestors(&self, pid: ProcessId) -> impl Iterator<Item = ProcessId> + '_ {
        struct Iter<'a> {
            cur: Option<ProcessId>,
            procs: &'a HashMap<ProcessId, Process, DefaultHashBuilder>,
        }
        impl Iterator for Iter<'_> {
            type Item = ProcessId;

            fn next(&mut self) -> Option<Self::Item> {
                let proc = self.procs.get(&self.cur?)?;
                self.cur = Some(proc.ppid);
                Some(proc.ppid)
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
        let process = self.processes.get_mut(&pid).ok_or(Error::new(EBADFD))?;
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
                let Some(proc) = self.processes.get_mut(&current_pid) else {
                    return Response::ready_err(ESRCH, tag);
                };
                if proc.threads.is_empty() {
                    let _ = syscall::write(1, b"\nWORKING ON AWAIT TERM\n");
                    let (signal, status) = match proc.status {
                        ProcessStatus::Exiting { signal, status } => (signal, status),
                        ProcessStatus::Exited { .. } => return Response::ready_ok(0, tag),
                        _ => return Response::ready_err(ESRCH, tag), // TODO?
                    };
                    // TODO: Properly remove state
                    state_entry.remove();

                    proc.status = ProcessStatus::Exited { signal, status };
                    let (ppid, pgid) = (proc.ppid, proc.pgid);
                    if let Some(parent) = self.processes.get_mut(&ppid) {
                        // TODO: transfer children to parent, and all of self.waitpid
                        parent.waitpid.insert(
                            WaitpidKey {
                                pid: Some(current_pid),
                                pgid: Some(pgid),
                            },
                            (current_pid, WaitpidStatus::Terminated { signal, status }),
                        );
                        //let _ = syscall::write(1, alloc::format!("\nAWAKING WAITPID {:?}\n", parent.waitpid_waiting).as_bytes());
                        // TODO: inefficient
                        awoken.extend(parent.waitpid_waiting.drain(..));
                    }
                    Ready(Response::new(Ok(0), tag))
                } else {
                    let _ = syscall::write(1, b"\nWAITING AGAIN\n");
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
                let _ = syscall::write(1, b"\nWORKING ON AWAIT STS CHANGE\n");

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
        let _ = syscall::write(
            1,
            alloc::format!("PROCESSES\n\n{:#?}\n\n", self.processes).as_bytes(),
        );
        let _ = syscall::write(
            1,
            alloc::format!("HANDLES\n\n{:#?}\n\n", self.handles).as_bytes(),
        );
    }
}
