use core::cell::RefCell;
use core::hash::BuildHasherDefault;
use core::mem::size_of;
use core::task::Poll;
use core::task::Poll::*;

use alloc::collections::VecDeque;
use alloc::rc::Rc;
use alloc::vec;
use alloc::vec::Vec;

use hashbrown::hash_map::{DefaultHashBuilder, Entry, OccupiedEntry};
use hashbrown::{HashMap, HashSet};

use redox_rt::proc::FdGuard;
use redox_rt::protocol::{ProcCall, ProcMeta, WaitFlags};
use redox_scheme::scheme::Op;
use redox_scheme::{
    CallerCtx, Id, OpenResult, Request, RequestKind, Response, SendFdRequest, SignalBehavior,
    Socket,
};
use slab::Slab;
use syscall::schemev2::NewFdFlags;
use syscall::{
    Error, Event, EventFlags, FobtainFdFlags, ProcSchemeAttrs, Result, EAGAIN, EBADF, EBADFD,
    EEXIST, EINTR, EINVAL, ENOENT, ENOSYS, EOPNOTSUPP, EPERM, ESRCH, EWOULDBLOCK, O_CLOEXEC,
    O_CREAT,
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

    'outer: loop {
        for awoken in awoken.drain(..) {
            let Entry::Occupied(entry) = states.entry(awoken) else {
                continue;
            };
            match scheme.work_on(entry) {
                Ready(resp) => loop {
                    match socket.write_response(resp, SignalBehavior::Interrupt) {
                        Ok(false) => break 'outer,
                        Ok(_) => break,
                        Err(err) if err.errno == EINTR => continue,
                        Err(err) => {
                            panic!("bootstrap: failed to write scheme response to kernel: {err}")
                        }
                    }
                },
                Pending => continue,
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
            let Some(resp) = handle_scheme(req, &socket, &mut scheme, &mut states) else {
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
        } else {
            let _ = syscall::write(1, b"\nTODO: EVENT\n");
        }
    }

    unreachable!()
}
fn handle_scheme<'a>(
    req: Request,
    socket: &'a Socket,
    scheme: &mut ProcScheme<'a>,
    states: &mut HashMap<Id, PendingState>,
) -> Option<Response> {
    match req.kind() {
        RequestKind::Call(req) => {
            let res = req.with(|req, caller, op| match op {
                Op::Open { path, flags } => {
                    Ready(Response::open_dup_like(&req, scheme.on_open(path, flags)))
                }
                Op::Dup { old_fd, buf } => {
                    Ready(Response::open_dup_like(&req, scheme.on_dup(old_fd, buf)))
                }
                Op::Read { fd, buf, .. } => Ready(Response::new(&req, scheme.on_read(fd, buf))),
                Op::Call {
                    fd,
                    payload,
                    metadata,
                } => scheme
                    .on_call(
                        fd,
                        payload,
                        metadata,
                        states.entry(req.request().request_id()),
                    )
                    .map(|r| Response::new(&req, r)),
                _ => Ready(Response::new(&req, Err(Error::new(ENOSYS)))),
            });
            match res {
                Ok(Ready(r)) | Err(r) => Some(r),
                // waker has already been registered, so the logic for the caller is to not send a
                // response and continue with remaining events
                Ok(Pending) => None,
            }
        }
        RequestKind::SendFd(req) => Some(scheme.on_sendfd(socket, &req)),
        _ => None,
    }
}
enum PendingState {
    AwaitingStatusChange {
        waiter: ProcessId,
        target: WaitpidTarget,
    },
    AwaitingThreadsTermination(ProcessId),
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

    waitpid: Vec<Id>,
    children_waitpid: Vec<Id>,
}
#[derive(Debug, Clone, Copy)]
enum ProcessStatus {
    PossiblyRunnable,
    Stopped(usize),
    Exiting { status: i32 },
    Exited { status: i32 },
}
#[derive(Debug)]
struct Thread {
    fd: FdGuard,
    // sig_ctrl: MmapGuard<...>
}
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct ProcessId(usize);

const INIT_PID: ProcessId = ProcessId(1);

struct ProcScheme<'a> {
    processes: HashMap<ProcessId, Process, DefaultHashBuilder>,
    sessions: HashSet<ProcessId, DefaultHashBuilder>,
    handles: Slab<Handle>,

    init_claimed: bool,
    next_id: ProcessId,

    waitpgid: HashMap<ProcessId, Vec<Id>, DefaultHashBuilder>,
    queue: &'a RawEventQueue,
    auth: &'a FdGuard,
}

#[derive(Debug)]
enum Handle {
    Init,
    Proc(ProcessId),
}

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
            waitpgid: HashMap::new(),
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
    fn on_sendfd(&mut self, socket: &Socket, req: &SendFdRequest) -> Response {
        match self.handles[req.id()] {
            ref mut st @ Handle::Init => {
                let mut fd_out = usize::MAX;
                if let Err(e) = req.obtain_fd(socket, FobtainFdFlags::empty(), Err(&mut fd_out)) {
                    return Response::for_sendfd(&req, Err(e));
                };
                let fd = FdGuard::new(fd_out);

                // TODO: Use global thread id etc. rather than reusing fd for identifier?
                self.queue
                    .subscribe(*fd, fd_out, EventFlags::EVENT_READ)
                    .expect("TODO");

                let thread = Rc::new(RefCell::new(Thread { fd }));
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
                        waitpid: Vec::new(),
                        children_waitpid: Vec::new(),
                    },
                );
                self.sessions.insert(INIT_PID);

                *st = Handle::Proc(INIT_PID);
                Response::for_sendfd(&req, Ok(0))
            }
            _ => Response::for_sendfd(&req, Err(Error::new(EBADF))),
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

        self.processes.insert(
            child_pid,
            Process {
                threads: vec![Rc::new(RefCell::new(Thread { fd: new_ctxt_fd }))],
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
                waitpid: Vec::new(),
                children_waitpid: Vec::new(),
            },
        );
        Ok(child_pid)
    }
    fn new_thread(&mut self, pid: ProcessId) -> Result<FdGuard> {
        let proc = self.processes.get_mut(&pid).ok_or(Error::new(EBADFD))?;
        let fd = todo!();
        proc.threads.push(Rc::new(RefCell::new(Thread { fd })));
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
        id: usize,
        payload: &mut [u8],
        metadata: &[u64],
        state: Entry<Id, PendingState, DefaultHashBuilder>,
    ) -> Poll<Result<usize>> {
        match self.handles[id] {
            Handle::Init => Ready(Err(Error::new(EBADF))),
            Handle::Proc(pid) => {
                let verb =
                    ProcCall::try_from_raw(metadata[0] as usize).ok_or(Error::new(EINVAL))?;
                fn cvt_u32(u: u32) -> Option<u32> {
                    if u == u32::MAX {
                        None
                    } else {
                        Some(u)
                    }
                }
                match verb {
                    ProcCall::Setrens => Ready(
                        self.on_setrens(
                            pid,
                            cvt_u32(metadata[1] as u32),
                            cvt_u32(metadata[2] as u32),
                        )
                        .map(|()| 0),
                    ),
                    ProcCall::Exit => self.on_exit_start(pid, metadata[1] as i32, state),
                    ProcCall::Waitpid | ProcCall::Waitpgid => {
                        let req_pid = ProcessId(metadata[1] as usize);
                        let target = match (verb, metadata[1] == 0) {
                            (ProcCall::Waitpid, true) => WaitpidTarget::AnyChild,
                            (ProcCall::Waitpid, false) => WaitpidTarget::SingleProc(req_pid),
                            (ProcCall::Waitpgid, true) => WaitpidTarget::AnyGroupMember,
                            (ProcCall::Waitpgid, false) => WaitpidTarget::ProcGroup(req_pid),
                            _ => unreachable!(),
                        };
                        self.on_waitpid(
                            pid,
                            target,
                            plain::from_mut_bytes(payload).map_err(|_| Error::new(EINVAL))?,
                            WaitFlags::from_bits(metadata[2] as usize).ok_or(Error::new(EINVAL))?,
                            state,
                        )
                    }
                }
            }
        }
    }
    pub fn on_exit_start(
        &mut self,
        pid: ProcessId,
        status: i32,
        mut state: Entry<Id, PendingState, DefaultHashBuilder>,
    ) -> Poll<Result<usize>> {
        let process = self.processes.get_mut(&pid).ok_or(Error::new(EBADFD))?;
        match process.status {
            ProcessStatus::Stopped(_) | ProcessStatus::PossiblyRunnable => (),
            //ProcessStatus::Exiting => return Pending,
            ProcessStatus::Exiting { .. } => return Ready(Err(Error::new(EAGAIN))),
            ProcessStatus::Exited { .. } => return Ready(Err(Error::new(ESRCH))),
        }
        process.status = ProcessStatus::Exiting { status };
        if process.threads.is_empty() {
            Self::on_exit_complete();
            Ready(Ok(0))
        } else {
            let _ = syscall::write(1, b"\nEXIT PENDING\n");
            self.debug();
            // TODO: check?
            state.insert(PendingState::AwaitingThreadsTermination(pid));
            Pending
        }
    }
    fn on_exit_complete() {
        // TODO: send waitpid status
    }
    pub fn on_waitpid(
        &mut self,
        this_pid: ProcessId,
        target: WaitpidTarget,
        stat_loc: &mut i32,
        flags: WaitFlags,
        mut state: Entry<Id, PendingState, DefaultHashBuilder>,
    ) -> Poll<Result<usize>> {
        let _ = syscall::write(1, b"\nWAITPID\n");
        self.debug();
        Pending
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
        mut entry: OccupiedEntry<Id, PendingState, DefaultHashBuilder>,
    ) -> Poll<Response> {
        match entry.get_mut() {
            // TODO
            PendingState::AwaitingThreadsTermination(_) => Pending,
            PendingState::AwaitingStatusChange { waiter, target } => Pending,
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
