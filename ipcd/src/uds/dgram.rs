//! uds scheme for handling Unix Domain Socket datagram communication

use super::{
    path_buf_to_string, read_msghdr_info, read_num, AncillaryData, Credential, DataPacket,
    MsgWriter, MAX_DGRAM_MSG_LEN,
};

use libc::{AF_UNIX, SO_DOMAIN, SO_PASSCRED};
use redox_rt::protocol::SocketCall;
use redox_scheme::{
    scheme::SchemeSync, CallerCtx, OpenResult, Response, SendFdRequest, SignalBehavior,
    Socket as SchemeSocket,
};
use std::{
    cell::RefCell,
    cmp,
    collections::{HashMap, HashSet, VecDeque},
    mem,
    rc::Rc,
};
use syscall::{error::*, flag::*, schemev2::NewFdFlags, Error, FobtainFdFlags};

impl DataPacket {
    pub fn serialize_to_stream(
        self,
        stream: &mut [u8],
        socket: &mut Socket,
        name_buf_size: usize,
        iov_size: usize,
    ) -> Result<usize> {
        let mut msg_writer = MsgWriter::new(stream);
        msg_writer.write_name(
            self.ancillary_data.name,
            name_buf_size,
            UdsDgramScheme::fpath_inner,
        )?;

        msg_writer.write_payload(&self.payload, self.payload.len(), iov_size)?;

        // Write the ancillary data
        if !msg_writer.write_rights(self.ancillary_data.num_fds) {
            // Buffer was too small, FDs could not be described. Drop the actual FDs.
            log::warn!(
                "serialize_to_stream: Buffer too small for SCM_RIGHTS, dropping {} FDs.",
                self.ancillary_data.num_fds
            );
            socket.drop_fds(self.ancillary_data.num_fds)?;
        }
        // Write other ancillary datas
        for option in &socket.options {
            let result = match *option {
                SO_PASSCRED => msg_writer.write_credentials(&self.ancillary_data.cred),
                _ => {
                    log::warn!(
                        "serialize_to_stream: Unsupported socket option for serialization: {}",
                        option
                    );
                    return Err(Error::new(EOPNOTSUPP));
                }
            };
            if !result {
                log::warn!("serialize_to_stream: Buffer too small for ancillary data, stopping further serialization.");
                break;
            }
        }

        Ok(msg_writer.len())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    Unbound,
    Bound,
    Closed,
}

impl Default for State {
    fn default() -> Self {
        Self::Unbound
    }
}

#[derive(Debug, Default)]
pub struct Socket {
    primary_id: usize,
    path: Option<String>,
    state: State,
    peer: Option<usize>,
    messages: VecDeque<DataPacket>,
    options: HashSet<i32>,
    fds: VecDeque<usize>,
    flags: usize,
}

impl Socket {
    fn drop_fds(&mut self, num_fd: usize) -> Result<()> {
        for i in 0..num_fd {
            if self.fds.pop_front().is_none() {
                log::error!("Socket::drop_fds: Attempted to drop FD #{} of {}, but fd queue is empty. State inconsistency.", i + 1, num_fd);
                return Err(Error::new(EINVAL));
            }
        }
        Ok(())
    }
}

pub struct UdsDgramScheme<'sock> {
    sockets: HashMap<usize, Rc<RefCell<Socket>>>,
    next_id: usize,
    socket_paths: HashMap<String, Rc<RefCell<Socket>>>,
    socket: &'sock SchemeSocket,
}

impl<'sock> UdsDgramScheme<'sock> {
    pub fn new(socket: &'sock SchemeSocket) -> Self {
        Self {
            sockets: HashMap::new(),
            next_id: 0,
            socket_paths: HashMap::new(),
            socket,
        }
    }

    fn post_fevent(&self, id: usize, flags: usize) -> Result<()> {
        let fevent_response = Response::post_fevent(id, flags);
        match self
            .socket
            .write_response(fevent_response, SignalBehavior::Restart)
        {
            Ok(true) => Ok(()),
            Ok(false) => Err(Error::new(EAGAIN)),
            Err(err) => Err(err),
        }
    }

    fn get_socket(&self, id: usize) -> Result<&Rc<RefCell<Socket>>, Error> {
        self.sockets.get(&id).ok_or(Error::new(EBADF))
    }

    fn get_connected_peer(&self, id: usize) -> Result<(usize, Rc<RefCell<Socket>>), Error> {
        let socket = self.get_socket(id)?.borrow();

        let remote_id = socket.peer.ok_or(Error::new(ENOTCONN))?;

        let remote_rc = self.get_socket(remote_id).map_err(|e| {
            log::error!("get_connected_peer(id: {}): Peer socket (id: {}) has vanished. Original error: {:?}", id, remote_id, e);
            Error::new(EPIPE)
        })?;

        if remote_rc.borrow().state == State::Closed {
            log::warn!(
                "get_connected_peer(id: {}): Attempted to interact with a closed peer (id: {}).",
                id,
                remote_id
            );
            return Err(Error::new(ECONNREFUSED));
        }

        Ok((remote_id, remote_rc.clone()))
    }

    fn handle_unnamed_socket(&mut self, flags: usize) -> usize {
        let new_id = self.next_id;
        let mut new = Socket::default();
        new.flags = flags;
        new.primary_id = new_id;

        self.sockets.insert(new_id, Rc::new(RefCell::new(new)));
        self.next_id += 1;
        new_id
    }

    fn call_inner(
        &mut self,
        id: usize,
        payload: &mut [u8],
        metadata: &[u64],
        ctx: &CallerCtx,
    ) -> Result<usize> {
        // metadata to Vec<u8>
        let Some(verb) = SocketCall::try_from_raw(metadata[0] as usize) else {
            log::error!("call_inner: Invalid verb in metadata: {:?}", metadata);
            return Err(Error::new(EINVAL));
        };
        match verb {
            SocketCall::Bind => self.handle_bind(id, &payload),
            SocketCall::Connect => self.handle_connect(id, &payload),
            SocketCall::SetSockOpt => self.handle_setsockopt(id, metadata[1] as i32, &payload),
            SocketCall::GetSockOpt => self.handle_getsockopt(id, metadata[1] as i32, payload),
            SocketCall::SendMsg => self.handle_sendmsg(id, payload, ctx),
            SocketCall::RecvMsg => self.handle_recvmsg(id, payload),
            _ => Err(Error::new(OPNOTSUP)),
        }
    }

    fn handle_bind(&mut self, id: usize, path_buf: &[u8]) -> Result<usize> {
        let path = path_buf_to_string(path_buf)?;

        // Check if path is already bound to a server
        if self.socket_paths.contains_key(&path) {
            log::warn!(
                "handle_bind(id: {}): Address '{}' already in use.",
                id,
                path
            );
            return Err(Error::new(EADDRINUSE));
        }

        let socket_rc = self.get_socket(id)?.clone();
        let mut socket = socket_rc.borrow_mut();

        if socket.state != State::Unbound {
            log::error!(
                "handle_bind(id: {}): Socket is already bound or connected (state: {:?})",
                id,
                socket.state
            );
            return Err(Error::new(EINVAL));
        }

        socket.path = Some(path.clone());
        socket.state = State::Bound;

        self.socket_paths.insert(path, socket_rc.clone());

        Ok(0)
    }

    fn handle_connect(&mut self, id: usize, path_buf: &[u8]) -> Result<usize> {
        let path = path_buf_to_string(path_buf)?;

        let target_rc = self
            .socket_paths
            .get(&path)
            .ok_or(Error::new(ECONNREFUSED))?;
        let target_id = target_rc.borrow().primary_id;

        let socket_rc = self.get_socket(id)?;
        socket_rc.borrow_mut().peer = Some(target_id);

        Ok(0)
    }

    fn handle_setsockopt(&mut self, id: usize, option: i32, value_slice: &[u8]) -> Result<usize> {
        let socket_rc = self.get_socket(id)?;
        let mut socket = socket_rc.borrow_mut();

        match option {
            SO_PASSCRED => {
                let value = read_num::<i32>(value_slice)?;
                if value != 0 {
                    socket.options.insert(SO_PASSCRED);
                } else {
                    socket.options.remove(&SO_PASSCRED);
                }
                Ok(value_slice.len())
            }
            _ => {
                log::warn!(
                    "handle_setsockopt(id: {}): Unsupported option: {}",
                    id,
                    option
                );
                Err(Error::new(ENOPROTOOPT))
            }
        }
    }

    fn handle_getsockopt(&mut self, id: usize, option: i32, payload: &mut [u8]) -> Result<usize> {
        match option {
            SO_DOMAIN => {
                payload.fill(0);
                if payload.len() < mem::size_of::<i32>() {
                    log::error!(
                        "handle_getsockopt(id: {}): SO_DOMAIN payload buffer is too small. len: {}",
                        id,
                        payload.len()
                    );
                    return Err(Error::new(ENOBUFS));
                }
                let domain = AF_UNIX.to_le_bytes();
                payload[..domain.len()].copy_from_slice(&domain);
                Ok(domain.len())
            }
            _ => {
                log::warn!(
                    "handle_getsockopt(id: {}): Unsupported option: {}",
                    id,
                    option
                );
                Err(Error::new(ENOPROTOOPT))
            }
        }
    }

    fn handle_sendmsg(&mut self, id: usize, msg_stream: &[u8], ctx: &CallerCtx) -> Result<usize> {
        if msg_stream.is_empty() {
            log::error!("handle_sendmsg(id: {}): msg_stream is empty.", id);
            return Err(Error::new(EINVAL));
        }

        let name = {
            let socket_rc = self.get_socket(id)?;
            let socket = socket_rc.borrow();
            socket.path.clone()
        };
        let (remote_id, remote_rc) = self.get_connected_peer(id)?;

        let bytes_written =
            Self::sendmsg_inner(&mut remote_rc.borrow_mut(), name, msg_stream, ctx)?;
        self.post_fevent(remote_id, EVENT_READ.bits())?;
        Ok(bytes_written)
    }

    fn sendmsg_inner(
        socket: &mut Socket,
        name: Option<String>,
        msg_stream: &[u8],
        ctx: &CallerCtx,
    ) -> Result<usize> {
        if msg_stream.is_empty() {
            log::error!("sendmsg_inner: msg_stream is empty.");
            return Err(Error::new(EINVAL));
        }

        let message = DataPacket::from_stream(msg_stream, name, ctx)?;
        let payload_len = message.len();
        socket.messages.push_back(message);

        Ok(payload_len)
    }

    fn handle_recvmsg(&mut self, id: usize, msg_stream: &mut [u8]) -> Result<usize> {
        let socket_rc = self.get_socket(id)?;
        let mut socket = socket_rc.borrow_mut();

        if let Some(message) = socket.messages.pop_front() {
            Ok(Self::recvmsg_inner(&mut socket, message, msg_stream)?)
        } else if (socket.flags as usize) & O_NONBLOCK == O_NONBLOCK {
            Err(Error::new(EAGAIN))
        } else {
            Err(Error::new(EWOULDBLOCK))
        }
    }

    fn recvmsg_inner(
        socket: &mut Socket,
        message: DataPacket,
        msg_stream: &mut [u8],
    ) -> Result<usize> {
        // Read the name length, whole iov size, and msg controllen from the stream
        let (prepared_name_len, prepared_whole_iov_size, _) = read_msghdr_info(msg_stream)?;

        message.serialize_to_stream(
            msg_stream,
            socket,
            prepared_name_len,
            prepared_whole_iov_size,
        )
    }

    fn handle_connect_socketpair(&mut self, id: usize) -> Result<OpenResult> {
        let new_id = self.next_id;
        let mut new = Socket::default();
        new.primary_id = new_id;

        let socket_rc = self.get_socket(id)?;
        if socket_rc.borrow().state == State::Closed {
            log::warn!(
                "handle_connect_socketpair(id: {}): Attempting to connect from a closed socket.",
                id
            );
            return Err(Error::new(ECONNREFUSED));
        }

        {
            let mut socket = socket_rc.borrow_mut();
            socket.peer = Some(new_id);
        }

        new.peer = Some(id);

        // smoltcp sends writeable whenever a listener gets a
        // client, we'll do the same too (but also readable,
        // why not)
        self.post_fevent(id, (EVENT_READ | EVENT_WRITE).bits())?;

        self.sockets.insert(new_id, Rc::new(RefCell::new(new)));

        self.next_id += 1;

        Ok(OpenResult::ThisScheme {
            number: new_id,
            flags: NewFdFlags::empty(),
        })
    }

    fn handle_recvfd(&mut self, id: usize) -> Result<OpenResult> {
        let socket_rc = self.get_socket(id)?;
        let mut socket = socket_rc.borrow_mut();
        let fd = socket.fds.pop_front().ok_or(Error::new(EWOULDBLOCK))?;

        Ok(OpenResult::OtherScheme { fd })
    }

    fn handle_listen(&mut self, id: usize) -> Result<OpenResult> {
        let socket_rc = self.get_socket(id)?;

        let new_id = self.next_id;

        self.sockets.insert(new_id, socket_rc.clone());
        self.next_id += 1;

        Ok(OpenResult::ThisScheme {
            number: new_id,
            flags: NewFdFlags::empty(),
        })
    }

    fn write_inner(&mut self, id: usize, buf: &[u8], ctx: &CallerCtx) -> Result<usize> {
        if buf.len() > MAX_DGRAM_MSG_LEN {
            return Err(Error::new(EMSGSIZE));
        }

        let name = {
            let socket_rc = self.get_socket(id)?;
            let socket = socket_rc.borrow();
            if matches!(socket.state, State::Closed) {
                return Err(Error::new(EPIPE));
            }

            socket.path.clone()
        };

        // Assume writing to the connected socket if the given id is the primary id
        let (remote_id, remote_rc) = self.get_connected_peer(id)?;
        let mut remote = remote_rc.borrow_mut();
        let message = DataPacket::new(
            buf.to_vec(),
            AncillaryData::new(
                Credential::new(ctx.pid as i32, ctx.uid as i32, ctx.gid as i32),
                name,
            ),
        );
        remote.messages.push_back(message);

        self.post_fevent(remote_id, EVENT_READ.bits())?;

        Ok(buf.len())
    }

    fn fpath_inner(path: &String, buf: &mut [u8]) -> Result<usize> {
        // Write scheme name
        const PREFIX: &[u8] = b"/scheme/uds_dgram/";
        let len = cmp::min(PREFIX.len(), buf.len());
        buf[..len].copy_from_slice(&PREFIX[..len]);
        if len < PREFIX.len() {
            return Ok(len);
        }

        // Write path
        let len = cmp::min(path.len(), buf.len() - PREFIX.len());
        buf[PREFIX.len()..][..len].copy_from_slice(&path.as_bytes()[..len]);

        Ok(PREFIX.len() + len)
    }

    fn read_inner(&mut self, id: usize, buf: &mut [u8], flags: u32) -> Result<usize> {
        let socket_rc = self.get_socket(id)?;
        let mut socket = socket_rc.borrow_mut();

        if let Some(message) = socket.messages.pop_front() {
            let full_len = message.len();
            let copy_len = cmp::min(buf.len(), full_len);
            buf[..copy_len].copy_from_slice(&message.payload[..copy_len]);

            Ok(copy_len)
        } else if (flags as usize) & O_NONBLOCK == O_NONBLOCK {
            Err(Error::new(EAGAIN))
        } else {
            Err(Error::new(EWOULDBLOCK))
        }
    }

    fn sendfd_inner(&mut self, sendfd_request: &SendFdRequest) -> Result<usize> {
        let mut new_fd = usize::MAX;
        if let Err(e) =
            sendfd_request.obtain_fd(&self.socket, FobtainFdFlags::empty(), Err(&mut new_fd))
        {
            log::error!("sendfd_inner: obtain_fd failed with error: {:?}", e);
            return Err(e);
        }
        let socket_id = sendfd_request.id();
        let (remote_id, remote_rc) = self.get_connected_peer(socket_id)?;
        remote_rc.borrow_mut().fds.push_back(new_fd);

        self.post_fevent(remote_id, EVENT_READ.bits())?;
        Ok(new_fd)
    }
}

impl<'sock> SchemeSync for UdsDgramScheme<'sock> {
    fn open(&mut self, path: &str, flags: usize, _ctx: &CallerCtx) -> Result<OpenResult> {
        let new_id = if path.is_empty() {
            self.handle_unnamed_socket(flags)
        } else {
            log::error!(
                "open(path: '{}'): Attempting to open a named socket, which is not supported.",
                path
            );
            return Err(Error::new(EINVAL));
        };
        Ok(OpenResult::ThisScheme {
            number: new_id,
            flags: NewFdFlags::empty(),
        })
    }

    fn call(
        &mut self,
        id: usize,
        payload: &mut [u8],
        metadata: &[u64],
        ctx: &CallerCtx,
    ) -> Result<usize> {
        self.call_inner(id, payload, metadata, ctx)
    }

    fn dup(&mut self, id: usize, buf: &[u8], _ctx: &CallerCtx) -> Result<OpenResult> {
        match buf {
            // Connect for socket pair
            b"connect" => self.handle_connect_socketpair(id),
            b"recvfd" => self.handle_recvfd(id),
            // listen will generate a id for same socket
            b"listen" => self.handle_listen(id),
            _ => Err(Error::new(EINVAL)),
        }
    }

    fn write(
        &mut self,
        id: usize,
        buf: &[u8],
        _offset: u64,
        _flags: u32,
        ctx: &CallerCtx,
    ) -> Result<usize> {
        self.write_inner(id, buf, ctx)
    }

    fn fpath(&mut self, id: usize, buf: &mut [u8], _ctx: &CallerCtx) -> Result<usize> {
        let socket_rc = self.get_socket(id)?;
        let socket = socket_rc.borrow();

        let path = socket.path.as_ref().ok_or_else(|| {
            log::error!("fpath(id: {}): Socket is unnamed, has no path.", id);
            Error::new(ENOENT)
        })?;
        Ok(Self::fpath_inner(path, buf)?)
    }

    fn fsync(&mut self, id: usize, _ctx: &CallerCtx) -> Result<()> {
        self.get_socket(id).and(Ok(()))
    }

    fn read(
        &mut self,
        id: usize,
        buf: &mut [u8],
        _offset: u64,
        flags: u32,
        _ctx: &CallerCtx,
    ) -> Result<usize> {
        self.read_inner(id, buf, flags)
    }

    fn on_close(&mut self, id: usize) {
        let Some(socket_rc) = self.sockets.remove(&id) else {
            return;
        };
        let mut socket = socket_rc.borrow_mut();
        if socket.primary_id == id {
            socket.state = State::Closed;
            socket.peer = None;
            let path = socket.path.clone();
            socket.path = None;

            if let Some(path) = path {
                self.socket_paths.remove(&path);
            }
        }
    }

    fn on_sendfd(&mut self, sendfd_request: &SendFdRequest) -> Result<usize> {
        self.sendfd_inner(sendfd_request)
    }

    fn fcntl(&mut self, id: usize, cmd: usize, arg: usize, _ctx: &CallerCtx) -> Result<usize> {
        let socket = self.get_socket(id)?;
        match cmd {
            F_GETFL => Ok(socket.borrow().flags),
            F_SETFL => {
                socket.borrow_mut().flags = arg;
                Ok(0)
            }
            _ => {
                log::error!("fcntl(id: {}): Unsupported cmd: {}", id, cmd);
                Err(Error::new(EINVAL))
            }
        }
    }
}
