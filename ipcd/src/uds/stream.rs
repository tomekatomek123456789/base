//! uds scheme for handling Unix Domain Socket stream communication

use super::{
    path_buf_to_string, read_msghdr_info, read_num, AncillaryData, Credential, DataPacket,
    MsgWriter, MIN_RECV_MSG_LEN,
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
use syscall::{error::*, flag::*, schemev2::NewFdFlags, Error};

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Connection {
    peer: usize,
    packets: VecDeque<DataPacket>,
    fds: VecDeque<usize>,

    is_peer_shutdown: bool,
}
impl Connection {
    fn new(peer: usize) -> Self {
        Self {
            peer,
            ..Default::default()
        }
    }

    fn drop_fds(&mut self, num_fd: usize) -> Result<()> {
        for i in 0..num_fd {
            if self.fds.pop_front().is_none() {
                log::error!("Connection::drop_fds: Attempted to drop FD #{} of {}, but fd queue is empty. State inconsistency.", i + 1, num_fd);
                return Err(Error::new(EPROTO));
            }
        }
        Ok(())
    }

    fn serialize_to_msgstream(
        &mut self,
        stream: &mut [u8],
        name_buf_size: usize,
        iov_size: usize,
        options: HashSet<i32>,
    ) -> Result<usize> {
        let mut name: Option<String> = None;
        let mut payload_buffer: Vec<u8> = Vec::with_capacity(iov_size);
        let mut ancillary_data_buffer: VecDeque<AncillaryData> = VecDeque::new();
        let mut total_copied_len = 0;
        let mut user_buf_offset = 0;

        while user_buf_offset < iov_size {
            let Some(packet) = self.packets.front_mut() else {
                // No more packets to read
                break;
            };

            let packet_rem_payload = &packet.payload[packet.read_offset..];

            let user_buf_rem_len = iov_size - user_buf_offset;

            let copied_len = cmp::min(packet_rem_payload.len(), user_buf_rem_len);
            if copied_len == 0 {
                // No more data to read from this packet
                break;
            }
            payload_buffer.extend_from_slice(&packet_rem_payload[..copied_len]);

            if !packet.ancillary_taken {
                name = name.or_else(|| packet.ancillary_data.name.take());
                ancillary_data_buffer.push_back(packet.ancillary_data.clone());
                packet.ancillary_taken = true; // Mark ancillary data as taken
            }

            packet.read_offset += copied_len;
            user_buf_offset += copied_len;
            total_copied_len += copied_len;
            if packet.read_offset >= packet.payload.len() {
                // If the packet is fully read, remove it from the queue
                self.packets.pop_front();
            }
        }

        let mut msg_writer = MsgWriter::new(stream);

        msg_writer.write_name(name, name_buf_size, UdsStreamScheme::fpath_inner)?;

        let full_len = cmp::min(total_copied_len, iov_size);
        msg_writer.write_payload(&payload_buffer, full_len, iov_size)?;

        let mut num_fds = 0;
        for ancillary_data in ancillary_data_buffer.iter() {
            num_fds += ancillary_data.num_fds;
        }
        if !msg_writer.write_rights(num_fds) {
            log::warn!(
                "serialize_to_msgstream: Buffer too small for SCM_RIGHTS, dropping {} FDs.",
                num_fds
            );
            self.drop_fds(num_fds)?;
        }

        for option in options {
            let result = match option {
                SO_PASSCRED => {
                    let mut success = true;
                    for data in &ancillary_data_buffer {
                        if !msg_writer.write_credentials(&data.cred) {
                            success = false;
                            break;
                        }
                    }
                    success
                }
                _ => {
                    log::warn!(
                        "serialize_to_msgstream: Unsupported socket option for serialization: {}",
                        option
                    );
                    return Err(Error::new(EOPNOTSUPP));
                }
            };
            if !result {
                log::warn!("serialize_to_msgstream: Buffer too small for ancillary data, stopping further serialization.");
                break;
            }
        }

        Ok(msg_writer.len())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub enum State {
    Unbound,
    Bound,
    Listening,
    Connecting,
    Accepted,
    Established,
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
    options: HashSet<i32>,
    flags: usize,
    state: State,
    awaiting: VecDeque<usize>,
    connection: Option<Connection>,
}

impl Socket {
    fn new(
        id: usize,
        path: Option<String>,
        state: State,
        options: HashSet<i32>,
        flags: usize,
        connection: Option<Connection>,
    ) -> Self {
        Self {
            primary_id: id,
            path,
            state,
            options,
            flags,
            connection,
            ..Default::default()
        }
    }

    fn accept(&mut self, primary_id: usize, awaiting_client_id: usize) -> Result<Self> {
        if !self.is_listening() {
            log::error!(
                "accept(id: {}): Accept called on a non-listening socket.",
                self.primary_id
            );
            return Err(Error::new(EINVAL));
        }
        Ok(Self::new(
            primary_id,
            self.path.clone(),
            State::Established,
            self.options.clone(),
            self.flags,
            Some(Connection::new(awaiting_client_id)),
        ))
    }

    fn establish(&mut self, peer: usize) -> Result<()> {
        if self.state != State::Connecting {
            log::error!(
                "establish(id: {}): Cannot establish connection in state: {:?}",
                self.primary_id,
                self.state
            );
            return Err(Error::new(EINVAL));
        }
        self.state = State::Accepted;
        self.connection = Some(Connection::new(peer));
        Ok(())
    }

    fn connect(&mut self, other: usize, flags: usize) -> Result<()> {
        match self.state {
            State::Unbound | State::Bound => {
                // If the socket is unbound or bound, wait for the listener to start listening.
                if flags & O_NONBLOCK == O_NONBLOCK {
                    self.awaiting.push_back(other);
                    Ok(())
                } else {
                    // If the connecting target is not a listening,
                    // the connecting socket will block until the socket
                    // is ready to accept.
                    Err(Error::new(EWOULDBLOCK))
                }
            }
            State::Listening => {
                // If the socket is already listening, it can accept connections.
                self.awaiting.push_back(other);
                Ok(())
            }
            _ => Err(Error::new(ECONNREFUSED)),
        }
    }

    // For socketpair, add the peer's id to the base socket's awaiting queue.
    fn connect_socketpair(&mut self, peer: usize) {
        self.awaiting.push_back(peer);
    }

    fn is_listening(&self) -> bool {
        self.state == State::Listening
    }

    fn require_connection(&mut self) -> Result<&mut Connection> {
        if let Some(connection) = &mut self.connection {
            Ok(connection)
        } else {
            log::error!(
                "Socket (id: {}): connection is None in require_connection",
                self.primary_id
            );
            Err(Error::new(EPROTO))
        }
    }

    fn require_connected_connection(&mut self) -> Result<&mut Connection> {
        match self.state {
            State::Established | State::Accepted => self.require_connection(),
            State::Closed => Err(Error::new(EPIPE)),
            _ => Err(Error::new(ENOTCONN)),
        }
    }

    fn start_listening(&mut self) -> Result<()> {
        if !matches!(self.state, State::Unbound | State::Bound) {
            log::error!(
                "start_listening(id: {}): Socket cannot listen in state {:?}.",
                self.primary_id,
                self.state
            );
            return Err(Error::new(EINVAL));
        }
        self.state = State::Listening;
        Ok(())
    }

    fn serialize_to_msgstream(
        &mut self,
        stream: &mut [u8],
        name_buf_size: usize,
        iov_size: usize,
    ) -> Result<usize> {
        let options = self.options.clone();
        let connection = self.require_connected_connection()?;
        connection.serialize_to_msgstream(stream, name_buf_size, iov_size, options)
    }
}

pub struct UdsStreamScheme<'sock> {
    sockets: HashMap<usize, Rc<RefCell<Socket>>>,
    next_id: usize,
    socket_paths: HashMap<String, Rc<RefCell<Socket>>>,
    socket: &'sock SchemeSocket,
}

impl<'sock> UdsStreamScheme<'sock> {
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
            Ok(true) => Ok(()),                   // Write response success
            Ok(false) => Err(Error::new(EAGAIN)), // Write response failed, retry.
            Err(err) => Err(err),                 // Error writing response
        }
    }

    fn get_socket(&self, id: usize) -> Result<&Rc<RefCell<Socket>>, Error> {
        self.sockets.get(&id).ok_or(Error::new(EBADF))
    }

    fn get_connected_peer(&self, id: usize) -> Result<(usize, Rc<RefCell<Socket>>), Error> {
        let mut socket = self.get_socket(id)?.borrow_mut();

        let remote_id = socket.require_connected_connection()?.peer;
        let remote_rc = self.get_socket(remote_id).map_err(|e| {
            log::error!("get_connected_peer(id: {}): Peer socket (id: {}) has vanished. Original error: {:?}", id, remote_id, e);
            Error::new(EPIPE)
        })?;

        if remote_rc.borrow().state == State::Closed {
            log::error!(
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
        let new = Socket::new(new_id, None, State::Unbound, HashSet::new(), flags, None);
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

        if self.socket_paths.contains_key(&path) {
            log::error!("handle_bind: Path '{}' is already in use.", path);
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

    // There are three phases of connecting a socket:
    //
    // Phase 1: The listener is bound but not yet listening.
    //          The client is trying to connect.
    //          If the listener is not listening, the client will block
    //          and wait until the listener starts listening.
    //
    // Phase 2: The listener is now listening.
    //          The client is still trying to connect.
    //          The client pushes its ID to the listener's awaiting queue
    //          and sets its state to `Connecting`.
    //          The client then blocks, waiting for the listener to accept it.
    //
    // Phase 3: The listener accepts the client, changes its state to `Established`,
    //          and then changes the client's state to `Accepted`.
    //          The client detects that its state has changed to `Accepted`
    //          and changes its own state to `Established`.
    //
    // After these three phases, the socket connection is considered established.
    //
    // After these three phases, the socket connection is considered established.
    //
    // The reason why `connect` is complicated is that if the processing blocks,
    // the SQE will be pushed back to the scheme's request queue,
    // and the same SQE will be woken up later.
    fn handle_connect(&mut self, id: usize, path_buf: &[u8]) -> Result<usize> {
        let path = path_buf_to_string(path_buf)?;
        let (listener_id, flags) = {
            let listener_rc = self
                .socket_paths
                .get(&path)
                .ok_or_else(|| Error::new(ECONNREFUSED))?;

            let client_rc = self.get_socket(id)?;
            let mut client = client_rc.borrow_mut();

            match client.state {
                State::Connecting => {
                    // If the client is already Connecting
                    // Fence to prevent calling connect multiple times.
                    return Err(Error::new(EWOULDBLOCK));
                }
                State::Established => {
                    return Err(Error::new(EISCONN));
                }
                State::Accepted => {
                    // Phase 3: Socket is already connected
                    client.state = State::Established;
                    return Ok(0);
                }
                _ => {}
            }

            // Phase 1: listener is bound but not yet listening
            let mut listener = listener_rc.borrow_mut();
            let listener_id = listener.primary_id;

            listener.connect(id, client.flags)?;
            // Phase 2: listener is now listening
            client.state = State::Connecting;

            (listener_id, client.flags)
        };
        // smoltcp sends writeable whenever a listener gets a
        // client, we'll do the same too (but also readable, why
        // not)
        self.post_fevent(listener_id, (EVENT_READ | EVENT_WRITE).bits())?;

        // Blocking pattern
        if flags & O_NONBLOCK == 0 {
            return Err(Error::new(EWOULDBLOCK));
        }

        // Non-blocking pattern
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
                    "socket_setsockopt(id: {}): Unsupported option: {}",
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
                        "socket_getsockopt(id: {}): SO_DOMAIN payload buffer is too small. len: {}",
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
                    "socket_getsockopt(id: {}): Unsupported option: {}",
                    id,
                    option
                );
                Err(Error::new(ENOPROTOOPT))
            }
        }
    }

    fn handle_sendmsg(&mut self, id: usize, msg_stream: &[u8], ctx: &CallerCtx) -> Result<usize> {
        if msg_stream.is_empty() {
            log::error!("msg_stream is empty, returning EINVAL.");
            return Err(Error::new(EINVAL));
        }

        let name = self.get_socket(id)?.borrow().path.clone();
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

        let connection = socket.require_connected_connection()?;
        let packet = DataPacket::from_stream(msg_stream, name, ctx)?;
        let payload_len = packet.len();
        connection.packets.push_back(packet);

        Ok(payload_len)
    }

    fn handle_recvmsg(&mut self, id: usize, msg_stream: &mut [u8]) -> Result<usize> {
        let socket_rc = self.get_socket(id)?;
        let mut socket = socket_rc.borrow_mut();
        let flags = socket.flags;
        let connection = match &mut socket.state {
            State::Established | State::Accepted => socket.require_connection()?,
            State::Closed => {
                // Remote dropped, send EOF
                return Self::write_eof(msg_stream);
            }
            State::Listening => {
                log::warn!("socket_recvmsg: Called on a listening socket, returning EOPNOTSUPP.");
                return Err(Error::new(EOPNOTSUPP));
            }
            _ => return Err(Error::new(ENOTCONN)),
        };

        if connection.packets.is_empty() {
            return if connection.is_peer_shutdown {
                // EOF, no data to read
                return Self::write_eof(msg_stream);
            } else if (flags as usize) & O_NONBLOCK == O_NONBLOCK {
                Err(Error::new(EAGAIN))
            } else {
                Err(Error::new(EWOULDBLOCK))
            };
        }
        Self::recvmsg_inner(&mut socket, msg_stream)
    }

    fn write_eof(buffer: &mut [u8]) -> Result<usize> {
        // Write EOF to the buffer
        let target = buffer.get_mut(..MIN_RECV_MSG_LEN).ok_or_else(|| {
            log::error!("write_eof: Buffer is too small to write EOF, returning EINVAL.");
            Error::new(EINVAL)
        })?;
        target.fill(0); // Fill the buffer with zeros to indicate EOF
        Ok(MIN_RECV_MSG_LEN)
    }

    fn recvmsg_inner(socket: &mut Socket, msg_stream: &mut [u8]) -> Result<usize> {
        let (prepared_name_len, prepared_whole_iov_size, _) = read_msghdr_info(msg_stream)?;

        let written_len = socket.serialize_to_msgstream(
            msg_stream,
            prepared_name_len,
            prepared_whole_iov_size,
        )?;

        Ok(written_len)
    }

    fn accept_connection(
        &mut self,
        listener_socket: &mut Socket,
        client_id: usize,
    ) -> Result<Option<OpenResult>> {
        let (new_id, new) = {
            let Ok(client_rc) = self.get_socket(client_id) else {
                return Ok(None); // Client socket has been closed, nothing to accept
            };
            let new_id = self.next_id;
            let new = listener_socket.accept(new_id, client_id)?;

            let mut client_socket = client_rc.borrow_mut();
            client_socket.establish(new_id)?;
            (new_id, new)
        };

        self.next_id += 1;
        self.sockets.insert(new_id, Rc::new(RefCell::new(new)));
        self.post_fevent(client_id, (EVENT_READ | EVENT_WRITE).bits())?;
        Ok(Some(OpenResult::ThisScheme {
            number: new_id,
            flags: NewFdFlags::empty(),
        }))
    }

    fn handle_accept(&mut self, id: usize, socket: &mut Socket) -> Result<Option<OpenResult>> {
        let flags = socket.flags;
        if !socket.is_listening() {
            log::error!(
                "socket_accept: Socket state is not Listening for id: {}",
                id
            );
            return Err(Error::new(EINVAL));
        }
        // Try to accept a waiting connection
        let Some(client_id) = socket.awaiting.pop_front() else {
            if flags & O_NONBLOCK == O_NONBLOCK {
                return Ok(Some(OpenResult::WouldBlock));
            } else {
                return Err(Error::new(EWOULDBLOCK));
            }
        };
        Ok(self.accept_connection(socket, client_id)?)
    }

    // Transition a Bound or Unbound socket to the Listening state.
    fn handle_start_listening(&mut self, socket_rc: &Rc<RefCell<Socket>>) -> Result<()> {
        let path = {
            let mut socket = socket_rc.borrow_mut();
            socket.start_listening()?;
            socket.path.clone()
        };

        if let Some(path) = path {
            if let Some(existing_socket_rc) = self.socket_paths.get(&path) {
                if !Rc::ptr_eq(socket_rc, existing_socket_rc) {
                    log::error!("handle_start_listening: Path '{}' is already in use.", path);
                    return Err(Error::new(EADDRINUSE));
                }
            }
            self.socket_paths.insert(path, socket_rc.clone());
        }
        Ok(())
    }

    // Handle a `dup` call for `b"listen"`.
    // If the socket is not yet listening, it transitions it to the Listening state.
    // If it is already listening, it tries to accept a pending connection.
    fn handle_listen(&mut self, id: usize) -> Result<OpenResult> {
        loop {
            let socket_rc = self.get_socket(id)?.clone();
            let is_listening = socket_rc.borrow().is_listening();

            if is_listening {
                let mut socket = socket_rc.borrow_mut();
                match self.handle_accept(id, &mut socket)? {
                    Some(result) => return Ok(result),
                    None => continue,
                }
            } else {
                self.handle_start_listening(&socket_rc)?;
                continue;
            }
        }
    }

    fn handle_connect_socketpair(&mut self, id: usize) -> Result<OpenResult> {
        let new_id = self.next_id;
        let flags = self.get_socket(id)?.borrow().flags;
        let new = Socket::new(new_id, None, State::Connecting, HashSet::new(), flags, None);
        {
            let socket_rc = self.get_socket(id)?;
            let mut socket = socket_rc.borrow_mut();

            if socket.state == State::Closed {
                log::error!(
                    "socket_connect_socketpair: Base socket {} is already closed.",
                    id
                );
                return Err(Error::new(EPIPE));
            }
            socket.connect_socketpair(new_id);
        }

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

        match socket.state {
            State::Established | State::Accepted => {
                let connection = socket.require_connected_connection()?;
                let fd = connection.fds.pop_front().ok_or(Error::new(EWOULDBLOCK))?;
                Ok(OpenResult::OtherScheme { fd })
            }
            State::Closed => Err(Error::new(EPIPE)),
            State::Listening => Err(Error::new(EOPNOTSUPP)),
            _ => Err(Error::new(ENOTCONN)),
        }
    }

    fn write_inner(&mut self, receiver_id: usize, buf: &[u8], ctx: &CallerCtx) -> Result<usize> {
        let receiver_rc = self.get_socket(receiver_id)?;
        let mut receiver = receiver_rc.borrow_mut();
        let name = receiver.path.clone();

        let connection = receiver.require_connected_connection()?;

        if !buf.is_empty() {
            // Send readable only if it wasn't readable before
            let ancillary_data = AncillaryData::new(
                Credential::new(ctx.pid as i32, ctx.uid as i32, ctx.gid as i32),
                name,
            );
            let packet = DataPacket::new(buf.to_vec(), ancillary_data);
            connection.packets.push_back(packet);
            self.post_fevent(receiver_id, EVENT_READ.bits())?;
        }

        Ok(buf.len())
    }

    fn sendfd_inner(
        &mut self,
        receiver_id: usize,
        sendfd_request: &SendFdRequest,
    ) -> Result<usize> {
        let mut new_fd = usize::MAX;
        if let Err(e) =
            sendfd_request.obtain_fd(&self.socket, FobtainFdFlags::empty(), Err(&mut new_fd))
        {
            log::error!("sendfd_inner: obtain_fd failed with error: {:?}", e);
            return Err(e);
        }
        let receiver_rc = self.get_socket(receiver_id)?;
        let mut receiver = receiver_rc.borrow_mut();

        let connection = receiver.require_connected_connection()?;
        connection.fds.push_back(new_fd);

        self.post_fevent(receiver_id, EVENT_READ.bits())?;

        Ok(new_fd)
    }

    fn read_inner(connection: &mut Connection, buf: &mut [u8], flags: u32) -> Result<usize> {
        let mut total_copied_len = 0;
        let mut user_buf_offset = 0;

        while user_buf_offset < buf.len() {
            let Some(packet) = connection.packets.front_mut() else {
                // No more packets to read
                break;
            };

            let packet_rem_payload = &packet.payload[packet.read_offset..];

            let user_buf_rem_len = buf.len() - user_buf_offset;

            let copied_len = cmp::min(packet_rem_payload.len(), user_buf_rem_len);
            if copied_len == 0 {
                // No more data to read from this packet
                break;
            }
            buf[user_buf_offset..user_buf_offset + copied_len]
                .copy_from_slice(&packet_rem_payload[..copied_len]);

            if packet.read_offset == 0 {
                packet.ancillary_taken = true; // Mark ancillary data as taken
            }

            packet.read_offset += copied_len;
            user_buf_offset += copied_len;
            total_copied_len += copied_len;
            if packet.read_offset >= packet.payload.len() {
                // If the packet is fully read, remove it from the queue
                connection.packets.pop_front();
            }
        }

        if total_copied_len > 0 {
            Ok(total_copied_len)
        } else if connection.is_peer_shutdown {
            Ok(0) // EOF, no data to read
        } else if (flags as usize) & O_NONBLOCK == O_NONBLOCK {
            Err(Error::new(EAGAIN))
        } else {
            Err(Error::new(EWOULDBLOCK))
        }
    }

    fn handle_listening_closure(&mut self, socket_rc: Rc<RefCell<Socket>>) {
        let socket = socket_rc.borrow();
        if let Some(path) = &socket.path {
            self.socket_paths.remove(path);
        }

        // Notify all waiting clients about listener closure
        for client_id in &socket.awaiting {
            if let Ok(client_rc) = self.get_socket(*client_id) {
                let mut client = client_rc.borrow_mut();
                client.state = State::Closed;
                let _ = self.post_fevent(*client_id, EVENT_READ.bits());

                drop(client);
            }
        }
    }

    fn handle_other_closure(&mut self, socket_rc: Rc<RefCell<Socket>>) {
        // If this is the last reference to the socket, it's safe to remove the socket path.
        if matches!(
            socket_rc.borrow().state,
            State::Established | State::Accepted
        ) {
            let mut socket = socket_rc.borrow_mut();
            let Ok(connection) = socket.require_connection() else {
                return;
            };
            let Ok(remote_rc) = self.get_socket(connection.peer) else {
                return;
            };
            let mut remote = remote_rc.borrow_mut();
            let Ok(connection) = remote.require_connection() else {
                return;
            };
            connection.is_peer_shutdown = true;
            let _ = self.post_fevent(remote.primary_id, EVENT_READ.bits());
        }

        if Rc::strong_count(&socket_rc) == 2 {
            if let Some(path) = socket_rc.borrow().path.clone() {
                // If this is the last reference to the socket, remove the path from the registry
                self.socket_paths.remove(&path);
            }
        }
        socket_rc.borrow_mut().state = State::Closed;
    }

    fn fpath_inner(path: &String, buf: &mut [u8]) -> Result<usize> {
        // Write scheme name
        const PREFIX: &[u8] = b"/scheme/uds_stream/";
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
}

impl<'sock> SchemeSync for UdsStreamScheme<'sock> {
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
            b"listen" => self.handle_listen(id),
            b"connect" => self.handle_connect_socketpair(id),
            b"recvfd" => self.handle_recvfd(id),
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
        let (receiver_id, _) = self.get_connected_peer(id)?;
        self.write_inner(receiver_id, buf, ctx)
    }

    fn fpath(&mut self, id: usize, buf: &mut [u8], _ctx: &CallerCtx) -> Result<usize> {
        let socket_rc = self.get_socket(id)?;
        let socket = socket_rc.borrow();

        let path = socket.path.as_ref().ok_or(Error::new(EBADF))?;
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
        let socket_rc = self.get_socket(id)?;
        let mut socket = socket_rc.borrow_mut();

        match socket.state {
            State::Established | State::Accepted => {
                let connection = socket.require_connected_connection()?;
                Self::read_inner(connection, buf, flags)
            }
            State::Closed => Ok(0),
            State::Listening => Err(Error::new(EOPNOTSUPP)),
            _ => Err(Error::new(ENOTCONN)),
        }
    }

    fn on_sendfd(&mut self, sendfd_request: &SendFdRequest) -> Result<usize> {
        let id = sendfd_request.id();
        let (receiver_id, _) = self.get_connected_peer(id)?;

        self.sendfd_inner(receiver_id, sendfd_request)
    }

    fn on_close(&mut self, id: usize) {
        let Some(socket_rc) = self.sockets.remove(&id) else {
            return;
        };

        let state = socket_rc.borrow().state;
        match state {
            State::Listening => {
                self.handle_listening_closure(socket_rc);
            }
            _ => {
                self.handle_other_closure(socket_rc);
            }
        }
    }

    fn fcntl(&mut self, id: usize, cmd: usize, arg: usize, _ctx: &CallerCtx) -> Result<usize> {
        let socket_rc = self.get_socket(id)?;
        let mut socket = socket_rc.borrow_mut();
        match cmd {
            F_GETFL => Ok(socket.flags),
            F_SETFL => {
                socket.flags = arg;
                Ok(0)
            }
            _ => Err(Error::new(EINVAL)),
        }
    }
}
