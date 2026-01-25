use smoltcp::iface::SocketHandle;
use smoltcp::socket::udp::{
    PacketBuffer as UdpSocketBuffer, PacketMetadata as UdpPacketMetadata, Socket as UdpSocket,
};
use smoltcp::wire::{IpEndpoint, IpListenEndpoint};
use std::str;
use syscall;
use syscall::{Error as SyscallError, Result as SyscallResult};

use super::socket::{Context, DupResult, SchemeFile, SchemeSocket, SocketFile};
use super::{parse_endpoint, SchemeWrapper, Smolnetd, SocketSet};
use crate::port_set::PortSet;
use crate::router::Router;
use std::fmt::Write;

const SO_SNDBUF: usize = 7;
const SO_RCVBUF: usize = 8;

pub type UdpScheme = SchemeWrapper<UdpSocket<'static>>;

impl<'a> SchemeSocket for UdpSocket<'a> {
    type SchemeDataT = PortSet;
    type DataT = IpListenEndpoint;
    type SettingT = ();

    fn new_scheme_data() -> Self::SchemeDataT {
        PortSet::new(49_152u16, 65_535u16).expect("Wrong UDP port numbers")
    }

    fn can_send(&self) -> bool {
        self.can_send()
    }

    fn can_recv(&mut self, data: &IpListenEndpoint) -> bool {
        loop {
            // If buffer is empty, we definitely can't recv
            if !UdpSocket::can_recv(self) {
                return false;
            }

            // If we are not connected to a specific remote, any packet is valid
            if !data.is_specified() {
                return true;
            }

            // If we are connected, peek at the packet.
            match self.peek() {
                Ok((_, meta)) => {
                    let source = meta.endpoint;
                    let connected_addr = data.addr.unwrap(); // Safe because is_specified() checked it

                    // Allow Broadcast special case (DHCP)
                    let is_broadcast = match connected_addr {
                        smoltcp::wire::IpAddress::Ipv4(ip) => {
                            ip == smoltcp::wire::Ipv4Address::BROADCAST
                        }
                        _ => false,
                    };

                    if !is_broadcast && !connected_addr.is_unspecified() {
                        if source.addr != connected_addr || source.port != data.port {
                            // Bad packet detetced
                            // Remove it from the buffer immediately so poll() doesn't trigger
                            let _ = self.recv();
                            continue; // Loop again to check the next packet
                        }
                    }
                    // Packet is valid
                    return true;
                }
                Err(_) => return false,
            }
        }
    }

    fn may_recv(&self) -> bool {
        true
    }

    fn hop_limit(&self) -> u8 {
        self.hop_limit().unwrap_or(64)
    }

    fn set_hop_limit(&mut self, hop_limit: u8) {
        self.set_hop_limit(Some(hop_limit));
    }

    fn get_setting(
        _file: &SocketFile<Self::DataT>,
        _setting: Self::SettingT,
        _buf: &mut [u8],
    ) -> SyscallResult<usize> {
        Ok(0)
    }

    fn set_setting(
        _file: &mut SocketFile<Self::DataT>,
        _setting: Self::SettingT,
        _buf: &[u8],
    ) -> SyscallResult<usize> {
        Ok(0)
    }

    fn new_socket(
        socket_set: &mut SocketSet,
        path: &str,
        uid: u32,
        port_set: &mut Self::SchemeDataT,
        context: &Context,
    ) -> SyscallResult<(SocketHandle, Self::DataT)> {
        let mut parts = path.split('/');
        let remote_endpoint = parse_endpoint(parts.next().unwrap_or(""));
        let mut local_endpoint = parse_endpoint(parts.next().unwrap_or(""));

        if local_endpoint.port > 0 && local_endpoint.port <= 1024 && uid != 0 {
            return Err(SyscallError::new(syscall::EACCES));
        }

        let rx_buffer = UdpSocketBuffer::new(
            vec![UdpPacketMetadata::EMPTY; Smolnetd::SOCKET_BUFFER_SIZE],
            vec![0; Router::MTU * Smolnetd::SOCKET_BUFFER_SIZE],
        );
        let tx_buffer = UdpSocketBuffer::new(
            vec![UdpPacketMetadata::EMPTY; Smolnetd::SOCKET_BUFFER_SIZE],
            vec![0; Router::MTU * Smolnetd::SOCKET_BUFFER_SIZE],
        );
        let udp_socket = UdpSocket::new(rx_buffer, tx_buffer);

        // TODO: claim port with ethernet ip address
        if local_endpoint.port == 0 {
            local_endpoint.port = port_set
                .get_port()
                .ok_or_else(|| SyscallError::new(syscall::EINVAL))?;
        } else if !port_set.claim_port(local_endpoint.port) {
            return Err(SyscallError::new(syscall::EADDRINUSE));
        }

        let socket_handle = socket_set.add(udp_socket);

        let udp_socket = socket_set.get_mut::<UdpSocket>(socket_handle);

        if remote_endpoint.is_specified() {
            let local_endpoint_addr = match local_endpoint.addr {
                Some(addr) if addr.is_unspecified() => Some(addr),
                _ => {
                    // local ip is 0.0.0.0, resolve it
                    let route_table = context.route_table.borrow();
                    let addr = route_table
                        .lookup_src_addr(&remote_endpoint.addr.expect("Checked in is_specified"));
                    if matches!(addr, None) {
                        error!("Opening a TCP connection with a probably invalid source IP as no route have been found for destination: {}", remote_endpoint);
                    }
                    addr
                }
            };
            local_endpoint = IpListenEndpoint {
                addr: local_endpoint_addr,
                port: local_endpoint.port,
            };
        }

        udp_socket
            .bind(local_endpoint)
            .expect("Can't bind udp socket to local endpoint");

        Ok((socket_handle, remote_endpoint))
    }

    fn close_file(
        &self,
        file: &SchemeFile<Self>,
        port_set: &mut Self::SchemeDataT,
    ) -> SyscallResult<()> {
        if let SchemeFile::Socket(_) = *file {
            port_set.release_port(self.endpoint().port);
        }
        Ok(())
    }

    fn write_buf(
        &mut self,
        file: &mut SocketFile<Self::DataT>,
        buf: &[u8],
    ) -> SyscallResult<usize> {
        if !file.data.is_specified() {
            return Err(SyscallError::new(syscall::EADDRNOTAVAIL));
        }
        if !file.write_enabled {
            return Err(SyscallError::new(syscall::EPIPE));
        }
        if self.can_send() {
            let endpoint = file.data;
            let endpoint = IpEndpoint::new(
                endpoint
                    .addr
                    .expect("If we can send, this should be specified"),
                endpoint.port,
            );
            self.send_slice(buf, endpoint).expect("Can't send slice");
            Ok(buf.len())
        } else if file.flags & syscall::O_NONBLOCK == syscall::O_NONBLOCK {
            Err(SyscallError::new(syscall::EAGAIN))
        } else {
            Err(SyscallError::new(syscall::EWOULDBLOCK)) // internally scheduled to re-read
        }
    }

    fn read_buf(
        &mut self,
        file: &mut SocketFile<Self::DataT>,
        buf: &mut [u8],
    ) -> SyscallResult<usize> {
        if !file.read_enabled {
            Ok(0)
        } else if self.can_recv(&file.data) {
            let (length, _) = self.recv_slice(buf).expect("Can't receive slice");
            Ok(length)
        } else if file.flags & syscall::O_NONBLOCK == syscall::O_NONBLOCK {
            Err(SyscallError::new(syscall::EAGAIN))
        } else {
            Err(SyscallError::new(syscall::EWOULDBLOCK)) // internally scheduled to re-read
        }
    }

    fn dup(
        socket_set: &mut SocketSet,
        file: &mut SchemeFile<Self>,
        path: &str,
        port_set: &mut Self::SchemeDataT,
    ) -> SyscallResult<DupResult<Self>> {
        let socket_handle = file.socket_handle();
        let file = match path {
            "listen" => {
                // there's no accept() for UDP
                return Err(SyscallError::new(syscall::EAFNOSUPPORT));
            }
            _ => {
                let remote_endpoint = parse_endpoint(path);
                if let SchemeFile::Socket(ref udp_handle) = *file {
                    SchemeFile::Socket(udp_handle.clone_with_data(
                        if remote_endpoint.is_specified() {
                            remote_endpoint
                        } else {
                            udp_handle.data
                        },
                    ))
                } else {
                    SchemeFile::Socket(SocketFile::new_with_data(socket_handle, remote_endpoint))
                }
            }
        };

        let endpoint = {
            let socket = socket_set.get::<UdpSocket>(socket_handle);
            socket.endpoint()
        };

        if let SchemeFile::Socket(_) = file {
            port_set.acquire_port(endpoint.port);
        }

        Ok(Some((file, None)))
    }

    fn fpath(&self, file: &SchemeFile<Self>, buf: &mut [u8]) -> SyscallResult<usize> {
        let unspecified = "0.0.0.0:0";
        let mut path = String::from("/scheme/udp/");

        // remote
        match file {
            SchemeFile::Socket(SocketFile { data: endpoint, .. }) => {
                if endpoint.is_specified() {
                    write!(&mut path, "{}", endpoint).unwrap()
                } else {
                    write!(&mut path, "0.0.0.0:{}", endpoint.port).unwrap()
                }
            }
            _ => path.push_str(unspecified),
        }
        path.push('/');
        // local
        let endpoint = self.endpoint();
        if endpoint.is_specified() {
            write!(&mut path, "{}", endpoint).unwrap()
        } else {
            write!(&mut path, "0.0.0.0:{}", endpoint.port).unwrap()
        }
        let path = path.as_bytes();

        let mut i = 0;
        while i < buf.len() && i < path.len() {
            buf[i] = path[i];
            i += 1;
        }

        Ok(i)
    }

    fn handle_get_peer_name(
        &self,
        file: &SchemeFile<Self>,
        buf: &mut [u8],
    ) -> SyscallResult<usize> {
        self.fpath(file, buf)
    }

    fn handle_shutdown(&mut self, file: &mut SchemeFile<Self>, how: usize) -> SyscallResult<usize> {
        let socket_file = match file {
            SchemeFile::Socket(ref mut file) => file,
            _ => return Err(SyscallError::new(syscall::EBADF)),
        };

        match how {
            0 => socket_file.read_enabled = false,  // SHUT_RD
            1 => socket_file.write_enabled = false, // SHUT_WR
            2 => {
                socket_file.read_enabled = false;
                socket_file.write_enabled = false;
            } // SHUT_RDWR
            _ => return Err(SyscallError::new(syscall::EINVAL)),
        }
        Ok(0)
    }

    fn get_sock_opt(
        &self,
        _file: &SchemeFile<Self>,
        name: usize,
        buf: &mut [u8],
    ) -> SyscallResult<usize> {
        match name {
            SO_RCVBUF => {
                let val = self.payload_recv_capacity() as i32;
                let bytes = val.to_ne_bytes();
                if buf.len() < bytes.len() {
                    return Err(SyscallError::new(syscall::EINVAL));
                }
                buf[..bytes.len()].copy_from_slice(&bytes);
                Ok(bytes.len())
            }
            SO_SNDBUF => {
                let val = self.payload_send_capacity() as i32;
                let bytes = val.to_ne_bytes();
                if buf.len() < bytes.len() {
                    return Err(SyscallError::new(syscall::EINVAL));
                }
                buf[..bytes.len()].copy_from_slice(&bytes);
                Ok(bytes.len())
            }
            _ => Err(SyscallError::new(syscall::ENOPROTOOPT)),
        }
    }
}
