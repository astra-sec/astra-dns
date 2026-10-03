//! Linux UDP reception with the post-NAT local destination preserved per packet.

use std::io;
use std::mem::{self, size_of};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::os::fd::AsRawFd;
use std::ptr;

use socket2::SockAddr;
use tokio::io::Interest;
use tokio::net::UdpSocket;

/// The local endpoint AFTER any DNAT/REDIRECT, not the client's original DNS target.
/// Using this address for the reply lets conntrack apply reverse NAT, including ports.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct PacketInfo {
    pub(super) local_addr: IpAddr,
    pub(super) if_index: u32,
}

pub(super) struct PacketSocket {
    socket: UdpSocket,
    ipv6: bool,
}

// Linux control messages use size_t alignment (including musl, where the Rust
// cmsghdr type itself can have weaker alignment). The zero-length field gives
// the storage that alignment without placing any bytes before `bytes`.
#[repr(C)]
struct ControlBuffer {
    alignment: [usize; 0],
    bytes: [u8; 128],
}

impl ControlBuffer {
    fn new() -> Self {
        Self {
            alignment: [],
            bytes: [0; 128],
        }
    }
}

impl PacketSocket {
    pub(super) fn new(socket: UdpSocket) -> io::Result<Self> {
        let ipv6 = socket.local_addr()?.is_ipv6();
        let (level, option) = if ipv6 {
            (libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO)
        } else {
            (libc::IPPROTO_IP, libc::IP_PKTINFO)
        };
        let enabled: libc::c_int = 1;
        // SAFETY: `enabled` is a valid, initialized integer of the supplied size;
        // the owned Tokio socket keeps this fd alive throughout the call.
        let result = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                level,
                option,
                ptr::from_ref(&enabled).cast(),
                size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if result == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { socket, ipv6 })
    }

    /// InvalidData means that one malformed/unsupported datagram was consumed.
    /// The caller should discard it and continue receiving subsequent datagrams.
    pub(super) async fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr, PacketInfo)> {
        loop {
            self.socket.readable().await?;
            match self
                .socket
                .try_io(Interest::READABLE, || self.recv_once(buf))
            {
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                result => return result,
            }
        }
    }

    pub(super) async fn send(
        &self,
        buf: &[u8],
        peer: SocketAddr,
        info: PacketInfo,
    ) -> io::Result<usize> {
        validate_info(info, self.ipv6)?;
        if peer.is_ipv6() != self.ipv6 {
            return Err(invalid_data("UDP peer and socket address families differ"));
        }
        loop {
            self.socket.writable().await?;
            match self
                .socket
                .try_io(Interest::WRITABLE, || self.send_once(buf, peer, info))
            {
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                result => return result,
            }
        }
    }

    fn recv_once(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr, PacketInfo)> {
        // SAFETY: these C structs consist entirely of integer/pointer fields for
        // which zero is valid. All pointers below remain valid until recvmsg ends.
        let mut address: libc::sockaddr_storage = unsafe { mem::zeroed() };
        let mut message: libc::msghdr = unsafe { mem::zeroed() };
        let mut control = ControlBuffer::new();
        let mut vector = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        message.msg_name = ptr::from_mut(&mut address).cast();
        message.msg_namelen = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        message.msg_iov = ptr::from_mut(&mut vector);
        message.msg_iovlen = 1;
        message.msg_control = control.bytes.as_mut_ptr().cast();
        message.msg_controllen = control.bytes.len() as _;
        // SAFETY: message and every referenced buffer are valid writable storage.
        let received = unsafe { libc::recvmsg(self.socket.as_raw_fd(), &mut message, 0) };
        if received == -1 {
            return Err(io::Error::last_os_error());
        }
        if message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
            return Err(invalid_data("truncated UDP datagram or packet metadata"));
        }
        let peer = decode_peer(&address, message.msg_namelen)?;
        if peer.is_ipv6() != self.ipv6 {
            return Err(invalid_data("UDP peer and socket address families differ"));
        }
        // musl uses socklen_t here, while glibc uses size_t.
        #[allow(clippy::unnecessary_cast)]
        let control_length = message.msg_controllen as usize;
        if control_length > control.bytes.len() {
            return Err(invalid_data("invalid UDP control buffer length"));
        }
        let info = decode_info(&control.bytes[..control_length], self.ipv6)?;
        Ok((received as usize, peer, info))
    }

    fn send_once(&self, buf: &[u8], peer: SocketAddr, info: PacketInfo) -> io::Result<usize> {
        let address = SockAddr::from(peer);
        let mut control = ControlBuffer::new();
        // SAFETY: a zeroed msghdr is valid; all pointers set below live until sendmsg returns.
        let mut message: libc::msghdr = unsafe { mem::zeroed() };
        let mut vector = libc::iovec {
            // sendmsg does not modify iov data, despite the C ABI using a mutable pointer.
            iov_base: buf.as_ptr().cast_mut().cast(),
            iov_len: buf.len(),
        };
        message.msg_name = address.as_ptr().cast_mut().cast();
        message.msg_namelen = address.len();
        message.msg_iov = ptr::from_mut(&mut vector);
        message.msg_iovlen = 1;

        match info.local_addr {
            IpAddr::V4(local_addr) => {
                let packet_info = libc::in_pktinfo {
                    ipi_ifindex: info.if_index as libc::c_int,
                    // On receipt ipi_spec_dst is the local unicast destination.
                    // On send it selects the source address; ipi_addr is ignored.
                    ipi_spec_dst: libc::in_addr {
                        s_addr: u32::from_ne_bytes(local_addr.octets()),
                    },
                    ipi_addr: libc::in_addr { s_addr: 0 },
                };
                message.msg_controllen = fill_control(
                    &mut control,
                    libc::IPPROTO_IP,
                    libc::IP_PKTINFO,
                    packet_info,
                ) as _;
            }
            IpAddr::V6(local_addr) => {
                let packet_info = libc::in6_pktinfo {
                    ipi6_addr: libc::in6_addr {
                        s6_addr: local_addr.octets(),
                    },
                    ipi6_ifindex: info.if_index,
                };
                message.msg_controllen = fill_control(
                    &mut control,
                    libc::IPPROTO_IPV6,
                    libc::IPV6_PKTINFO,
                    packet_info,
                ) as _;
            }
        }
        message.msg_control = control.bytes.as_mut_ptr().cast();
        // SAFETY: message references initialized address/control data and readable payload.
        let sent = unsafe { libc::sendmsg(self.socket.as_raw_fd(), &message, 0) };
        if sent == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(sent as usize)
        }
    }
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn validate_info(info: PacketInfo, ipv6: bool) -> io::Result<()> {
    let valid_address = match info.local_addr {
        IpAddr::V4(address) => {
            !ipv6 && !address.is_unspecified() && !address.is_multicast() && !address.is_broadcast()
        }
        IpAddr::V6(address) => {
            ipv6 && !address.is_unspecified()
                && !address.is_multicast()
                && address.to_ipv4_mapped().is_none()
        }
    };
    if !valid_address || info.if_index == 0 || (!ipv6 && info.if_index > i32::MAX as u32) {
        return Err(invalid_data(
            "UDP packet metadata is not a local unicast endpoint",
        ));
    }
    Ok(())
}

fn decode_peer(
    address: &libc::sockaddr_storage,
    length: libc::socklen_t,
) -> io::Result<SocketAddr> {
    match libc::c_int::from(address.ss_family) {
        libc::AF_INET if length as usize >= size_of::<libc::sockaddr_in>() => {
            // SAFETY: sockaddr_storage is sufficiently large and the family and
            // kernel-returned length identify a completely initialized sockaddr_in.
            let address =
                unsafe { ptr::read_unaligned(ptr::from_ref(address).cast::<libc::sockaddr_in>()) };
            Ok(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes())),
                u16::from_be(address.sin_port),
            ))
        }
        libc::AF_INET6 if length as usize >= size_of::<libc::sockaddr_in6>() => {
            // SAFETY: same length/family guarantee as for AF_INET above.
            let address =
                unsafe { ptr::read_unaligned(ptr::from_ref(address).cast::<libc::sockaddr_in6>()) };
            let ip = Ipv6Addr::from(address.sin6_addr.s6_addr);
            if ip.to_ipv4_mapped().is_some() {
                return Err(invalid_data(
                    "IPv4-mapped peers require the IPv4 UDP listener",
                ));
            }
            Ok(SocketAddr::V6(SocketAddrV6::new(
                ip,
                u16::from_be(address.sin6_port),
                u32::from_be(address.sin6_flowinfo),
                address.sin6_scope_id,
            )))
        }
        _ => Err(invalid_data("invalid UDP peer address")),
    }
}

fn decode_info(control: &[u8], ipv6: bool) -> io::Result<PacketInfo> {
    let mut offset = 0;
    let mut result = None;
    // SAFETY: CMSG_LEN computes a size only and does not dereference pointers.
    let header_length = unsafe { libc::CMSG_LEN(0) } as usize;
    while control.len().saturating_sub(offset) >= size_of::<libc::cmsghdr>() {
        // SAFETY: the loop condition ensures the complete header is in the slice.
        // read_unaligned also permits unit tests to pass ordinary byte slices.
        let header =
            unsafe { ptr::read_unaligned(control.as_ptr().add(offset).cast::<libc::cmsghdr>()) };
        // musl uses socklen_t here, while glibc uses size_t.
        #[allow(clippy::unnecessary_cast)]
        let length = header.cmsg_len as usize;
        if length < header_length || length > control.len() - offset {
            return Err(invalid_data("invalid UDP ancillary message length"));
        }
        let payload = &control[offset + header_length..offset + length];
        let info = match (header.cmsg_level, header.cmsg_type) {
            (libc::IPPROTO_IP, libc::IP_PKTINFO) => {
                if ipv6 || payload.len() != size_of::<libc::in_pktinfo>() {
                    return Err(invalid_data("invalid IPv4 UDP packet metadata"));
                }
                // SAFETY: payload length was validated, and integer-only pktinfo
                // permits every bit pattern. Unaligned access avoids alignment assumptions.
                let packet =
                    unsafe { ptr::read_unaligned(payload.as_ptr().cast::<libc::in_pktinfo>()) };
                let local = Ipv4Addr::from(packet.ipi_spec_dst.s_addr.to_ne_bytes());
                let destination = Ipv4Addr::from(packet.ipi_addr.s_addr.to_ne_bytes());
                // A broadcast/multicast destination must never become a reply's
                // source. Directed broadcasts differ from the local ipi_spec_dst.
                if destination != local || packet.ipi_ifindex <= 0 {
                    return Err(invalid_data("non-unicast IPv4 UDP destination"));
                }
                Some(PacketInfo {
                    local_addr: IpAddr::V4(local),
                    if_index: packet.ipi_ifindex as u32,
                })
            }
            (libc::IPPROTO_IPV6, libc::IPV6_PKTINFO) => {
                if !ipv6 || payload.len() != size_of::<libc::in6_pktinfo>() {
                    return Err(invalid_data("invalid IPv6 UDP packet metadata"));
                }
                // SAFETY: same initialized, length-checked integer-only payload as above.
                let packet =
                    unsafe { ptr::read_unaligned(payload.as_ptr().cast::<libc::in6_pktinfo>()) };
                Some(PacketInfo {
                    local_addr: IpAddr::V6(Ipv6Addr::from(packet.ipi6_addr.s6_addr)),
                    if_index: packet.ipi6_ifindex,
                })
            }
            _ => None,
        };
        if let Some(info) = info {
            validate_info(info, ipv6)?;
            if result.replace(info).is_some() {
                return Err(invalid_data("duplicate UDP packet metadata"));
            }
        }
        // libc aligns Linux control messages to size_t, including on 32-bit targets.
        let alignment = size_of::<usize>();
        offset += (length + alignment - 1) & !(alignment - 1);
    }
    result.ok_or_else(|| invalid_data("missing UDP local destination metadata"))
}

/// Fill the sole cmsg in our 128-byte, cmsghdr-aligned control buffer.
fn fill_control<T>(
    control: &mut ControlBuffer,
    level: libc::c_int,
    kind: libc::c_int,
    data: T,
) -> usize {
    assert!(
        size_of::<T>() <= 64,
        "packet metadata exceeds control buffer"
    );
    // SAFETY: these macros only calculate sizes. The payload bound above ensures
    // the entire message fits, including the header and alignment padding.
    let length = unsafe { libc::CMSG_SPACE(size_of::<T>() as libc::c_uint) } as usize;
    let header_length = unsafe { libc::CMSG_LEN(0) } as usize;
    assert!(length <= control.bytes.len());
    // SAFETY: ControlBuffer is cmsghdr-aligned and the lengths were checked.
    // write_unaligned handles arbitrary T alignment without typed references.
    unsafe {
        let header = control.bytes.as_mut_ptr().cast::<libc::cmsghdr>();
        (*header).cmsg_level = level;
        (*header).cmsg_type = kind;
        (*header).cmsg_len = libc::CMSG_LEN(size_of::<T>() as libc::c_uint) as _;
        ptr::write_unaligned(
            control.bytes.as_mut_ptr().add(header_length).cast::<T>(),
            data,
        );
    }
    length
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    async fn bounded<T>(future: impl Future<Output = T>) -> T {
        tokio::time::timeout(Duration::from_secs(5), future)
            .await
            .expect("UDP test timed out")
    }

    fn test_control<T>(level: libc::c_int, kind: libc::c_int, data: T) -> (ControlBuffer, usize) {
        let mut control = ControlBuffer::new();
        let length = fill_control(&mut control, level, kind, data);
        (control, length)
    }

    #[tokio::test]
    async fn ipv4_preserves_destination_for_concurrent_requests_from_one_peer() {
        let socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        let server = Arc::new(PacketSocket::new(socket).unwrap());
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addresses = [Ipv4Addr::new(127, 0, 0, 1), Ipv4Addr::new(127, 0, 0, 2)];
        for (index, address) in addresses.iter().enumerate() {
            client
                .send_to(&[index as u8], SocketAddr::from((*address, port)))
                .await
                .unwrap();
        }
        let mut replies = Vec::new();
        for _ in 0..2 {
            let mut buffer = [0; 16];
            let (size, peer, info) = bounded(server.recv(&mut buffer)).await.unwrap();
            assert_eq!(info.local_addr, IpAddr::V4(addresses[buffer[0] as usize]));
            assert_eq!(size, 1);
            replies.push((buffer[0], peer, info));
        }
        // Reverse order and send from independent tasks: no client-keyed mutable
        // state may overwrite the destination saved for the first query.
        let mut tasks = Vec::new();
        for (id, peer, info) in replies.into_iter().rev() {
            let server = server.clone();
            tasks.push(tokio::spawn(async move {
                server.send(&[id], peer, info).await.unwrap()
            }));
        }
        let mut seen = [false; 2];
        for _ in 0..2 {
            let mut buffer = [0; 16];
            let (size, source) = bounded(client.recv_from(&mut buffer)).await.unwrap();
            assert_eq!(size, 1);
            let index = buffer[0] as usize;
            assert_eq!(source, SocketAddr::from((addresses[index], port)));
            seen[index] = true;
        }
        assert_eq!(seen, [true, true]);
        for task in tasks {
            assert_eq!(task.await.unwrap(), 1);
        }
    }

    #[tokio::test]
    async fn ipv6_preserves_loopback_source_and_port() {
        let socket = UdpSocket::bind("[::]:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        let server = PacketSocket::new(socket).unwrap();
        let client = UdpSocket::bind("[::1]:0").await.unwrap();
        client
            .send_to(b"request", (Ipv6Addr::LOCALHOST, port))
            .await
            .unwrap();
        let mut buffer = [0; 32];
        let (size, peer, info) = bounded(server.recv(&mut buffer)).await.unwrap();
        assert_eq!(info.local_addr, IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_ne!(info.if_index, 0);
        assert_eq!(size, 7);
        server.send(b"response", peer, info).await.unwrap();
        let (size, source) = bounded(client.recv_from(&mut buffer)).await.unwrap();
        assert_eq!(&buffer[..size], b"response");
        assert_eq!(source, SocketAddr::from((Ipv6Addr::LOCALHOST, port)));
    }

    #[tokio::test]
    async fn truncated_datagram_is_discarded_without_poisoning_next_request() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let server = PacketSocket::new(socket).unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(&[0; 32], address).await.unwrap();
        let mut buffer = [0; 8];
        let error = bounded(server.recv(&mut buffer)).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        client.send_to(b"valid", address).await.unwrap();
        let (size, _, _) = bounded(server.recv(&mut buffer)).await.unwrap();
        assert_eq!(&buffer[..size], b"valid");
    }

    #[test]
    fn missing_short_and_wrong_family_metadata_are_rejected() {
        assert!(decode_info(&[], false).is_err());
        let packet = libc::in6_pktinfo {
            ipi6_addr: libc::in6_addr {
                s6_addr: Ipv6Addr::LOCALHOST.octets(),
            },
            ipi6_ifindex: 1,
        };
        let (control, length) = test_control(libc::IPPROTO_IPV6, libc::IPV6_PKTINFO, packet);
        assert!(decode_info(&control.bytes[..length], true).is_ok());
        assert!(decode_info(&control.bytes[..length], false).is_err());
        assert!(decode_info(&control.bytes[..length / 2], true).is_err());
    }

    #[test]
    fn broadcast_multicast_unspecified_and_mapped_destinations_are_rejected() {
        for address in [
            IpAddr::V4(Ipv4Addr::BROADCAST),
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            IpAddr::V6("ff02::1".parse().unwrap()),
            IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped()),
        ] {
            assert!(
                validate_info(
                    PacketInfo {
                        local_addr: address,
                        if_index: 1
                    },
                    address.is_ipv6()
                )
                .is_err()
            );
        }
        let packet = libc::in_pktinfo {
            ipi_ifindex: 1,
            ipi_spec_dst: libc::in_addr {
                s_addr: u32::from_ne_bytes([192, 168, 80, 1]),
            },
            ipi_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes([192, 168, 80, 255]),
            },
        };
        let (control, length) = test_control(libc::IPPROTO_IP, libc::IP_PKTINFO, packet);
        assert!(decode_info(&control.bytes[..length], false).is_err());
    }
}
