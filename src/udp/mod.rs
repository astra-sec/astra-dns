// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
// Copyright 2026 Astra DNS contributors
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option.

//! Linux UDP ingress that preserves the local destination of each datagram.
//!
//! A wildcard listener may receive traffic for several local IP addresses. In
//! particular, REDIRECT can select a different local address from the one the
//! kernel would choose when replying with plain `send_to`. The reply must use
//! the *post-NAT* destination from pktinfo so conntrack can reverse the NAT.
//! DNS parsing, catalog handling and response serialization remain Hickory's.
//! This listener, like the binary's `Server::new`, has no network ACL; any future
//! application ACL must be applied to both UDP and TCP ingress.

use std::{future::Future, io, net::SocketAddr, sync::Arc};

use hickory_proto::{
    op::{Header, HeaderCounts, LowerQuery, MessageType, Metadata, OpCode, ResponseCode},
    rr::Record,
    serialize::binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder},
};
use hickory_server::{
    net::{NetError, runtime::TokioTime, xfer::Protocol},
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
    zone_handler::{MessageResponse, MessageResponseBuilder, Queries},
};
use tokio::{net::UdpSocket, task::JoinSet};
use tracing::{debug, warn};

mod pktinfo;
use pktinfo::{PacketInfo, PacketSocket};

/// A bound Linux UDP listener with packet-local reply addressing enabled.
pub struct UdpListener {
    socket: Arc<PacketSocket>,
}

impl UdpListener {
    /// Enable packet information before handing the socket to the serving loop.
    /// Failure is a startup error, not a silent fallback to incorrect replies.
    pub fn new(socket: UdpSocket) -> io::Result<Self> {
        Ok(Self {
            socket: Arc::new(PacketSocket::new(socket)?),
        })
    }

    /// Serve until shutdown, cancelling in-flight requests when the listener
    /// stops. Each response owns its received local address, even when several
    /// concurrent requests share the same client IP and port.
    pub async fn run<T: RequestHandler>(
        self,
        handler: T,
        shutdown: impl Future<Output = ()>,
    ) -> io::Result<()> {
        let handler = Arc::new(handler);
        let mut requests = JoinSet::new();
        // Accept a whole non-jumbo UDP datagram; never parse a truncated prefix.
        let mut buffer = vec![0; u16::MAX as usize];
        tokio::pin!(shutdown);

        loop {
            let packet = tokio::select! {
                biased;
                _ = &mut shutdown => return Ok(()),
                result = requests.join_next(), if !requests.is_empty() => {
                    if let Some(Err(error)) = result {
                        warn!(%error, "UDP request task failed");
                    }
                    continue;
                }
                packet = self.socket.recv(&mut buffer) => packet,
            };
            let (len, peer, packet_info) = match packet {
                Ok(packet) => packet,
                Err(error) => {
                    if matches!(error.kind(), io::ErrorKind::InvalidData) {
                        debug!(%error, "discarding UDP datagram without valid packet information");
                        continue;
                    }
                    if matches!(
                        error.kind(),
                        io::ErrorKind::NotConnected | io::ErrorKind::ConnectionAborted
                    ) || matches!(error.raw_os_error(), Some(libc::EBADF | libc::ENOTSOCK))
                    {
                        return Err(error);
                    }
                    warn!(%error, "error receiving message on UDP socket");
                    continue;
                }
            };

            if !safe_peer(peer) {
                debug!(%peer, "discarding UDP datagram with an unsafe source address");
                continue;
            }

            let bytes = buffer[..len].to_vec();
            let handler = handler.clone();
            let socket = self.socket.clone();
            requests.spawn(async move {
                handle_request(bytes, peer, packet_info, socket, handler).await;
            });
        }
    }
}

fn safe_peer(peer: SocketAddr) -> bool {
    if peer.port() == 0 || peer.ip().is_unspecified() || peer.ip().is_multicast() {
        return false;
    }
    match peer.ip() {
        std::net::IpAddr::V4(ip) => !ip.is_broadcast(),
        std::net::IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .is_none_or(|ip| !ip.is_unspecified() && !ip.is_broadcast() && !ip.is_multicast()),
    }
}

async fn handle_request<T: RequestHandler>(
    bytes: Vec<u8>,
    peer: SocketAddr,
    packet_info: PacketInfo,
    socket: Arc<PacketSocket>,
    handler: Arc<T>,
) {
    let Ok(header) = Header::read(&mut BinDecoder::new(&bytes)) else {
        // A datagram shorter than a DNS header cannot be answered safely.
        return;
    };
    // Reject QR=Response before parsing the body, including malformed responses,
    // so two DNS servers cannot reflect FORMERR responses back to each other.
    if header.message_type == MessageType::Response {
        return;
    }
    let mut response = PacketResponse {
        socket,
        peer,
        packet_info,
        request_meta: header.metadata,
        queries: Vec::new(),
    };
    let request = match Request::from_bytes(bytes, peer, Protocol::Udp) {
        Ok(request) => request,
        Err(error) => {
            debug!(id = header.id, %peer, %error, "malformed UDP DNS request");
            let queries = Queries::read(&mut BinDecoder::new(&[]), 0)
                .expect("decoding zero queries from an empty buffer cannot fail");
            let message = MessageResponseBuilder::new(&queries, None)
                .error_msg(&header, ResponseCode::FormErr);
            if let Err(error) = response.send_response(message).await {
                warn!(%peer, %error, "failed to return UDP FORMERR to client");
            }
            return;
        }
    };

    debug!(
        "request:{id} src:udp://{addr}#{port} type:{message_type} dnssec:{dnssec} {op} qflags:{qflags}",
        id = request.metadata.id,
        addr = peer.ip(),
        port = peer.port(),
        message_type = request.metadata.message_type,
        dnssec = request
            .edns
            .as_ref()
            .is_some_and(|edns| edns.flags().dnssec_ok),
        op = request.metadata.op_code,
        qflags = request.metadata.flags(),
    );
    response.queries = request.queries.queries().to_vec();
    handler
        .handle_request::<_, TokioTime>(&request, response)
        .await;
}

#[derive(Clone)]
struct PacketResponse {
    socket: Arc<PacketSocket>,
    peer: SocketAddr,
    packet_info: PacketInfo,
    request_meta: Metadata,
    queries: Vec<LowerQuery>,
}

#[async_trait::async_trait]
impl ResponseHandler for PacketResponse {
    async fn send_response<'a>(
        &mut self,
        response: MessageResponse<
            '_,
            'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
        >,
    ) -> Result<ResponseInfo, NetError> {
        // Hickory's MessageResponse::encode is crate-private. Mirror its UDP
        // policy using the public serializer: respect EDNS, set TC when records
        // don't fit, and fall back to a small SERVFAIL on serialization errors.
        let id = response.metadata().id;
        let max_size = response.edns().map_or(512, |edns| edns.max_payload());
        let mut bytes = Vec::with_capacity(512);
        let mut encoder = BinEncoder::new(&mut bytes);
        encoder.set_max_size(max_size);
        let result = response.destructive_emit(&mut encoder);
        let response_info = match result {
            Ok(info) => info,
            Err(error) => {
                warn!(%error, "error encoding UDP DNS response");
                bytes.clear();
                let mut metadata = Metadata::new(id, MessageType::Response, OpCode::Query);
                metadata.response_code = ResponseCode::ServFail;
                let header = Header {
                    metadata,
                    counts: HeaderCounts::default(),
                };
                header.emit(&mut BinEncoder::new(&mut bytes))?;
                ResponseInfo::from(header)
            }
        };

        let sent = self
            .socket
            .send(&bytes, self.peer, self.packet_info)
            .await?;
        if sent != bytes.len() {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "partial UDP response").into());
        }
        if response_info.id != self.request_meta.id {
            warn!(
                request_id = self.request_meta.id,
                response_id = response_info.id,
                "DNS response ID mismatch"
            );
        }
        // Keep per-query logs opt-in, just like the binary's Hickory log filter.
        debug!(
            "request:{id} src:udp://{addr}#{port} {op} qflags:{qflags} response:{code:?} rr:{answers}/{authorities}/{additionals} rflags:{rflags}",
            id = response_info.id,
            addr = self.peer.ip(),
            port = self.peer.port(),
            op = self.request_meta.op_code,
            qflags = self.request_meta.flags(),
            code = response_info.response_code,
            answers = response_info.counts().answers,
            authorities = response_info.counts().authorities,
            additionals = response_info.counts().additionals,
            rflags = response_info.flags(),
        );
        for query in &self.queries {
            debug!(
                "query:{query}:{qtype}:{class}",
                query = query.name(),
                qtype = query.query_type(),
                class = query.query_class()
            );
        }
        Ok(response_info)
    }
}

#[cfg(test)]
mod tests {
    use super::safe_peer;

    #[test]
    fn unsafe_sources_are_not_answered() {
        for peer in [
            "127.0.0.1:0",
            "0.0.0.0:1234",
            "255.255.255.255:1234",
            "224.0.0.1:1234",
            "[::]:1234",
            "[ff02::1]:1234",
            "[::ffff:255.255.255.255]:1234",
        ] {
            assert!(!safe_peer(peer.parse().unwrap()), "{peer}");
        }
        for peer in ["127.0.0.1:1234", "[::1]:1234", "[fe80::1%1]:1234"] {
            assert!(safe_peer(peer.parse().unwrap()), "{peer}");
        }
    }
}
