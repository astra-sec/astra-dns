//! Explicit, read-only probe for a separately prepared Linux NAT test setup.
//!
//! Example (the endpoints must already serve local.test -> 192.0.2.42):
//! ASTRA_DNS_TEST_SOURCE='[fd00::2]:0' \
//! ASTRA_DNS_TEST_ENDPOINTS='[fd00::1]:15553,[2001:db8::1]:15553,[fd00::1]:15353' \
//! cargo test --test udp_nat_probe -- --ignored --nocapture
//!
//! This does not spawn Astra, create interfaces, or change firewall rules. The
//! caller is responsible for preparing direct and redirected endpoints. Running
//! the compiled test executable on Linux requires no privileges of its own when
//! binding to an unprivileged source port.

use std::{net::SocketAddr, time::Duration};

use hickory_proto::{
    op::{Message, MessageType, OpCode, Query, ResponseCode},
    rr::{Name, RData, RecordType, rdata::A},
};
use tokio::{net::UdpSocket, time::timeout};

#[tokio::test]
#[ignore = "requires explicitly prepared external DNS/NAT endpoints and ASTRA_DNS_TEST_* environment"]
async fn one_client_port_preserves_every_direct_or_redirected_endpoint() {
    let source: SocketAddr = std::env::var("ASTRA_DNS_TEST_SOURCE")
        .expect("set ASTRA_DNS_TEST_SOURCE to the client's bind SocketAddr, e.g. [fd00::2]:0")
        .parse()
        .expect("ASTRA_DNS_TEST_SOURCE must be a SocketAddr");
    let endpoints: Vec<SocketAddr> = std::env::var("ASTRA_DNS_TEST_ENDPOINTS")
        .expect("set ASTRA_DNS_TEST_ENDPOINTS to comma-separated DNS SocketAddr endpoints")
        .split(',')
        .map(|value| {
            value
                .trim()
                .parse()
                .expect("every ASTRA_DNS_TEST_ENDPOINTS item must be a SocketAddr")
        })
        .collect();
    assert!(!endpoints.is_empty(), "at least one endpoint is required");
    for endpoint in &endpoints {
        assert_eq!(
            endpoint.is_ipv4(),
            source.is_ipv4(),
            "all endpoints must have the same address family as the source",
        );
        assert_ne!(endpoint.port(), 0, "DNS endpoint ports must be nonzero");
    }

    let socket = UdpSocket::bind(source)
        .await
        .expect("could not bind the requested client address");
    println!(
        "Sending 96 concurrent requests from {} to {:?}",
        socket.local_addr().unwrap(),
        endpoints,
    );
    const BASE_ID: u16 = 41000;
    const COUNT: usize = 96;
    let expected: Vec<SocketAddr> = (0..COUNT)
        .map(|offset| endpoints[offset % endpoints.len()])
        .collect();

    timeout(Duration::from_secs(5), async {
        // Queue every request before receiving any replies. The socket is not
        // connected: incorrect reply sources must be reported, not filtered out
        // by the kernel. All queries share one client address and source port.
        for (offset, endpoint) in expected.iter().copied().enumerate() {
            let mut request =
                Message::new(BASE_ID + offset as u16, MessageType::Query, OpCode::Query);
            request.metadata.recursion_desired = true;
            request.add_query(Query::query(
                Name::from_ascii("local.test.").unwrap(),
                RecordType::A,
            ));
            socket
                .send_to(&request.to_vec().unwrap(), endpoint)
                .await
                .expect("failed to send DNS probe");
        }

        let mut seen = [false; COUNT];
        let mut buf = [0; 4096];
        for _ in 0..COUNT {
            let (len, peer) = socket
                .recv_from(&mut buf)
                .await
                .expect("failed to receive DNS probe reply");
            let response = Message::from_vec(&buf[..len]).expect("invalid DNS response");
            let offset = response
                .metadata
                .id
                .checked_sub(BASE_ID)
                .map(usize::from)
                .filter(|offset| *offset < COUNT)
                .expect("reply has an ID not issued by this probe");
            assert!(
                !seen[offset],
                "duplicate reply for ID {}",
                response.metadata.id
            );
            seen[offset] = true;
            assert_eq!(
                peer, expected[offset],
                "ID {}: reply source IP/port does not match the queried endpoint",
                response.metadata.id,
            );
            assert_eq!(response.metadata.message_type, MessageType::Response);
            assert_eq!(response.metadata.response_code, ResponseCode::NoError);
            assert_eq!(response.answers.len(), 1);
            assert_eq!(
                response.answers[0].data,
                RData::A(A("192.0.2.42".parse().unwrap())),
            );
        }
        assert!(seen.into_iter().all(|received| received));
    })
    .await
    .expect("all 96 DNS replies must arrive within five seconds");
}
