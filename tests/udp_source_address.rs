//! Exercise the executable's UDP ingress, not a standalone Hickory server.
//!
//! The multi-address regression needs Linux, where all of 127.0.0.0/8 is local
//! without configuring aliases. IPv6 REDIRECT still needs an external Linux
//! network-namespace/router test with two local IPv6 addresses: ::1 alone does
//! not exercise conntrack's reverse-NAT matching.

#![cfg(unix)]

use std::{
    fs,
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use hickory_proto::{
    op::{Edns, Message, MessageType, OpCode, Query, ResponseCode},
    rr::{Name, RData, Record, RecordType, rdata::A},
};
use tokio::{
    net::UdpSocket,
    task::JoinHandle,
    time::{Instant, sleep, timeout},
};

static NEXT_TEST: AtomicU64 = AtomicU64::new(0);
const QUERY_TIMEOUT: Duration = Duration::from_secs(3);

struct RunningServer {
    child: Child,
    port: u16,
    directory: PathBuf,
}

impl RunningServer {
    async fn start(ipv6: bool, upstream: Option<SocketAddr>) -> Self {
        // Keep both protocol ports reserved until immediately before spawning.
        let udp_reservation = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        let port = udp_reservation.local_addr().unwrap().port();
        let tcp_reservation = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port)).unwrap();
        let directory = std::env::temp_dir().join(format!(
            "astra-udp-source-{}-{}",
            std::process::id(),
            NEXT_TEST.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&directory).unwrap();
        let config = directory.join("named.yaml");
        fs::write(
            &config,
            format!(
                r#"
listen_addrs_ipv4: ["0.0.0.0"]
listen_addrs_ipv6: {ipv6_addrs}
listen_port: {port}
disable_tcp: true
log_level: Info
filter_cache_dir: {cache:?}
filter_refresh_interval_secs: 0
lan_hosts:
  enabled: false
user_rules:
  - "||ads.test^"
filtering:
  blocking_mode: nxdomain
  rewrites:
    - domain: local.test
      answer: 192.0.2.42
dns:
  upstream_dns: ["{upstream}"]
  cache_size: 128
"#,
                ipv6_addrs = if ipv6 { "[\"::\"]" } else { "[]" },
                cache = directory.join("filter-cache"),
                upstream = upstream.unwrap_or_else(|| "127.0.0.1:9".parse().unwrap()),
            ),
        )
        .unwrap();
        let log = fs::File::create(directory.join("server.log")).unwrap();
        drop(tcp_reservation);
        drop(udp_reservation);
        // Cross-compiled test executables can run against a staged Linux core.
        let executable = std::env::var_os("ASTRA_DNS_TEST_BINARY")
            .unwrap_or_else(|| env!("CARGO_BIN_EXE_astra-dns").into());
        let child = Command::new(executable)
            .args(["--workers", "2", "--config"])
            .arg(config)
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap();
        let mut server = Self {
            child,
            port,
            directory,
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            server.assert_alive();
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let probe = request(1, "local.test.").to_vec().unwrap();
            socket.send_to(&probe, server.ipv4(1)).await.unwrap();
            let mut buf = [0; 512];
            if let Ok(Ok((len, source))) =
                timeout(Duration::from_millis(100), socket.recv_from(&mut buf)).await
            {
                assert_eq!(source, server.ipv4(1));
                assert_local_answer(&Message::from_vec(&buf[..len]).unwrap(), 1);
                break;
            }
            assert!(
                Instant::now() < deadline,
                "UDP-only listeners did not start:\n{}",
                server.log(),
            );
        }
        server
    }

    fn ipv4(&self, last_octet: u8) -> SocketAddr {
        (Ipv4Addr::new(127, 0, 0, last_octet), self.port).into()
    }

    fn log(&self) -> String {
        fs::read_to_string(self.directory.join("server.log")).unwrap_or_default()
    }

    fn assert_alive(&mut self) {
        let status = self.child.try_wait().unwrap();
        assert!(status.is_none(), "Astra exited {status:?}:\n{}", self.log());
    }

    fn signal(&self, signal: libc::c_int) {
        // The live Child handle supplies our own child's PID, not a process found
        // by name. Calling kill with this positive PID targets only that child.
        assert_eq!(
            unsafe { libc::kill(self.child.id() as libc::pid_t, signal) },
            0
        );
    }

    async fn stop(&mut self) {
        self.assert_alive();
        self.signal(libc::SIGTERM);
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(
                    status.success(),
                    "unclean shutdown {status}:\n{}",
                    self.log()
                );
                break;
            }
            assert!(Instant::now() < deadline, "shutdown hung:\n{}", self.log());
            sleep(Duration::from_millis(10)).await;
        }
        // The UDP-only task must participate in shutdown and release its socket.
        let rebound = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, self.port)).unwrap();
        drop(rebound);
    }
}

impl Drop for RunningServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn request(id: u16, name: &str) -> Message {
    let mut message = Message::new(id, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
    message
}

async fn exchange(socket: &UdpSocket, target: SocketAddr, bytes: &[u8]) -> (Message, usize) {
    socket.send_to(bytes, target).await.unwrap();
    let mut buf = vec![0; 65535];
    let (len, source) = timeout(QUERY_TIMEOUT, socket.recv_from(&mut buf))
        .await
        .expect("DNS response timed out")
        .unwrap();
    assert_eq!(
        source, target,
        "reply used the wrong source address or port"
    );
    (Message::from_vec(&buf[..len]).unwrap(), len)
}

fn assert_local_answer(message: &Message, id: u16) {
    assert_eq!(message.metadata.id, id);
    assert_eq!(message.metadata.message_type, MessageType::Response);
    assert_eq!(message.metadata.response_code, ResponseCode::NoError);
    assert_eq!(message.answers.len(), 1);
    assert_eq!(
        message.answers[0].data,
        RData::A(A("192.0.2.42".parse().unwrap()))
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn wildcard_udp_preserves_each_destination_from_one_client_port() {
    let mut server = RunningServer::start(false, None).await;
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // A connected client rejects replies sourced from 127.0.0.1 when it queried
    // 127.0.0.2. Use recv_from instead so failure names the incorrect source.
    let (response, _) = exchange(
        &socket,
        server.ipv4(2),
        &request(2, "local.test.").to_vec().unwrap(),
    )
    .await;
    assert_local_answer(&response, 2);

    // All outstanding queries use exactly the same client source port. A single
    // mutable "last local address" per socket/client cannot pass this burst.
    const COUNT: u16 = 48;
    for offset in 0..COUNT {
        socket
            .send_to(
                &request(1000 + offset, "local.test.").to_vec().unwrap(),
                server.ipv4(1 + (offset % 3) as u8),
            )
            .await
            .unwrap();
    }
    let mut seen = [false; COUNT as usize];
    let mut buf = [0; 4096];
    for _ in 0..COUNT {
        let (len, source) = timeout(QUERY_TIMEOUT, socket.recv_from(&mut buf))
            .await
            .expect("concurrent DNS reply timed out")
            .unwrap();
        let response = Message::from_vec(&buf[..len]).unwrap();
        let offset = response.metadata.id.checked_sub(1000).unwrap();
        assert!(offset < COUNT);
        assert!(!seen[usize::from(offset)], "duplicate response");
        seen[usize::from(offset)] = true;
        assert_eq!(source, server.ipv4(1 + (offset % 3) as u8));
        assert_local_answer(&response, 1000 + offset);
    }
    assert!(seen.into_iter().all(|received| received));
    server.stop().await;
}

#[tokio::test]
async fn ipv6_wildcard_udp_serves_queries_and_shuts_down() {
    let mut server = RunningServer::start(true, None).await;
    let socket = UdpSocket::bind("[::1]:0").await.unwrap();
    let target: SocketAddr = format!("[::1]:{}", server.port).parse().unwrap();
    let (response, _) = exchange(
        &socket,
        target,
        &request(3, "local.test.").to_vec().unwrap(),
    )
    .await;
    assert_local_answer(&response, 3);
    let (response, _) = exchange(&socket, target, &request(4, "ads.test.").to_vec().unwrap()).await;
    assert_eq!(response.metadata.id, 4);
    assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
    server.stop().await;
    let rebound =
        std::net::UdpSocket::bind((std::net::Ipv6Addr::UNSPECIFIED, server.port)).unwrap();
    drop(rebound);
}

#[tokio::test]
async fn udp_rejects_malformed_queries_and_does_not_answer_responses() {
    let mut server = RunningServer::start(false, None).await;
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target = server.ipv4(1);

    // A valid header declares one question, but the question is missing.
    let malformed = [0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    let (response, _) = exchange(&socket, target, &malformed).await;
    assert_eq!(response.metadata.id, 0x1234);
    assert_eq!(response.metadata.message_type, MessageType::Response);
    assert_eq!(response.metadata.response_code, ResponseCode::FormErr);

    let mut not_a_query = request(5, "local.test.");
    not_a_query.metadata.message_type = MessageType::Response;
    for bytes in [vec![0x12, 0x34], not_a_query.to_vec().unwrap()] {
        socket.send_to(&bytes, target).await.unwrap();
        let mut buf = [0; 4096];
        assert!(
            timeout(Duration::from_millis(150), socket.recv_from(&mut buf))
                .await
                .is_err(),
            "short packets and DNS responses must not elicit a reply",
        );
    }
    #[cfg(target_os = "linux")]
    {
        // Ignore QR=Response before parsing the body, so malformed responses
        // cannot trigger a FORMERR reflection loop. The legacy non-Linux
        // Hickory ingress does not yet provide this stronger guarantee.
        let mut malformed_response = malformed;
        malformed_response[2] |= 0x80;
        socket.send_to(&malformed_response, target).await.unwrap();
        let mut buf = [0; 4096];
        assert!(
            timeout(Duration::from_millis(150), socket.recv_from(&mut buf))
                .await
                .is_err(),
            "a Response header with a malformed body must not elicit FORMERR",
        );
    }
    let (response, _) = exchange(
        &socket,
        target,
        &request(6, "local.test.").to_vec().unwrap(),
    )
    .await;
    assert_local_answer(&response, 6);
    server.stop().await;
}

#[tokio::test]
async fn udp_only_listener_survives_sighup_and_retains_source_address() {
    let mut server = RunningServer::start(false, None).await;
    let pid = server.child.id();
    let config_path = server.directory.join("named.yaml");
    let config = fs::read_to_string(&config_path).unwrap();
    fs::write(&config_path, config.replace("192.0.2.42", "192.0.2.43")).unwrap();
    server.signal(libc::SIGHUP);
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target = server.ipv4(if cfg!(target_os = "linux") { 2 } else { 1 });
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        server.assert_alive();
        let (response, _) = exchange(
            &socket,
            target,
            &request(7, "local.test.").to_vec().unwrap(),
        )
        .await;
        assert_eq!(response.metadata.id, 7);
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        if response.answers[0].data == RData::A(A("192.0.2.43".parse().unwrap())) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "reload did not take effect:\n{}",
            server.log()
        );
        sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(server.child.id(), pid);
    server.stop().await;
}

struct LargeAnswerUpstream {
    addr: SocketAddr,
    task: JoinHandle<()>,
}

// Exceeds the downstream legacy 512-byte limit, but fits the resolver's
// upstream EDNS budget (normally 1232 bytes). Sending 80 records would violate
// that separate budget and test upstream packet loss instead of server encoding.
const LARGE_ANSWER_COUNT: u8 = 40;

impl LargeAnswerUpstream {
    async fn start() -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut buf = [0; 65535];
            loop {
                let (len, peer) = socket.recv_from(&mut buf).await.unwrap();
                let query = Message::from_vec(&buf[..len]).unwrap();
                let payload_limit = usize::from(query.max_payload());
                let name = query.queries[0].name().clone();
                let mut response =
                    Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
                response.metadata.recursion_available = true;
                response.queries = query.queries;
                response.edns = query.edns;
                for last_octet in 1..=LARGE_ANSWER_COUNT {
                    response.add_answer(Record::from_rdata(
                        name.clone(),
                        60,
                        RData::A(A(Ipv4Addr::new(192, 0, 2, last_octet))),
                    ));
                }
                let bytes = response.to_vec().unwrap();
                assert!(
                    bytes.len() <= payload_limit,
                    "mock upstream response must fit the resolver's advertised UDP size",
                );
                socket.send_to(&bytes, peer).await.unwrap();
            }
        });
        Self { addr, task }
    }
}

impl Drop for LargeAnswerUpstream {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[tokio::test]
async fn udp_response_encoding_preserves_edns_and_truncation_limits() {
    let upstream = LargeAnswerUpstream::start().await;
    let mut server = RunningServer::start(false, Some(upstream.addr)).await;
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target = server.ipv4(if cfg!(target_os = "linux") { 2 } else { 1 });

    let (response, len) = exchange(
        &socket,
        target,
        &request(8, "large.test.").to_vec().unwrap(),
    )
    .await;
    assert_eq!(response.metadata.id, 8);
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert!(
        len <= 512,
        "non-EDNS UDP response exceeded 512 bytes: {len}"
    );
    assert!(response.metadata.truncation, "large response must set TC");

    let mut query = request(9, "large.test.");
    let mut edns = Edns::new();
    edns.set_max_payload(4096);
    query.set_edns(edns);
    let (response, len) = exchange(&socket, target, &query.to_vec().unwrap()).await;
    assert_eq!(response.metadata.id, 9);
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert!(response.edns.is_some(), "EDNS negotiation was lost");
    assert!(
        !response.metadata.truncation,
        "EDNS response was unnecessarily truncated"
    );
    assert_eq!(response.answers.len(), usize::from(LARGE_ANSWER_COUNT));
    assert!((513..=4096).contains(&len));
    server.stop().await;
}
