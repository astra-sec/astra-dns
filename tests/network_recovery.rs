//! Exercise the real executable without depending on an Internet connection.

use std::{
    fs,
    net::SocketAddr,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering},
    },
    time::Duration,
};

use hickory_proto::{
    op::{Message, MessageType, OpCode, Query, ResponseCode},
    rr::{Name, RData, Record, RecordType, rdata::A},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    task::JoinHandle,
    time::{Instant, sleep, timeout},
};

static NEXT_TEST: AtomicU64 = AtomicU64::new(0);

struct RunningServer {
    child: Child,
    addr: SocketAddr,
    directory: PathBuf,
}

impl RunningServer {
    async fn start(dns: &str) -> Self {
        Self::start_with_settings(dns, "").await
    }

    async fn start_with_settings(dns: &str, additional_config: &str) -> Self {
        let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = reservation.local_addr().unwrap();
        let directory = std::env::temp_dir().join(format!(
            "astra-network-recovery-{}-{}",
            std::process::id(),
            NEXT_TEST.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&directory).unwrap();
        let config = directory.join("named.yaml");
        fs::write(
            &config,
            format!(
                r#"
listen_addrs_ipv4: ["127.0.0.1"]
listen_port: {}
log_level: Info
filter_cache_dir: {:?}
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
{dns}
{additional_config}
"#,
                addr.port(),
                directory.join("filter-cache"),
            ),
        )
        .unwrap();
        let log = fs::File::create(directory.join("server.log")).unwrap();
        drop(reservation);
        let child = Command::new(env!("CARGO_BIN_EXE_astra-dns"))
            .args(["--workers", "2", "--config"])
            .arg(config)
            .env("NO_PROXY", "127.0.0.1,localhost")
            .env("no_proxy", "127.0.0.1,localhost")
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap();
        let mut server = Self {
            child,
            addr,
            directory,
        };
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            server.assert_alive();
            if TcpStream::connect(server.addr).await.is_ok() {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "DNS listeners did not start promptly while bootstrap was unavailable:\n{}",
                server.log(),
            );
            sleep(Duration::from_millis(20)).await;
        }
        server
    }

    fn log(&self) -> String {
        fs::read_to_string(self.directory.join("server.log")).unwrap_or_default()
    }

    fn assert_alive(&mut self) {
        let status = self.child.try_wait().unwrap();
        assert!(
            status.is_none(),
            "Astra exited with {status:?}:\n{}",
            self.log(),
        );
    }

    async fn query(&mut self, name: &str, tcp: bool) -> Message {
        self.assert_alive();
        let result = query(self.addr, name, tcp).await;
        assert!(result.is_ok(), "{name}: {result:?}\n{}", self.log());
        result.unwrap()
    }
}

impl Drop for RunningServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.directory);
    }
}

async fn query(addr: SocketAddr, name: &str, tcp: bool) -> Result<Message, String> {
    let mut request = Message::new(4192, MessageType::Query, OpCode::Query);
    request.metadata.recursion_desired = true;
    request.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
    let bytes = request.to_vec().unwrap();
    let response = timeout(Duration::from_secs(3), async {
        if tcp {
            let mut stream = TcpStream::connect(addr).await?;
            stream.write_u16(bytes.len() as u16).await?;
            stream.write_all(&bytes).await?;
            let size = stream.read_u16().await?;
            let mut response = vec![0; usize::from(size)];
            stream.read_exact(&mut response).await?;
            Ok::<_, std::io::Error>(response)
        } else {
            let socket = UdpSocket::bind("127.0.0.1:0").await?;
            socket.connect(addr).await?;
            socket.send(&bytes).await?;
            let mut response = vec![0; 65535];
            let size = socket.recv(&mut response).await?;
            response.truncate(size);
            Ok(response)
        }
    })
    .await
    .map_err(|_| "DNS query timed out".to_owned())?
    .map_err(|error| error.to_string())?;
    let response = Message::from_vec(&response).map_err(|error| error.to_string())?;
    assert_eq!(response.metadata.id, 4192);
    Ok(response)
}

struct MockUpstream {
    addr: SocketAddr,
    online: Arc<AtomicBool>,
    task: JoinHandle<()>,
}

impl MockUpstream {
    async fn start(online: bool) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let online = Arc::new(AtomicBool::new(online));
        let task_online = online.clone();
        let task = tokio::spawn(async move {
            let mut buf = vec![0; 65535];
            loop {
                let (len, peer) = socket.recv_from(&mut buf).await.unwrap();
                let request = Message::from_vec(&buf[..len]).unwrap();
                let mut response =
                    Message::new(request.metadata.id, MessageType::Response, OpCode::Query);
                response.metadata.recursion_available = true;
                response.queries = request.queries;
                if task_online.load(Ordering::SeqCst) {
                    let name = response.queries[0].name().clone();
                    match name.to_ascii().as_str() {
                        "missing.test." => {
                            response.metadata.response_code = ResponseCode::NXDomain;
                        }
                        "empty.test." => {}
                        _ => {
                            response.add_answer(Record::from_rdata(
                                name,
                                60,
                                RData::A(A("203.0.113.42".parse().unwrap())),
                            ));
                        }
                    }
                } else {
                    response.metadata.response_code = ResponseCode::ServFail;
                }
                socket
                    .send_to(&response.to_vec().unwrap(), peer)
                    .await
                    .unwrap();
            }
        });
        Self { addr, online, task }
    }
}

impl Drop for MockUpstream {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct MockFilterHttp {
    addr: SocketAddr,
    // 0 stalls the response, 1 returns HTTP 503, and 2 serves the filter.
    mode: Arc<AtomicU8>,
    requests: Arc<AtomicU64>,
    failures: Arc<AtomicU64>,
    task: JoinHandle<()>,
}

impl MockFilterHttp {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mode = Arc::new(AtomicU8::new(0));
        let requests = Arc::new(AtomicU64::new(0));
        let failures = Arc::new(AtomicU64::new(0));
        let task_mode = mode.clone();
        let task_requests = requests.clone();
        let task_failures = failures.clone();
        let task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                let mut buf = [0; 1024];
                while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                    let len = stream.read(&mut buf).await.unwrap();
                    assert!(
                        len > 0,
                        "filter client closed before sending request headers"
                    );
                    request.extend_from_slice(&buf[..len]);
                    assert!(request.len() < 16_384);
                }
                task_requests.fetch_add(1, Ordering::SeqCst);
                while task_mode.load(Ordering::SeqCst) == 0 {
                    sleep(Duration::from_millis(10)).await;
                }
                let (status, body) = if task_mode.load(Ordering::SeqCst) == 2 {
                    ("200 OK", "||downloaded-filter.test^\n")
                } else {
                    task_failures.fetch_add(1, Ordering::SeqCst);
                    ("503 Service Unavailable", "temporarily unavailable\n")
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len(),
                );
                stream.write_all(response.as_bytes()).await.unwrap();
                stream.shutdown().await.unwrap();
            }
        });
        Self {
            addr,
            mode,
            requests,
            failures,
            task,
        }
    }
}

impl Drop for MockFilterHttp {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn assert_answer(response: &Message, ip: &str) {
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert_eq!(response.answers.len(), 1);
    assert_eq!(response.answers[0].data, RData::A(A(ip.parse().unwrap())));
}

#[tokio::test]
async fn unavailable_doh_bootstrap_keeps_listeners_and_local_rules_alive() {
    // Bootstrap stays on loopback, so this test never needs public DNS. The reserved
    // .invalid name must not resolve even if the host happens to run a local resolver.
    let mut server = RunningServer::start(
        r#"  upstream_dns: ["https://astra-unavailable.invalid/dns-query"]
  bootstrap_ips: ["127.0.0.1"]"#,
    )
    .await;
    let pid = server.child.id();
    for tcp in [false, true] {
        assert_answer(&server.query("local.test.", tcp).await, "192.0.2.42");
        assert_eq!(
            server.query("ads.test.", tcp).await.metadata.response_code,
            ResponseCode::NXDomain,
        );
        assert_eq!(
            server
                .query("external.test.", tcp)
                .await
                .metadata
                .response_code,
            ResponseCode::ServFail,
        );
    }

    // Survive multiple background retry opportunities, without reloading the process.
    sleep(Duration::from_secs(4)).await;
    assert_answer(&server.query("local.test.", false).await, "192.0.2.42");
    server.assert_alive();
    assert_eq!(server.child.id(), pid);
}

#[tokio::test]
async fn unavailable_doh_does_not_hold_up_an_independent_plain_upstream() {
    let upstream = MockUpstream::start(true).await;
    let mut server = RunningServer::start(&format!(
        r#"  upstream_dns:
    - "https://astra-unavailable.invalid/dns-query"
    - "{}"
  bootstrap_ips: ["127.0.0.1"]"#,
        upstream.addr,
    ))
    .await;

    for tcp in [false, true] {
        assert_answer(&server.query("forward.test.", tcp).await, "203.0.113.42");
        assert_answer(&server.query("local.test.", tcp).await, "192.0.2.42");
    }
    server.assert_alive();
}

#[tokio::test]
async fn upstream_outage_and_recovery_preserve_process_rules_and_cache() {
    let upstream = MockUpstream::start(false).await;
    let mut server = RunningServer::start(&format!(
        "  upstream_dns: [\"{}\"]\n  cache_size: 128",
        upstream.addr,
    ))
    .await;
    let pid = server.child.id();
    assert_eq!(
        server
            .query("before-recovery.test.", false)
            .await
            .metadata
            .response_code,
        ResponseCode::ServFail,
    );

    upstream.online.store(true, Ordering::SeqCst);
    assert_answer(
        &server.query("cached-answer.test.", false).await,
        "203.0.113.42",
    );

    upstream.online.store(false, Ordering::SeqCst);
    assert_answer(
        &server.query("cached-answer.test.", true).await,
        "203.0.113.42",
    );
    assert_eq!(
        server
            .query("during-outage.test.", false)
            .await
            .metadata
            .response_code,
        ResponseCode::ServFail,
    );
    assert_answer(&server.query("local.test.", true).await, "192.0.2.42");
    assert_eq!(
        server.query("ads.test.", true).await.metadata.response_code,
        ResponseCode::NXDomain,
    );

    upstream.online.store(true, Ordering::SeqCst);
    assert_answer(
        &server.query("after-recovery.test.", true).await,
        "203.0.113.42",
    );
    server.assert_alive();
    assert_eq!(server.child.id(), pid);
}

#[tokio::test]
async fn ordinary_negative_answers_preserve_upstream_and_cached_answers() {
    let upstream = MockUpstream::start(true).await;
    let mut server = RunningServer::start(&format!(
        "  upstream_dns: [\"{}\"]\n  cache_size: 128",
        upstream.addr,
    ))
    .await;
    assert_answer(
        &server.query("cached-answer.test.", false).await,
        "203.0.113.42",
    );
    for tcp in [false, true] {
        assert_eq!(
            server
                .query("missing.test.", tcp)
                .await
                .metadata
                .response_code,
            ResponseCode::NXDomain,
        );
        let empty = server.query("empty.test.", tcp).await;
        assert_eq!(empty.metadata.response_code, ResponseCode::NoError);
        assert!(empty.answers.is_empty());
    }
    upstream.online.store(false, Ordering::SeqCst);
    assert_answer(
        &server.query("cached-answer.test.", true).await,
        "203.0.113.42",
    );
    server.assert_alive();
}

#[tokio::test]
async fn missing_remote_filter_downloads_after_startup_and_recovers_without_restart() {
    let upstream = MockUpstream::start(true).await;
    let filter = MockFilterHttp::start().await;
    let mut server = RunningServer::start_with_settings(
        &format!("  upstream_dns: [\"{}\"]", upstream.addr),
        &format!(
            "filters:\n  - enabled: true\n    id: 91\n    url: http://{}/filter.txt",
            filter.addr,
        ),
    )
    .await;
    let pid = server.child.id();

    // The missing list must not hold up listening or locally configured rules,
    // even though its HTTP server accepts the request and sends no response.
    let deadline = Instant::now() + Duration::from_secs(3);
    while filter.requests.load(Ordering::SeqCst) == 0 {
        assert!(
            Instant::now() < deadline,
            "initial background filter download never started:\n{}",
            server.log(),
        );
        sleep(Duration::from_millis(20)).await;
    }
    assert_answer(&server.query("local.test.", false).await, "192.0.2.42");
    assert_eq!(
        server.query("ads.test.", true).await.metadata.response_code,
        ResponseCode::NXDomain,
    );
    assert_answer(
        &server.query("downloaded-filter.test.", false).await,
        "203.0.113.42",
    );
    assert_answer(
        &server.query("keep-cache.test.", false).await,
        "203.0.113.42",
    );

    // A failed first download must keep retrying, even with scheduled filter
    // refreshes disabled, while the existing DNS service remains available.
    filter.mode.store(1, Ordering::SeqCst);
    let deadline = Instant::now() + Duration::from_secs(8);
    while filter.failures.load(Ordering::SeqCst) < 2 {
        assert!(
            Instant::now() < deadline,
            "filter download was not retried after HTTP 503:\n{}",
            server.log(),
        );
        assert_answer(&server.query("local.test.", false).await, "192.0.2.42");
        sleep(Duration::from_millis(50)).await;
    }
    filter.mode.store(2, Ordering::SeqCst);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if server
            .query("downloaded-filter.test.", true)
            .await
            .metadata
            .response_code
            == ResponseCode::NXDomain
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "downloaded filter did not become active after HTTP recovery:\n{}",
            server.log(),
        );
        sleep(Duration::from_millis(50)).await;
    }
    assert!(server.directory.join("filter-cache/91.txt").is_file());
    upstream.online.store(false, Ordering::SeqCst);
    assert_answer(
        &server.query("keep-cache.test.", true).await,
        "203.0.113.42",
    );
    assert_answer(&server.query("local.test.", true).await, "192.0.2.42");
    server.assert_alive();
    assert_eq!(server.child.id(), pid);
}
