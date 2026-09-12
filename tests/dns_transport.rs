use std::{net::SocketAddr, time::Duration};

use astra_dns::{CompiledRuleSets, Config};
use hickory_proto::{
    op::{Message, MessageType, OpCode, Query, ResponseCode},
    rr::{
        Name, RData, Record, RecordType,
        rdata::{A, CNAME},
    },
};
use hickory_server::{Server, zone_handler::Catalog};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    time::timeout,
};

async fn query(addr: SocketAddr, name: &str, tcp: bool) -> Message {
    let mut message = Message::new(1234, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
    let bytes = message.to_vec().unwrap();
    let response = timeout(Duration::from_secs(5), async {
        if tcp {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            stream.write_u16(bytes.len() as u16).await.unwrap();
            stream.write_all(&bytes).await.unwrap();
            let size = stream.read_u16().await.unwrap();
            let mut response = vec![0; usize::from(size)];
            stream.read_exact(&mut response).await.unwrap();
            response
        } else {
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            socket.connect(addr).await.unwrap();
            socket.send(&bytes).await.unwrap();
            let mut response = vec![0; 65535];
            let size = socket.recv(&mut response).await.unwrap();
            response.truncate(size);
            response
        }
    })
    .await
    .expect("DNS query timed out");
    let response = Message::from_vec(&response).unwrap();
    assert_eq!(response.metadata.id, 1234);
    response
}

#[tokio::test]
async fn filtering_and_forwarding_survive_transport_migration() {
    // A local upstream makes the forwarding and rewrite checks independent of public DNS.
    let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move {
        let mut buf = vec![0; 65535];
        loop {
            let (len, peer) = upstream.recv_from(&mut buf).await.unwrap();
            let request = Message::from_vec(&buf[..len]).unwrap();
            let name = request.queries[0].name().clone();
            let mut response =
                Message::new(request.metadata.id, MessageType::Response, OpCode::Query);
            response.metadata.recursion_available = true;
            response.queries = request.queries;
            let target = if name.to_ascii() == "cname.test." {
                let target = Name::from_ascii("cdn.test.").unwrap();
                response.add_answer(Record::from_rdata(
                    name,
                    60,
                    RData::CNAME(CNAME(target.clone())),
                ));
                target
            } else {
                name
            };
            let ip = if target.to_ascii() == "rewrite.test." {
                "192.0.2.10"
            } else {
                "203.0.113.10"
            };
            response.add_answer(Record::from_rdata(
                target,
                60,
                RData::A(A(ip.parse().unwrap())),
            ));
            upstream
                .send_to(&response.to_vec().unwrap(), peer)
                .await
                .unwrap();
        }
    });

    let config = Config::from_yaml(&format!(
        r#"
dns:
  upstream_dns: ["{upstream_addr}"]
lan_hosts:
  enabled: false
user_rules:
  - "||ads.test^"
filtering:
  blocking_mode: nxdomain
  rewrites:
    - domain: local.test
      answer: 192.168.82.1
    - ip: ["192.0.2.0/24"]
      answer: 192.168.82.2
    - cname: ["domain:cdn.test"]
      answer: 192.168.82.3
"#
    ))
    .unwrap();
    let rules = CompiledRuleSets::validate(config.adblock_runtime_config().unwrap()).unwrap();
    let mut catalog = Catalog::new();
    for zone in config.zones() {
        catalog.upsert(
            zone.zone().unwrap().into(),
            zone.load(Some(&rules)).await.unwrap(),
        );
    }
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let socket = UdpSocket::bind(addr).await.unwrap();
    let mut server = Server::new(catalog);
    server.register_socket(socket);
    server.register_listener(listener, Duration::from_secs(5), 32);
    let shutdown = server.shutdown_token().clone();
    let server_task = tokio::spawn(async move { server.block_until_done().await });

    for tcp in [false, true] {
        for (name, expected) in [
            ("local.test.", "192.168.82.1"),
            ("rewrite.test.", "192.168.82.2"),
            ("cname.test.", "192.168.82.3"),
            ("forward.test.", "203.0.113.10"),
        ] {
            let response = query(addr, name, tcp).await;
            assert_eq!(response.metadata.response_code, ResponseCode::NoError);
            assert_eq!(response.answers.len(), 1, "{name}");
            assert_eq!(
                response.answers[0].data,
                RData::A(A(expected.parse().unwrap())),
                "{name}"
            );
        }
        assert_eq!(
            query(addr, "ads.test.", tcp).await.metadata.response_code,
            ResponseCode::NXDomain
        );
    }

    // Inflated record counts and truncated payloads must not prevent subsequent queries.
    let malformed = [0x12, 0x34, 1, 0, 0, 1, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.send_to(&malformed, addr).await.unwrap();
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_u16(malformed.len() as u16).await.unwrap();
    stream.write_all(&malformed).await.unwrap();
    drop(stream);
    assert_eq!(query(addr, "local.test.", false).await.answers.len(), 1);
    assert_eq!(query(addr, "local.test.", true).await.answers.len(), 1);

    shutdown.cancel();
    timeout(Duration::from_secs(5), server_task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    upstream_task.abort();
    let _ = upstream_task.await;
}
