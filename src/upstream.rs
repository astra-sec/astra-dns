//! Forwarding stays alive while hostname-based upstreams wait for the network.
//!
//! Each upstream owns its resolver and cache. Refreshing one endpoint does not
//! discard another endpoint's cache, and a failed refresh keeps its last known
//! addresses. The rule/override chain remains usable even before any bootstrap
//! lookup succeeds.

use std::{
    collections::HashMap,
    future::Future,
    io,
    net::IpAddr,
    sync::{Arc, Mutex, OnceLock, RwLock, Weak},
    time::Duration,
};

use async_trait::async_trait;
use hickory_proto::{
    op::ResponseCode,
    rr::{LowerName, Name, RecordType, TSigResponseContext},
};
use hickory_resolver::config::{NameServerConfig, ResolverOpts};
use hickory_server::{
    net::{DnsError, NetError},
    server::{Request, RequestInfo},
    store::forwarder::{ForwardConfig, ForwardZoneHandler},
    zone_handler::{
        AuthLookup, AxfrPolicy, LookupControlFlow, LookupError, LookupOptions, ZoneHandler,
        ZoneType,
    },
};
use tokio::{
    sync::Notify,
    task::{AbortHandle, JoinSet},
    time::{Instant, sleep, sleep_until, timeout},
};
use tracing::{info, warn};

use crate::{
    CompactForwardConfig, UpstreamDnsConfig, parse_doh_endpoint, parse_plain_upstream_dns_address,
};

#[derive(Clone, Copy)]
struct RecoveryTiming {
    bootstrap_timeout: Duration,
    retry_min: Duration,
    retry_max: Duration,
    refresh_interval: Duration,
}

impl Default for RecoveryTiming {
    fn default() -> Self {
        Self {
            bootstrap_timeout: Duration::from_secs(5),
            retry_min: Duration::from_secs(1),
            retry_max: Duration::from_secs(30),
            refresh_interval: Duration::from_secs(300),
        }
    }
}

struct ReadyUpstream {
    addresses: Vec<IpAddr>,
    forwarder: Arc<ForwardZoneHandler>,
    trust_negative_responses: bool,
}

#[derive(Default)]
struct UpstreamSlot {
    ready: RwLock<Option<ReadyUpstream>>,
    refresh: Arc<Notify>,
}

pub(crate) struct RecoveringForwarder {
    origin: LowerName,
    slots: Vec<Arc<UpstreamSlot>>,
    tasks: Vec<AbortHandle>,
}

impl RecoveringForwarder {
    pub(crate) fn shared(origin: Name, config: &CompactForwardConfig) -> Result<Arc<Self>, String> {
        // Filter refreshes and equivalent SIGHUP reloads reuse the live
        // forwarding state. Weak entries do not keep obsolete workers alive.
        static FORWARDERS: OnceLock<Mutex<HashMap<String, Weak<RecoveringForwarder>>>> =
            OnceLock::new();
        let key = format!("{origin}:{config:?}");
        let mut shared = FORWARDERS
            .get_or_init(Mutex::default)
            .lock()
            .expect("forwarder registry lock poisoned");
        shared.retain(|_, handler| handler.strong_count() > 0);
        if let Some(handler) = shared.get(&key).and_then(Weak::upgrade) {
            return Ok(handler);
        }
        let handler = Arc::new(Self::new(origin, config)?);
        shared.insert(key, Arc::downgrade(&handler));
        Ok(handler)
    }

    pub(crate) fn new(origin: Name, config: &CompactForwardConfig) -> Result<Self, String> {
        if config.upstream_dns.is_empty() {
            return Err("dns.upstream_dns must contain at least one upstream".to_owned());
        }

        // Keep the configured cache budget across the independent resolvers.
        let mut options = config.options.clone().unwrap_or_default();
        options.cache_size /= config.upstream_dns.len() as u64;
        let mut handler = Self {
            origin: origin.clone().into(),
            slots: Vec::new(),
            tasks: Vec::new(),
        };

        for upstream in &config.upstream_dns {
            let slot = Arc::new(UpstreamSlot::default());
            let needs_bootstrap = match upstream {
                UpstreamDnsConfig::Address(address) if address.starts_with("https://") => {
                    parse_doh_endpoint(address)?
                        .tls_dns_name
                        .parse::<IpAddr>()
                        .is_err()
                }
                _ => false,
            };

            if needs_bootstrap {
                let weak_slot = Arc::downgrade(&slot);
                let source = upstream.clone();
                let bootstrap_ips = config.bootstrap_ips.clone();
                let task_origin = origin.clone();
                let task_options = options.clone();
                let label = match upstream {
                    UpstreamDnsConfig::Address(address) => address.clone(),
                    _ => unreachable!(),
                };
                let task = tokio::spawn(async move {
                    recover_upstream(
                        weak_slot,
                        task_origin,
                        task_options,
                        label,
                        RecoveryTiming::default(),
                        || source.resolve_name_server_configs(&bootstrap_ips),
                    )
                    .await;
                });
                handler.tasks.push(task.abort_handle());
            } else {
                let servers = match upstream {
                    UpstreamDnsConfig::Detailed(server) => vec![server.clone()],
                    UpstreamDnsConfig::Address(address) if address.starts_with("https://") => {
                        let endpoint = parse_doh_endpoint(address)?;
                        let ip = endpoint
                            .tls_dns_name
                            .parse::<IpAddr>()
                            .map_err(|err| format!("invalid DoH IP address: {err}"))?;
                        crate::doh_name_server_configs(endpoint, vec![ip])
                    }
                    UpstreamDnsConfig::Address(address) => {
                        vec![parse_plain_upstream_dns_address(address)?]
                    }
                };
                install_upstream(&slot, &origin, &options, servers)?;
            }
            handler.slots.push(slot);
        }
        Ok(handler)
    }
}

impl Drop for RecoveringForwarder {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

fn install_upstream(
    slot: &UpstreamSlot,
    origin: &Name,
    options: &ResolverOpts,
    servers: Vec<NameServerConfig>,
) -> Result<bool, String> {
    let mut addresses: Vec<_> = servers.iter().map(|server| server.ip).collect();
    addresses.sort_unstable();
    addresses.dedup();
    if addresses.is_empty() {
        return Err("upstream resolved to no addresses".to_owned());
    }
    // This slot's protocol/SNI/options never change. Avoid rebuilding its
    // resolver (and dropping its cache) when a refresh finds the same IPs.
    if slot
        .ready
        .read()
        .expect("upstream lock poisoned")
        .as_ref()
        .is_some_and(|ready| ready.addresses == addresses)
    {
        return Ok(false);
    }
    let trust_negative_responses = servers.iter().all(|server| server.trust_negative_responses);
    let forwarder = ForwardZoneHandler::builder_tokio(ForwardConfig {
        name_servers: servers,
        options: Some(options.clone()),
    })
    .with_origin(origin.clone())
    .build()?;
    *slot.ready.write().expect("upstream lock poisoned") = Some(ReadyUpstream {
        addresses,
        forwarder: Arc::new(forwarder),
        trust_negative_responses,
    });
    Ok(true)
}

async fn recover_upstream<F, Fut>(
    slot: Weak<UpstreamSlot>,
    origin: Name,
    options: ResolverOpts,
    label: String,
    timing: RecoveryTiming,
    resolve: F,
) where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<Vec<NameServerConfig>, String>>,
{
    let Some(refresh) = slot.upgrade().map(|slot| slot.refresh.clone()) else {
        return;
    };
    let mut backoff = timing.retry_min;
    let mut failing = false;
    loop {
        if slot.strong_count() == 0 {
            return;
        }
        let started = Instant::now();
        let result = match timeout(timing.bootstrap_timeout, resolve()).await {
            Ok(result) => result,
            Err(_) => Err("bootstrap lookup timed out".to_owned()),
        };
        let Some(current) = slot.upgrade() else {
            return;
        };
        let result =
            result.and_then(|servers| install_upstream(&current, &origin, &options, servers));
        drop(current);
        let delay = match result {
            Ok(changed) => {
                if changed || failing {
                    info!(upstream = %label, "DNS upstream bootstrap is ready");
                }
                failing = false;
                backoff = timing.retry_min;
                timing.refresh_interval
            }
            Err(err) => {
                // Log the state transition; repeated retries are expected while
                // the WAN is down and must not fill OpenWrt's small log buffer.
                if !failing {
                    warn!(upstream = %label, error = %err, "DNS upstream bootstrap unavailable; retrying in background");
                }
                failing = true;
                let delay = backoff;
                backoff = (backoff * 2).min(timing.retry_max);
                delay
            }
        };
        if failing {
            // Query failures cannot defeat the backoff during a WAN outage.
            sleep(delay).await;
        } else {
            tokio::select! {
                _ = sleep(delay) => {},
                _ = refresh.notified() => {
                    sleep_until(started + timing.retry_min).await;
                },
            }
        }
    }
}

#[async_trait]
impl ZoneHandler for RecoveringForwarder {
    fn zone_type(&self) -> ZoneType {
        ZoneType::External
    }

    fn axfr_policy(&self) -> AxfrPolicy {
        AxfrPolicy::Deny
    }

    fn origin(&self) -> &LowerName {
        &self.origin
    }

    fn can_validate_dnssec(&self) -> bool {
        self.slots.iter().any(|slot| {
            slot.ready
                .read()
                .expect("upstream lock poisoned")
                .as_ref()
                .is_some_and(|ready| ready.forwarder.can_validate_dnssec())
        })
    }

    async fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        _request_info: Option<&RequestInfo<'_>>,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        let mut queries = JoinSet::new();
        for slot in &self.slots {
            let ready = slot.ready.read().expect("upstream lock poisoned");
            if let Some(ready) = ready.as_ref() {
                let forwarder = ready.forwarder.clone();
                let trust_negative = ready.trust_negative_responses;
                let refresh = slot.refresh.clone();
                let name = name.clone();
                queries.spawn(async move {
                    let result = forwarder.lookup(&name, rtype, None, lookup_options).await;
                    (result, trust_negative, refresh)
                });
            }
        }

        let mut negative = None;
        while let Some(result) = queries.join_next().await {
            let Ok((result, trust_negative, refresh)) = result else {
                continue;
            };
            match result {
                LookupControlFlow::Continue(Ok(answer)) | LookupControlFlow::Break(Ok(answer)) => {
                    return LookupControlFlow::Continue(Ok(answer));
                }
                LookupControlFlow::Continue(Err(err)) | LookupControlFlow::Break(Err(err)) => {
                    if is_negative_answer(&err) {
                        if trust_negative {
                            return LookupControlFlow::Continue(Err(err));
                        }
                        negative.get_or_insert(err);
                    } else {
                        refresh.notify_one();
                    }
                }
                LookupControlFlow::Skip => {}
            }
        }
        // An unavailable upstream is a temporary resolution failure, never an
        // NXDOMAIN answer (which clients could cache as a nonexistent name).
        LookupControlFlow::Continue(Err(
            negative.unwrap_or_else(|| ResponseCode::ServFail.into())
        ))
    }

    async fn search(
        &self,
        request: &Request,
        lookup_options: LookupOptions,
    ) -> (LookupControlFlow<AuthLookup>, Option<TSigResponseContext>) {
        let info = match request.request_info() {
            Ok(info) => info,
            Err(err) => return (LookupControlFlow::Break(Err(err)), None),
        };
        (
            self.lookup(
                info.query.name(),
                info.query.query_type(),
                Some(&info),
                lookup_options,
            )
            .await,
            None,
        )
    }

    async fn nsec_records(
        &self,
        _name: &LowerName,
        _lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        LookupControlFlow::Continue(Err(LookupError::from(io::Error::other(
            "Getting NSEC records is unimplemented for the forwarder",
        ))))
    }
}

fn is_negative_answer(error: &LookupError) -> bool {
    match error {
        LookupError::NameExists | LookupError::ResponseCode(ResponseCode::NXDomain) => true,
        LookupError::NetError(NetError::Dns(DnsError::NoRecordsFound(records))) => {
            matches!(
                records.response_code,
                ResponseCode::NXDomain | ResponseCode::NoError
            )
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use hickory_proto::{
        op::{Message, MessageType, OpCode},
        rr::{RData, Record, rdata::A},
    };
    use tokio::net::UdpSocket;

    use super::*;

    fn test_timing() -> RecoveryTiming {
        RecoveryTiming {
            bootstrap_timeout: Duration::from_millis(20),
            retry_min: Duration::from_millis(10),
            retry_max: Duration::from_millis(40),
            refresh_interval: Duration::from_secs(60),
        }
    }

    async fn wait_until(mut condition: impl FnMut() -> bool) {
        timeout(Duration::from_secs(2), async {
            while !condition() {
                sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .expect("background upstream did not reach the expected state");
    }

    async fn answer_from(handler: &RecoveringForwarder) -> LookupControlFlow<AuthLookup> {
        handler
            .lookup(
                &Name::from_ascii("recovery.test.").unwrap().into(),
                RecordType::A,
                None,
                LookupOptions::default(),
            )
            .await
    }

    #[tokio::test]
    async fn bootstrap_recovers_without_restarting_and_keeps_the_good_cache() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let servers = vec![
            parse_plain_upstream_dns_address(&socket.local_addr().unwrap().to_string()).unwrap(),
        ];
        let queries = Arc::new(AtomicUsize::new(0));
        let received = queries.clone();
        let server = tokio::spawn(async move {
            let mut buf = [0; 4096];
            loop {
                let (len, peer) = socket.recv_from(&mut buf).await.unwrap();
                received.fetch_add(1, Ordering::SeqCst);
                let request = Message::from_vec(&buf[..len]).unwrap();
                let name = request.queries[0].name().clone();
                let mut response =
                    Message::new(request.metadata.id, MessageType::Response, OpCode::Query);
                response.metadata.recursion_available = true;
                response.queries = request.queries;
                response.add_answer(Record::from_rdata(
                    name,
                    60,
                    RData::A(A("203.0.113.8".parse().unwrap())),
                ));
                socket
                    .send_to(&response.to_vec().unwrap(), peer)
                    .await
                    .unwrap();
            }
        });

        let slot = Arc::new(UpstreamSlot::default());
        let state: Arc<Mutex<Result<Vec<NameServerConfig>, String>>> =
            Arc::new(Mutex::new(Err("WAN not ready".to_owned())));
        let attempts = Arc::new(AtomicUsize::new(0));
        let source = state.clone();
        let calls = attempts.clone();
        let worker = tokio::spawn(recover_upstream(
            Arc::downgrade(&slot),
            Name::root(),
            ResolverOpts::default(),
            "test".to_owned(),
            test_timing(),
            move || {
                calls.fetch_add(1, Ordering::SeqCst);
                let result = source.lock().unwrap().clone();
                async move { result }
            },
        ));
        let handler = RecoveringForwarder {
            origin: Name::root().into(),
            slots: vec![slot.clone()],
            tasks: vec![worker.abort_handle()],
        };

        wait_until(|| attempts.load(Ordering::SeqCst) >= 2).await;
        assert!(matches!(
            answer_from(&handler).await,
            LookupControlFlow::Continue(Err(LookupError::ResponseCode(ResponseCode::ServFail)))
        ));

        *state.lock().unwrap() = Ok(servers.clone());
        wait_until(|| slot.ready.read().unwrap().is_some()).await;
        let answer = answer_from(&handler).await.unwrap();
        assert_eq!(
            &answer.iter().next().unwrap().data,
            &RData::A(A("203.0.113.8".parse().unwrap()))
        );
        assert_eq!(queries.load(Ordering::SeqCst), 1);

        let before = slot
            .ready
            .read()
            .unwrap()
            .as_ref()
            .unwrap()
            .forwarder
            .clone();
        assert!(
            !install_upstream(&slot, &Name::root(), &ResolverOpts::default(), servers).unwrap()
        );
        let after = slot
            .ready
            .read()
            .unwrap()
            .as_ref()
            .unwrap()
            .forwarder
            .clone();
        assert!(
            Arc::ptr_eq(&before, &after),
            "unchanged IPs must retain the resolver/cache"
        );

        let previous_attempts = attempts.load(Ordering::SeqCst);
        *state.lock().unwrap() = Err("WAN down again".to_owned());
        slot.refresh.notify_one();
        wait_until(|| attempts.load(Ordering::SeqCst) > previous_attempts).await;
        assert!(answer_from(&handler).await.is_continue());
        assert_eq!(
            queries.load(Ordering::SeqCst),
            1,
            "failed bootstrap must keep cached answers"
        );
        assert!(Arc::ptr_eq(
            &before,
            &slot.ready.read().unwrap().as_ref().unwrap().forwarder
        ));
        drop(handler);
        assert!(worker.await.unwrap_err().is_cancelled());
        server.abort();
    }

    #[tokio::test]
    async fn stalled_bootstrap_times_out_and_drop_cancels_retries() {
        let slot = Arc::new(UpstreamSlot::default());
        let attempts = Arc::new(AtomicUsize::new(0));
        let calls = attempts.clone();
        let worker = tokio::spawn(recover_upstream(
            Arc::downgrade(&slot),
            Name::root(),
            ResolverOpts::default(),
            "stalled".to_owned(),
            test_timing(),
            move || {
                calls.fetch_add(1, Ordering::SeqCst);
                std::future::pending::<Result<Vec<NameServerConfig>, String>>()
            },
        ));
        let handler = RecoveringForwarder {
            origin: Name::root().into(),
            slots: vec![slot],
            tasks: vec![worker.abort_handle()],
        };
        wait_until(|| attempts.load(Ordering::SeqCst) >= 3).await;
        assert!(matches!(
            answer_from(&handler).await,
            LookupControlFlow::Continue(Err(LookupError::ResponseCode(ResponseCode::ServFail)))
        ));
        drop(handler);
        assert!(worker.await.unwrap_err().is_cancelled());
        let stopped_at = attempts.load(Ordering::SeqCst);
        sleep(Duration::from_millis(80)).await;
        assert_eq!(attempts.load(Ordering::SeqCst), stopped_at);
    }

    #[tokio::test]
    async fn equivalent_reload_reuses_forwarders_and_releases_obsolete_tasks() {
        let config = CompactForwardConfig {
            upstream_dns: vec![UpstreamDnsConfig::Address(
                "https://unavailable.invalid/dns-query".to_owned(),
            )],
            bootstrap_ips: vec!["192.0.2.53".parse().unwrap()],
            options: None,
        };
        let first = RecoveringForwarder::shared(Name::root(), &config).unwrap();
        let second = RecoveringForwarder::shared(Name::root(), &config).unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        let task = first.tasks[0].clone();
        let weak = Arc::downgrade(&first);
        drop(first);
        assert!(weak.upgrade().is_some());
        drop(second);
        assert!(weak.upgrade().is_none());
        wait_until(|| task.is_finished()).await;
    }

    #[test]
    fn servfail_is_not_a_negative_dns_answer() {
        assert!(!is_negative_answer(&ResponseCode::ServFail.into()));
        assert!(is_negative_answer(&ResponseCode::NXDomain.into()));
    }
}
