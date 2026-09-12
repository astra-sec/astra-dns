// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Configuration module for the server binary, `named`.

use std::{
    fmt,
    fs::File,
    io::Read,
    net::{AddrParseError, IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::PathBuf,
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{self, Deserialize, Deserializer};

use hickory_proto::{ProtoError, rr::Name};
use hickory_resolver::{
    TokioResolver,
    config::{ConnectionConfig, NameServerConfig, ProtocolConfig, ResolverConfig, ResolverOpts},
    net::runtime::TokioRuntimeProvider,
};
use hickory_server::store::forwarder::ForwardConfig;
use hickory_server::store::forwarder::ForwardZoneHandler;
use hickory_server::zone_handler::{ZoneHandler, ZoneType};
use tracing::{debug, info, warn};
use url::{Host, Url};

mod adblock;
#[cfg(feature = "prometheus-metrics")]
mod prometheus_server;

pub use adblock::{
    AdblockRuntimeConfig, BlockingMode, CompiledRuleSets, FilterConfig, FilteringConfig,
    LanHostsConfig,
};
#[cfg(feature = "prometheus-metrics")]
pub use prometheus_server::PrometheusServer;

static DEFAULT_PORT: u16 = 53;
static DEFAULT_TCP_REQUEST_TIMEOUT: u64 = 5;
static DEFAULT_FILTER_CACHE_DIR: &str = "/tmp/astra-dns/filters-cache";
static DEFAULT_FILTER_REFRESH_INTERVAL_SECS: u64 = 86_400;

/// Server configuration
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The list of IPv4 addresses to listen on
    #[serde(default)]
    listen_addrs_ipv4: Vec<String>,
    /// This list of IPv6 addresses to listen on
    #[serde(default)]
    listen_addrs_ipv6: Vec<String>,
    /// Port on which to listen (associated to all IPs)
    listen_port: Option<u16>,
    /// Prometheus listen address
    #[cfg(feature = "prometheus-metrics")]
    prometheus_listen_addr: Option<SocketAddr>,
    /// Disable TCP protocol
    disable_tcp: Option<bool>,
    /// Disable UDP protocol
    disable_udp: Option<bool>,
    /// Disable TLS protocol
    disable_tls: Option<bool>,
    /// Disable HTTPS protocol
    disable_https: Option<bool>,
    /// Disable QUIC protocol
    disable_quic: Option<bool>,
    /// Disable Prometheus metrics
    #[cfg(feature = "prometheus-metrics")]
    disable_prometheus: Option<bool>,
    /// Timeout associated to a request before it is closed.
    tcp_request_timeout: Option<u64>,
    /// Level at which to log, default is WARN
    log_level: Option<String>,
    /// Directory for downloaded remote filter list cache files.
    filter_cache_dir: Option<PathBuf>,
    /// Interval for refreshing remote filter lists. Zero disables refreshes.
    filter_refresh_interval_secs: Option<u64>,
    /// User to run the server as.
    ///
    /// Only supported on Unix-like platforms. When both user and group are set, the server will
    /// attempt to switch to them after binding sockets.
    pub user: Option<String>,
    /// Group to run the server as.
    ///
    /// Only supported on Unix-like platforms. When both user and group are set, the server will
    /// attempt to switch to them after binding sockets.
    pub group: Option<String>,
    /// List of configurations for zones
    #[serde(default)]
    zones: Vec<ZoneConfig>,
    /// Optional AdGuard-style DNS section for simple upstream forwarding setups
    #[serde(default)]
    dns: Option<DnsConfig>,
    /// Remote filter lists inspired by AdGuard Home's `filters`
    #[serde(default)]
    filters: Vec<FilterConfig>,
    /// Local rules inspired by AdGuard Home's `user_rules`
    #[serde(default)]
    user_rules: Vec<String>,
    /// Blocking behavior inspired by AdGuard Home's `filtering`
    #[serde(default)]
    filtering: FilteringConfig,
    /// LAN hostname source, currently using dnsmasq/OpenWrt lease-file format.
    #[serde(default)]
    lan_hosts: LanHostsConfig,
}

impl Config {
    /// read a Config file from the file specified at path.
    pub fn read_config(path: &std::path::Path) -> Result<Self, serde_yaml::Error> {
        let mut file = File::open(path).unwrap();
        let mut yaml = String::new();
        file.read_to_string(&mut yaml).unwrap();
        Self::from_yaml(&yaml)
    }

    /// Read a [`Config`] from the given YAML string.
    pub fn from_yaml(yaml: &str) -> Result<Self, serde_yaml::Error> {
        let config: Self = serde_yaml::from_str(yaml)?;
        config
            .normalize()
            .map_err(<serde_yaml::Error as serde::de::Error>::custom)
    }

    /// set of listening ipv4 addresses (for TCP and UDP)
    pub fn listen_addrs_ipv4(&self) -> Result<Vec<Ipv4Addr>, AddrParseError> {
        self.listen_addrs_ipv4.iter().map(|s| s.parse()).collect()
    }

    /// set of listening ipv6 addresses (for TCP and UDP)
    pub fn listen_addrs_ipv6(&self) -> Result<Vec<Ipv6Addr>, AddrParseError> {
        self.listen_addrs_ipv6.iter().map(|s| s.parse()).collect()
    }

    /// port on which to listen for connections on specified addresses
    pub fn listen_port(&self) -> u16 {
        self.listen_port.unwrap_or(DEFAULT_PORT)
    }

    /// prometheus metric endpoint listen address
    #[cfg(feature = "prometheus-metrics")]
    pub fn prometheus_listen_addr(&self) -> SocketAddr {
        self.prometheus_listen_addr
            .unwrap_or(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 9000))
    }

    /// get if TCP protocol should be disabled
    pub fn disable_tcp(&self) -> bool {
        self.disable_tcp.unwrap_or_default()
    }

    /// get if UDP protocol should be disabled
    pub fn disable_udp(&self) -> bool {
        self.disable_udp.unwrap_or_default()
    }

    /// get if TLS protocol should be disabled
    pub fn disable_tls(&self) -> bool {
        self.disable_tls.unwrap_or_default()
    }

    /// get if HTTPS protocol should be disabled
    pub fn disable_https(&self) -> bool {
        self.disable_https.unwrap_or_default()
    }

    /// get if QUIC protocol should be disabled
    pub fn disable_quic(&self) -> bool {
        self.disable_quic.unwrap_or_default()
    }

    /// get if Prometheus metrics endpoint should be disabled
    #[cfg(feature = "prometheus-metrics")]
    pub fn disable_prometheus(&self) -> bool {
        self.disable_prometheus.unwrap_or_default()
    }

    /// default timeout for all TCP connections before forcibly shutdown
    pub fn tcp_request_timeout(&self) -> Duration {
        Duration::from_secs(
            self.tcp_request_timeout
                .unwrap_or(DEFAULT_TCP_REQUEST_TIMEOUT),
        )
    }

    /// specify the log level which should be used, ["Trace", "Debug", "Info", "Warn", "Error"]
    pub fn log_level(&self) -> tracing::Level {
        if let Some(level_str) = &self.log_level {
            tracing::Level::from_str(level_str).unwrap_or(tracing::Level::INFO)
        } else {
            tracing::Level::INFO
        }
    }

    /// the set of zones which should be loaded
    pub fn zones(&self) -> &[ZoneConfig] {
        &self.zones
    }

    pub fn filters(&self) -> &[FilterConfig] {
        &self.filters
    }

    pub fn user_rules(&self) -> &[String] {
        &self.user_rules
    }

    pub fn filtering(&self) -> &FilteringConfig {
        &self.filtering
    }

    pub fn lan_hosts(&self) -> &LanHostsConfig {
        &self.lan_hosts
    }

    pub fn filter_cache_dir(&self) -> PathBuf {
        self.filter_cache_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from(DEFAULT_FILTER_CACHE_DIR))
    }

    pub fn filter_refresh_interval_secs(&self) -> u64 {
        self.filter_refresh_interval_secs
            .unwrap_or(DEFAULT_FILTER_REFRESH_INTERVAL_SECS)
    }

    pub fn adblock_runtime_config(&self) -> Option<AdblockRuntimeConfig> {
        if !adblock::is_adblock_enabled(
            &self.filters,
            &self.user_rules,
            &self.filtering,
            &self.lan_hosts,
        ) {
            return None;
        }

        Some(AdblockRuntimeConfig {
            filters: self.filters.clone(),
            user_rules: self.user_rules.clone(),
            filtering: self.filtering.clone(),
            filter_cache_dir: self.filter_cache_dir(),
            lan_hosts: self.lan_hosts.clone(),
        })
    }

    fn normalize(mut self) -> Result<Self, String> {
        if let Some(dns) = &self.dns
            && !dns.upstream_dns.is_empty()
        {
            if !self.zones.is_empty() {
                return Err(
                    "cannot configure both `zones` and `dns.upstream_dns`; use one style"
                        .to_owned(),
                );
            }

            #[cfg(feature = "resolver")]
            {
                self.zones = vec![ZoneConfig::root_forward(dns.clone())?];
            }
        }

        Ok(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct DnsConfig {
    upstream_dns: Vec<UpstreamDnsConfig>,
    bootstrap_ips: Vec<IpAddr>,
    cache_size: Option<u64>,
    cache_ttl_min: Option<u64>,
    cache_ttl_max: Option<u64>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
enum UpstreamDnsConfig {
    Address(String),
    Detailed(#[serde(deserialize_with = "deserialize_name_server")] NameServerConfig),
}

// Keep the pre-0.26 YAML shape usable while translating it to connection configs.
fn deserialize_name_server<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<NameServerConfig, D::Error> {
    #[derive(Default, Deserialize)]
    #[serde(rename_all = "lowercase")]
    enum LegacyProtocol {
        #[default]
        Udp,
        Tcp,
        Tls,
        Https,
    }
    #[derive(Deserialize)]
    struct Legacy {
        socket_addr: SocketAddr,
        #[serde(default)]
        protocol: LegacyProtocol,
        tls_dns_name: Option<String>,
        http_endpoint: Option<String>,
        #[serde(default)]
        trust_negative_responses: bool,
        bind_addr: Option<SocketAddr>,
    }
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Compatible {
        Legacy(Legacy),
        Current(NameServerConfig),
    }
    let legacy = match Compatible::deserialize(deserializer)? {
        Compatible::Current(config) => return Ok(config),
        Compatible::Legacy(config) => config,
    };
    let server_name = legacy
        .tls_dns_name
        .unwrap_or_else(|| legacy.socket_addr.ip().to_string())
        .into();
    let mut connection = match legacy.protocol {
        LegacyProtocol::Udp => ConnectionConfig::udp(),
        LegacyProtocol::Tcp => ConnectionConfig::tcp(),
        LegacyProtocol::Tls => ConnectionConfig::tls(server_name),
        LegacyProtocol::Https => {
            ConnectionConfig::https(server_name, legacy.http_endpoint.map(Into::into))
        }
    };
    connection.port = legacy.socket_addr.port();
    connection.bind_addr = legacy.bind_addr;
    Ok(NameServerConfig::new(
        legacy.socket_addr.ip(),
        legacy.trust_negative_responses,
        vec![connection],
    ))
}

fn deserialize_forward_config<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<ForwardConfig, D::Error> {
    #[derive(Deserialize)]
    struct Server(#[serde(deserialize_with = "deserialize_name_server")] NameServerConfig);
    #[derive(Deserialize)]
    struct Config {
        name_servers: Vec<Server>,
        options: Option<ResolverOpts>,
    }
    let config = Config::deserialize(deserializer)?;
    Ok(ForwardConfig {
        name_servers: config
            .name_servers
            .into_iter()
            .map(|server| server.0)
            .collect(),
        options: config.options,
    })
}

impl UpstreamDnsConfig {
    fn validate(&self) -> Result<(), String> {
        match self {
            Self::Address(address) if address.contains("://") => {
                if address.starts_with("udp://") || address.starts_with("tcp://") {
                    parse_plain_upstream_dns_address(address).map(drop)
                } else {
                    parse_doh_endpoint(address).map(drop)
                }
            }
            Self::Address(address) => parse_plain_upstream_dns_address(address).map(drop),
            Self::Detailed(_) => Ok(()),
        }
    }

    async fn resolve_name_server_configs(
        &self,
        bootstrap_ips: &[IpAddr],
    ) -> Result<Vec<NameServerConfig>, String> {
        match self {
            Self::Address(address) if address.contains("://") => {
                if address.starts_with("udp://") || address.starts_with("tcp://") {
                    Ok(vec![parse_plain_upstream_dns_address(address)?])
                } else {
                    resolve_doh_endpoint(parse_doh_endpoint(address)?, bootstrap_ips).await
                }
            }
            Self::Address(address) => Ok(vec![parse_plain_upstream_dns_address(address)?]),
            Self::Detailed(config) => Ok(vec![config.clone()]),
        }
    }
}

fn parse_plain_upstream_dns_address(address: &str) -> Result<NameServerConfig, String> {
    let (protocol, address) = if let Some(addr) = address.strip_prefix("udp://") {
        (ProtocolConfig::Udp, addr)
    } else if let Some(addr) = address.strip_prefix("tcp://") {
        (ProtocolConfig::Tcp, addr)
    } else {
        (ProtocolConfig::Udp, address)
    };

    let socket_addr = address
        .parse::<SocketAddr>()
        .or_else(|_| address.parse::<IpAddr>().map(|ip| SocketAddr::new(ip, 53)))
        .map_err(|_| {
            format!(
                "invalid upstream DNS address `{address}`; expected `IP`, `IP:PORT`, `udp://IP:PORT`, `tcp://IP:PORT`, or an HTTPS URL"
            )
        })?;

    let mut connection = ConnectionConfig::new(protocol);
    connection.port = socket_addr.port();
    Ok(NameServerConfig::new(
        socket_addr.ip(),
        false,
        vec![connection],
    ))
}

#[derive(Debug)]
struct DnsOverHttpsEndpoint {
    tls_dns_name: String,
    port: u16,
    http_endpoint: String,
}

fn parse_doh_endpoint(address: &str) -> Result<DnsOverHttpsEndpoint, String> {
    let url = Url::parse(address)
        .map_err(|err| format!("invalid DNS-over-HTTPS URL `{address}`: {err}"))?;

    if url.scheme() != "https" {
        return Err(format!(
            "unsupported upstream DNS URL scheme `{}` in `{address}`; only `https` is supported",
            url.scheme()
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(format!(
            "DNS-over-HTTPS URL `{address}` must not contain user information"
        ));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(format!(
            "DNS-over-HTTPS URL `{address}` must not contain a query string or fragment"
        ));
    }

    let tls_dns_name = match url.host() {
        Some(Host::Domain(domain)) => domain.to_owned(),
        Some(Host::Ipv4(ip)) => ip.to_string(),
        Some(Host::Ipv6(ip)) => ip.to_string(),
        None => return Err(format!("DNS-over-HTTPS URL `{address}` is missing a host")),
    };
    let port = url
        .port_or_known_default()
        .ok_or_else(|| format!("DNS-over-HTTPS URL `{address}` is missing a port"))?;
    let http_endpoint = match url.path() {
        "" | "/" => "/dns-query".to_owned(),
        path => path.to_owned(),
    };

    Ok(DnsOverHttpsEndpoint {
        tls_dns_name,
        port,
        http_endpoint,
    })
}

async fn resolve_doh_endpoint(
    endpoint: DnsOverHttpsEndpoint,
    bootstrap_ips: &[IpAddr],
) -> Result<Vec<NameServerConfig>, String> {
    let DnsOverHttpsEndpoint {
        tls_dns_name,
        port,
        http_endpoint,
    } = endpoint;

    let mut socket_addrs: Vec<SocketAddr> = if let Ok(ip) = tls_dns_name.parse::<IpAddr>() {
        vec![SocketAddr::new(ip, port)]
    } else if bootstrap_ips.is_empty() {
        tokio::net::lookup_host((tls_dns_name.as_str(), port))
            .await
            .map_err(|err| {
                format!(
                    "failed to resolve DNS-over-HTTPS upstream `{tls_dns_name}`: {err}; configure `dns.bootstrap_ips` to avoid system DNS bootstrap"
                )
            })?
            .collect()
    } else {
        resolve_with_bootstrap_dns(&tls_dns_name, bootstrap_ips)
            .await?
            .map(|ip| SocketAddr::new(ip, port))
            .collect()
    };

    socket_addrs.sort_unstable();
    socket_addrs.dedup();
    if socket_addrs.is_empty() {
        return Err(format!(
            "DNS-over-HTTPS upstream `{tls_dns_name}` resolved to no addresses"
        ));
    }

    Ok(socket_addrs
        .into_iter()
        .map(|socket_addr| {
            let mut connection = ConnectionConfig::https(
                tls_dns_name.clone().into(),
                Some(http_endpoint.clone().into()),
            );
            connection.port = socket_addr.port();
            NameServerConfig::new(socket_addr.ip(), false, vec![connection])
        })
        .collect())
}

async fn resolve_with_bootstrap_dns(
    hostname: &str,
    bootstrap_ips: &[IpAddr],
) -> Result<impl Iterator<Item = IpAddr>, String> {
    let name_servers = bootstrap_name_server_configs(bootstrap_ips);
    let resolver = TokioResolver::builder_with_config(
        ResolverConfig::from_name_servers(name_servers),
        TokioRuntimeProvider::default(),
    )
    .build()
    .map_err(|err| format!("failed to build bootstrap DNS resolver: {err}"))?;
    let lookup_name = format!("{hostname}.");
    let lookup = resolver.lookup_ip(lookup_name).await.map_err(|err| {
        format!(
            "failed to resolve DNS-over-HTTPS upstream `{hostname}` using `dns.bootstrap_ips`: {err}"
        )
    })?;

    Ok(lookup.into_iter())
}

fn bootstrap_name_server_configs(bootstrap_ips: &[IpAddr]) -> Vec<NameServerConfig> {
    bootstrap_ips
        .iter()
        .copied()
        .map(|ip| NameServerConfig::new(ip, false, vec![ConnectionConfig::udp()]))
        .collect()
}

#[doc(hidden)]
#[derive(Clone, Debug)]
pub struct CompactForwardConfig {
    upstream_dns: Vec<UpstreamDnsConfig>,
    bootstrap_ips: Vec<IpAddr>,
    options: Option<ResolverOpts>,
}

impl CompactForwardConfig {
    async fn resolve(&self) -> Result<ForwardConfig, String> {
        let mut name_servers = Vec::new();
        for upstream in &self.upstream_dns {
            name_servers.extend(
                upstream
                    .resolve_name_server_configs(&self.bootstrap_ips)
                    .await?,
            );
        }

        Ok(ForwardConfig {
            name_servers,
            options: self.options.clone(),
        })
    }
}

/// Configuration for a zone
#[derive(Deserialize, Debug)]
pub struct ZoneConfig {
    /// name of the zone
    pub zone: String, // TODO: make Domain::Name decodable
    /// type of the zone
    #[serde(flatten)]
    pub zone_type_config: ZoneTypeConfig,
}

impl ZoneConfig {
    fn root_forward(dns: DnsConfig) -> Result<Self, String> {
        let DnsConfig {
            upstream_dns,
            bootstrap_ips,
            cache_size,
            cache_ttl_min,
            cache_ttl_max,
        } = dns;

        for upstream in &upstream_dns {
            upstream.validate()?;
        }

        let options = if cache_size.is_some() || cache_ttl_min.is_some() || cache_ttl_max.is_some()
        {
            let mut options = ResolverOpts::default();
            if let Some(cache_size) = cache_size {
                options.cache_size = cache_size;
            }
            if let Some(cache_ttl_min) = cache_ttl_min {
                let ttl = Duration::from_secs(cache_ttl_min);
                options.positive_min_ttl = Some(ttl);
                options.negative_min_ttl = Some(ttl);
            }
            if let Some(cache_ttl_max) = cache_ttl_max {
                let ttl = Duration::from_secs(cache_ttl_max);
                options.positive_max_ttl = Some(ttl);
                options.negative_max_ttl = Some(ttl);
            }
            Some(options)
        } else {
            None
        };

        Ok(Self {
            zone: ".".to_owned(),
            zone_type_config: ZoneTypeConfig::External {
                stores: vec![ExternalStoreConfig::CompactForward(CompactForwardConfig {
                    upstream_dns,
                    bootstrap_ips,
                    options,
                })],
            },
        })
    }

    #[warn(clippy::wildcard_enum_match_arm)] // make sure all cases are handled despite of non_exhaustive
    pub async fn load(
        &self,
        adblock_rules: Option<&CompiledRuleSets>,
    ) -> Result<Vec<Arc<dyn ZoneHandler>>, String> {
        debug!("loading zone with config: {self:#?}");

        let zone_name = self
            .zone()
            .map_err(|err| format!("failed to read zone name: {err}"))?;

        // load the zone and insert any configured authorities in the catalog.

        let mut authorities: Vec<Arc<dyn ZoneHandler>> = vec![];

        match &self.zone_type_config {
            ZoneTypeConfig::External { stores } => {
                debug!(
                    "loading authorities for {zone_name} with stores {:?}",
                    stores
                );

                for store in stores {
                    let config = match store {
                        ExternalStoreConfig::Forward(config) => config.clone(),
                        ExternalStoreConfig::CompactForward(config) => config.resolve().await?,
                        ExternalStoreConfig::Default => return empty_stores_error(),
                    };

                    if let Some(adblock_rules) = adblock_rules {
                        let chained =
                            adblock::build_authorities(zone_name.clone(), config, adblock_rules)?;
                        authorities.extend(chained);
                        continue;
                    }

                    let forwarder = ForwardZoneHandler::builder_tokio(config)
                        .with_origin(zone_name.clone())
                        .build()?;
                    authorities.push(Arc::new(forwarder));
                }
            }
        }

        info!("zone successfully loaded: {zone_name}");
        Ok(authorities)
    }

    // TODO this is a little ugly for the parse, b/c there is no terminal char
    /// returns the name of the Zone, i.e. the `example.com` of `www.example.com.`
    pub fn zone(&self) -> Result<Name, ProtoError> {
        Name::parse(&self.zone, Some(&Name::new()))
    }

    /// the type of the zone
    pub fn zone_type(&self) -> ZoneType {
        match &self.zone_type_config {
            ZoneTypeConfig::External { .. } => ZoneType::External,
        }
    }
}

fn empty_stores_error<T>() -> Result<T, String> {
    Result::Err("empty [[zones.stores]] in config".to_owned())
}

#[derive(Deserialize, Debug)]
#[serde(tag = "zone_type")]
#[serde(deny_unknown_fields)]
/// Enumeration over each zone type's configuration.
pub enum ZoneTypeConfig {
    External {
        /// Store configurations. This accepts either a single YAML map or a sequence of maps.
        #[serde(default = "store_config_default")]
        #[serde(deserialize_with = "store_config_visitor")]
        stores: Vec<ExternalStoreConfig>,
    },
}

/// Enumeration over store types for external nameservers.
#[allow(clippy::large_enum_variant)]
#[derive(Deserialize, Debug, Default)]
#[serde(rename_all = "lowercase", tag = "type")]
#[non_exhaustive]
pub enum ExternalStoreConfig {
    /// Forwarding Resolver
    Forward(#[serde(deserialize_with = "deserialize_forward_config")] ForwardConfig),
    #[serde(skip)]
    CompactForward(CompactForwardConfig),
    /// This is used by the configuration processing code to represent a deprecated or main-block config without an associated store.
    #[default]
    Default,
}

/// Create a default value for serde for store config enums.
fn store_config_default<S: Default>() -> Vec<S> {
    vec![Default::default()]
}

/// Custom serde visitor that can deserialize a map (single configuration store, expressed as a YAML
/// table) or sequence (chained configuration stores, expressed as a YAML array of tables.)
/// This is used instead of an untagged enum because serde cannot provide variant-specific error
/// messages when using an untagged enum.
fn store_config_visitor<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct MapOrSequence<T>(std::marker::PhantomData<T>);

    impl<'de, T: Deserialize<'de>> Visitor<'de> for MapOrSequence<T> {
        type Value = Vec<T>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("map or sequence")
        }

        fn visit_seq<S>(self, seq: S) -> Result<Vec<T>, S::Error>
        where
            S: SeqAccess<'de>,
        {
            Deserialize::deserialize(de::value::SeqAccessDeserializer::new(seq))
        }

        fn visit_map<M>(self, map: M) -> Result<Vec<T>, M::Error>
        where
            M: MapAccess<'de>,
        {
            match Deserialize::deserialize(de::value::MapAccessDeserializer::new(map)) {
                Ok(seq) => Ok(vec![seq]),
                Err(e) => Err(e),
            }
        }
    }

    deserializer.deserialize_any(MapOrSequence::<T>(Default::default()))
}

#[cfg(test)]
mod config_tests {
    use super::*;

    async fn resolved_forward_config(config: &Config) -> ForwardConfig {
        match &config.zones[0].zone_type_config {
            ZoneTypeConfig::External { stores } => match &stores[0] {
                ExternalStoreConfig::CompactForward(config) => config
                    .resolve()
                    .await
                    .expect("forward config should resolve"),
                ExternalStoreConfig::Forward(config) => config.clone(),
                ExternalStoreConfig::Default => panic!("expected a forward store"),
            },
        }
    }

    #[tokio::test]
    async fn supports_adguard_style_upstream_dns() {
        let config = Config::from_yaml(
            r#"
listen_addrs_ipv4: ["127.0.0.1"]
dns:
  upstream_dns:
    - 127.0.0.1:7874
"#,
        )
        .expect("config should parse");

        assert_eq!(config.zones.len(), 1);
        assert_eq!(config.zones[0].zone, ".");

        let forward = resolved_forward_config(&config).await;
        assert_eq!(forward.name_servers.len(), 1);
        let upstream = &forward.name_servers[0];
        assert_eq!(upstream.ip, "127.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(upstream.connections[0].port, 7874);
        assert!(matches!(
            upstream.connections[0].protocol,
            ProtocolConfig::Udp
        ));
        assert!(!upstream.trust_negative_responses);
    }

    #[tokio::test]
    async fn upstream_dns_defaults_port_53() {
        let config = Config::from_yaml(
            r#"
dns:
  upstream_dns:
    - 8.8.8.8
"#,
        )
        .expect("config should parse");

        let forward = resolved_forward_config(&config).await;
        assert_eq!(
            forward.name_servers[0].ip,
            "8.8.8.8".parse::<IpAddr>().unwrap()
        );
        assert_eq!(forward.name_servers[0].connections[0].port, 53);
    }

    #[tokio::test]
    async fn supports_adguard_style_cache_options() {
        let config = Config::from_yaml(
            r#"
dns:
  upstream_dns:
    - 8.8.8.8
  cache_size: 1024
  cache_ttl_min: 30
  cache_ttl_max: 600
"#,
        )
        .expect("config should parse");

        let forward = resolved_forward_config(&config).await;
        let options = forward
            .options
            .as_ref()
            .expect("resolver options should exist");
        assert_eq!(options.cache_size, 1024);
        assert_eq!(options.positive_min_ttl, Some(Duration::from_secs(30)));
        assert_eq!(options.negative_min_ttl, Some(Duration::from_secs(30)));
        assert_eq!(options.positive_max_ttl, Some(Duration::from_secs(600)));
        assert_eq!(options.negative_max_ttl, Some(Duration::from_secs(600)));
    }

    #[tokio::test]
    async fn supports_doh_with_bootstrap_ips() {
        let config = Config::from_yaml(
            r#"
dns:
  upstream_dns:
    - https://doh.cleanbrowsing.org/doh/security-filter/
    - https://freedns.controld.com/p0
  bootstrap_ips:
    - 223.5.5.5
    - 119.29.29.29
"#,
        )
        .expect("config should parse");

        let compact = match &config.zones[0].zone_type_config {
            ZoneTypeConfig::External { stores } => match &stores[0] {
                ExternalStoreConfig::CompactForward(config) => config,
                _ => panic!("expected a compact forward store"),
            },
        };
        assert_eq!(compact.upstream_dns.len(), 2);
        assert_eq!(
            compact.bootstrap_ips,
            [
                "223.5.5.5".parse::<IpAddr>().unwrap(),
                "119.29.29.29".parse::<IpAddr>().unwrap()
            ]
        );

        let bootstrap = bootstrap_name_server_configs(&compact.bootstrap_ips);
        assert_eq!(bootstrap.len(), 2);
        assert_eq!(bootstrap[0].ip, "223.5.5.5".parse::<IpAddr>().unwrap());
        assert_eq!(bootstrap[1].ip, "119.29.29.29".parse::<IpAddr>().unwrap());
        assert!(
            bootstrap
                .iter()
                .all(|server| server.connections[0].port == 53
                    && matches!(server.connections[0].protocol, ProtocolConfig::Udp))
        );
    }

    #[tokio::test]
    async fn supports_compact_doh_url_with_ip_host() {
        let config = Config::from_yaml(
            r#"
dns:
  upstream_dns:
    - https://1.1.1.1
  bootstrap_ips:
    - 9.9.9.9
"#,
        )
        .expect("config should parse");

        let forward = resolved_forward_config(&config).await;
        let upstream = &forward.name_servers[0];
        assert_eq!(upstream.ip, "1.1.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(upstream.connections[0].port, 443);
        assert!(matches!(&upstream.connections[0].protocol,
            ProtocolConfig::Https { server_name, path }
            if server_name.as_ref() == "1.1.1.1" && path.as_ref() == "/dns-query"));
    }

    #[tokio::test]
    async fn resolves_compact_doh_hostname_at_runtime() {
        let config = Config::from_yaml(
            r#"
dns:
  upstream_dns:
    - https://localhost/dns-query
"#,
        )
        .expect("config should parse without a bootstrap lookup");

        let forward = resolved_forward_config(&config).await;
        assert!(!forward.name_servers.is_empty());
        for upstream in forward.name_servers.iter() {
            assert!(matches!(&upstream.connections[0].protocol,
                ProtocolConfig::Https { server_name, .. } if server_name.as_ref() == "localhost"));
        }
    }

    #[test]
    fn rejects_invalid_doh_urls() {
        for upstream in [
            "http://doh.example/dns-query",
            "https://user@doh.example/dns-query",
            "https://doh.example/dns-query?format=json",
        ] {
            let yaml = format!("dns:\n  upstream_dns:\n    - {upstream}\n");
            assert!(
                Config::from_yaml(&yaml).is_err(),
                "upstream should be rejected: {upstream}"
            );
        }
    }

    #[test]
    fn filter_cache_dir_defaults_to_tmp() {
        let config = Config::from_yaml("").expect("config should parse");

        assert_eq!(
            config.filter_cache_dir(),
            PathBuf::from("/tmp/astra-dns/filters-cache")
        );
    }

    #[test]
    fn supports_custom_filter_cache_dir() {
        let config = Config::from_yaml(
            r#"
filter_cache_dir: /mnt/storage/astra-dns/filters-cache
filters:
  - enabled: true
    url: https://example.test/filter.txt
    id: 7
"#,
        )
        .expect("config should parse");

        let runtime = config
            .adblock_runtime_config()
            .expect("adblock should be enabled");

        assert_eq!(
            runtime.filter_cache_dir,
            PathBuf::from("/mnt/storage/astra-dns/filters-cache")
        );
    }

    #[test]
    fn filter_refresh_defaults_to_daily_and_can_be_disabled() {
        let default_config = Config::from_yaml("").expect("config should parse");
        assert_eq!(default_config.filter_refresh_interval_secs(), 86_400);

        let disabled_config =
            Config::from_yaml("filter_refresh_interval_secs: 0").expect("config should parse");
        assert_eq!(disabled_config.filter_refresh_interval_secs(), 0);
    }

    #[test]
    fn lan_hosts_default_to_enabled_minute_refresh() {
        let config = Config::from_yaml("").expect("config should parse");

        assert!(config.lan_hosts().enabled);
        assert_eq!(config.lan_hosts().source, PathBuf::from("/var/dhcp.leases"));
        assert_eq!(config.lan_hosts().domain.as_deref(), Some("lan"));
        assert!(config.lan_hosts().include_unqualified);
        assert_eq!(config.lan_hosts().refresh_interval_secs, 60);
    }

    #[test]
    fn rejects_mixing_zones_and_upstream_dns() {
        let err = Config::from_yaml(
            r#"
dns:
  upstream_dns:
    - 127.0.0.1:7874
zones:
  - zone: "."
    zone_type: "External"
    stores:
      - type: "forward"
        name_servers:
          - socket_addr: "8.8.8.8:53"
"#,
        )
        .expect_err("config should fail");

        assert!(
            err.to_string()
                .contains("cannot configure both `zones` and `dns.upstream_dns`")
        );
    }
    #[tokio::test]
    async fn preserves_legacy_detailed_upstreams() {
        let config = Config::from_yaml(
            r#"
dns:
  upstream_dns:
    - socket_addr: "192.0.2.1:8443"
      protocol: https
      tls_dns_name: dns.example
      http_endpoint: /custom-query
      bind_addr: "127.0.0.1:0"
      trust_negative_responses: true
    - socket_addr: "[::1]:5353"
      protocol: tcp
"#,
        )
        .unwrap();
        let forward = resolved_forward_config(&config).await;
        let server = &forward.name_servers[0];
        assert!(server.trust_negative_responses);
        assert_eq!(server.ip, "192.0.2.1".parse::<IpAddr>().unwrap());
        assert_eq!(server.connections[0].port, 8443);
        assert_eq!(
            server.connections[0].bind_addr,
            Some("127.0.0.1:0".parse().unwrap())
        );
        assert!(matches!(&server.connections[0].protocol,
            ProtocolConfig::Https { server_name, path }
            if server_name.as_ref() == "dns.example" && path.as_ref() == "/custom-query"));
        let server = &forward.name_servers[1];
        assert!(!server.trust_negative_responses);
        assert_eq!(server.connections[0].port, 5353);
        assert!(matches!(
            server.connections[0].protocol,
            ProtocolConfig::Tcp
        ));
    }

    #[tokio::test]
    async fn preserves_legacy_zone_forward_store() {
        let config = Config::from_yaml(
            r#"
zones:
  - zone: "."
    zone_type: External
    stores:
      type: forward
      name_servers:
        - socket_addr: "127.0.0.1:5353"
"#,
        )
        .unwrap();
        let forward = resolved_forward_config(&config).await;
        assert_eq!(forward.name_servers[0].connections[0].port, 5353);
        assert!(!forward.name_servers[0].trust_negative_responses);
        assert!(matches!(
            forward.name_servers[0].connections[0].protocol,
            ProtocolConfig::Udp
        ));
    }

    #[tokio::test]
    async fn preserves_doh_ipv6_port_and_path() {
        let config = Config::from_yaml(
            r#"
dns:
  upstream_dns:
    - https://[::1]:8443/custom-query
"#,
        )
        .unwrap();
        let forward = resolved_forward_config(&config).await;
        let server = &forward.name_servers[0];
        assert_eq!(server.ip, "::1".parse::<IpAddr>().unwrap());
        assert_eq!(server.connections[0].port, 8443);
        assert!(matches!(&server.connections[0].protocol,
            ProtocolConfig::Https { server_name, path }
            if server_name.as_ref() == "::1" && path.as_ref() == "/custom-query"));
    }
}
