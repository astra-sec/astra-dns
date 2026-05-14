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
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{self, Deserialize, Deserializer};

use hickory_proto::{ProtoError, rr::Name, xfer::Protocol};
use hickory_resolver::config::{NameServerConfig, NameServerConfigGroup};
use hickory_server::authority::{AuthorityObject, ZoneType};
use hickory_server::store::forwarder::ForwardAuthority;
use hickory_server::store::forwarder::ForwardConfig;
use tracing::{debug, info, warn};

mod adblock;
#[cfg(feature = "prometheus-metrics")]
mod prometheus_server;

pub use adblock::{
    AdblockRuntimeConfig, BlockingMode, CompiledRuleSets, FilterConfig, FilteringConfig,
};
#[cfg(feature = "prometheus-metrics")]
pub use prometheus_server::PrometheusServer;

static DEFAULT_PORT: u16 = 53;
static DEFAULT_TCP_REQUEST_TIMEOUT: u64 = 5;

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
    /// Level at which to log, default is INFO
    log_level: Option<String>,
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

    pub fn adblock_runtime_config(&self) -> Option<AdblockRuntimeConfig> {
        if !adblock::is_adblock_enabled(&self.filters, &self.user_rules, &self.filtering) {
            return None;
        }

        Some(AdblockRuntimeConfig {
            filters: self.filters.clone(),
            user_rules: self.user_rules.clone(),
            filtering: self.filtering.clone(),
        })
    }

    fn normalize(mut self) -> Result<Self, String> {
        if let Some(dns) = &self.dns {
            if !dns.upstream_dns.is_empty() {
                if !self.zones.is_empty() {
                    return Err(
                        "cannot configure both `zones` and `dns.upstream_dns`; use one style"
                            .to_owned(),
                    );
                }

                #[cfg(feature = "resolver")]
                {
                    self.zones = vec![ZoneConfig::root_forward(dns.upstream_dns.clone())?];
                }
            }
        }

        Ok(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct DnsConfig {
    upstream_dns: Vec<UpstreamDnsConfig>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
enum UpstreamDnsConfig {
    Address(String),
    #[cfg(feature = "resolver")]
    Detailed(NameServerConfig),
}

impl UpstreamDnsConfig {
    fn into_name_server_config(self) -> Result<NameServerConfig, String> {
        match self {
            Self::Address(address) => parse_upstream_dns_address(&address),
            Self::Detailed(config) => Ok(config),
        }
    }
}

fn parse_upstream_dns_address(address: &str) -> Result<NameServerConfig, String> {
    let (protocol, address) = if let Some(addr) = address.strip_prefix("udp://") {
        (Protocol::Udp, addr)
    } else if let Some(addr) = address.strip_prefix("tcp://") {
        (Protocol::Tcp, addr)
    } else {
        (Protocol::Udp, address)
    };

    let socket_addr = address
        .parse::<SocketAddr>()
        .or_else(|_| address.parse::<IpAddr>().map(|ip| SocketAddr::new(ip, 53)))
        .map_err(|_| {
            format!(
                "invalid upstream DNS address `{address}`; expected `IP`, `IP:PORT`, `udp://IP:PORT`, or `tcp://IP:PORT`"
            )
        })?;

    Ok(NameServerConfig {
        socket_addr,
        protocol,
        tls_dns_name: None,
        http_endpoint: None,
        trust_negative_responses: false,
        bind_addr: None,
    })
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
    fn root_forward(upstreams: Vec<UpstreamDnsConfig>) -> Result<Self, String> {
        let name_servers: Vec<NameServerConfig> = upstreams
            .into_iter()
            .map(UpstreamDnsConfig::into_name_server_config)
            .collect::<Result<_, _>>()?;

        Ok(Self {
            zone: ".".to_owned(),
            zone_type_config: ZoneTypeConfig::External {
                stores: vec![ExternalStoreConfig::Forward(ForwardConfig {
                    name_servers: NameServerConfigGroup::from(name_servers),
                    options: None,
                })],
            },
        })
    }

    #[warn(clippy::wildcard_enum_match_arm)] // make sure all cases are handled despite of non_exhaustive
    pub async fn load(
        &self,
        adblock_rules: Option<&CompiledRuleSets>,
    ) -> Result<Vec<Arc<dyn AuthorityObject>>, String> {
        debug!("loading zone with config: {self:#?}");

        let zone_name = self
            .zone()
            .map_err(|err| format!("failed to read zone name: {err}"))?;

        // load the zone and insert any configured authorities in the catalog.

        let mut authorities: Vec<Arc<dyn AuthorityObject>> = vec![];

        match &self.zone_type_config {
            ZoneTypeConfig::External { stores } => {
                debug!(
                    "loading authorities for {zone_name} with stores {:?}",
                    stores
                );

                for store in stores {
                    let authority: Arc<dyn AuthorityObject> = match store {
                        ExternalStoreConfig::Forward(config) => {
                            if let Some(adblock_rules) = adblock_rules {
                                let chained = adblock::build_authorities(
                                    zone_name.clone(),
                                    config.clone(),
                                    adblock_rules,
                                )?;
                                authorities.extend(chained);
                                continue;
                            }

                            let forwarder = ForwardAuthority::builder_tokio(config.clone())
                                .with_origin(zone_name.clone())
                                .build()?;

                            Arc::new(forwarder)
                        }
                        _ => return empty_stores_error(),
                    };

                    authorities.push(authority);
                }
            }
        }

        info!("zone successfully loaded: {}", self.zone()?);
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
    Forward(ForwardConfig),
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

    #[test]
    fn supports_adguard_style_upstream_dns() {
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

        match &config.zones[0].zone_type_config {
            ZoneTypeConfig::External { stores } => {
                assert_eq!(stores.len(), 1);
                match &stores[0] {
                    #[cfg(feature = "resolver")]
                    ExternalStoreConfig::Forward(config) => {
                        assert_eq!(config.name_servers.len(), 1);
                        let upstream = &config.name_servers[0];
                        assert_eq!(upstream.socket_addr, "127.0.0.1:7874".parse().unwrap());
                        assert_eq!(upstream.protocol, Protocol::Udp);
                        assert!(!upstream.trust_negative_responses);
                    }
                    _ => panic!("expected a forward store"),
                }
            }
        }
    }

    #[test]
    fn upstream_dns_defaults_port_53() {
        let config = Config::from_yaml(
            r#"
dns:
  upstream_dns:
    - 8.8.8.8
"#,
        )
        .expect("config should parse");

        match &config.zones[0].zone_type_config {
            ZoneTypeConfig::External { stores } => match &stores[0] {
                #[cfg(feature = "resolver")]
                ExternalStoreConfig::Forward(config) => {
                    assert_eq!(
                        config.name_servers[0].socket_addr,
                        "8.8.8.8:53".parse().unwrap()
                    );
                }
                _ => panic!("expected a forward store"),
            },
        }
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
}
