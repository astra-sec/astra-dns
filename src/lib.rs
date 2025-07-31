// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Configuration module for the server binary, `named`.

#[cfg(feature = "prometheus-metrics")]
use std::net::SocketAddr;
use std::{
    fmt,
    fs::File,
    io::Read,
    net::{AddrParseError, Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use ipnet::IpNet;
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{self, Deserialize, Deserializer};

use hickory_proto::{ProtoError, rr::Name};
#[cfg(feature = "blocklist")]
use hickory_server::store::blocklist::BlocklistAuthority;
#[cfg(feature = "blocklist")]
use hickory_server::store::blocklist::BlocklistConfig;
use hickory_server::store::file::FileConfig;
#[cfg(feature = "resolver")]
use hickory_server::store::forwarder::ForwardAuthority;
#[cfg(feature = "resolver")]
use hickory_server::store::forwarder::ForwardConfig;
#[cfg(feature = "recursor")]
use hickory_server::store::recursor::RecursiveAuthority;
#[cfg(feature = "recursor")]
use hickory_server::store::recursor::RecursiveConfig;
#[cfg(feature = "sqlite")]
use hickory_server::store::sqlite::{SqliteAuthority, SqliteConfig};
use hickory_server::{
    authority::{AuthorityObject, ZoneType},
    store::file::FileAuthority,
};
use tracing::{debug, info, warn};

#[cfg(feature = "prometheus-metrics")]
mod prometheus_server;

#[cfg(feature = "prometheus-metrics")]
pub use prometheus_server::PrometheusServer;

static DEFAULT_PATH: &str = "/var/named"; // TODO what about windows (do I care? ;)
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
    /// Base configuration directory, i.e. root path for zones
    directory: Option<String>,
    /// User to run the server as.
    ///
    /// Only supported on Unix-like platforms. If the real or effective UID of the hickory process
    /// is root, we will attempt to change to this user (or to nobody if no user is specified here.)
    pub user: Option<String>,
    /// Group to run the server as.
    ///
    /// Only supported on Unix-like platforms. If the real or effective UID of the hickory process
    /// is root, we will attempt to change to this group (or to nobody if no group is specified here.)
    pub group: Option<String>,
    /// List of configurations for zones
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_with_file")]
    zones: Vec<ZoneConfig>,
    /// Networks denied to access the server
    #[serde(default)]
    deny_networks: Vec<IpNet>,
    /// Networks allowed to access the server
    #[serde(default)]
    allow_networks: Vec<IpNet>,
}

impl Config {
    /// read a Config file from the file specified at path.
    pub fn read_config(path: &Path) -> Result<Self, serde_yaml::Error> {
        let mut file = File::open(path).unwrap();
        let mut yaml = String::new();
        file.read_to_string(&mut yaml).unwrap();
        Self::from_yaml(&yaml)
    }

    /// Read a [`Config`] from the given YAML string.
    pub fn from_yaml(yaml: &str) -> Result<Self, serde_yaml::Error> {
        Ok(serde_yaml::from_str(yaml)?)
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

    /// the path for all zone configurations, defaults to `/var/named`
    pub fn directory(&self) -> &Path {
        self.directory
            .as_ref()
            .map_or(Path::new(DEFAULT_PATH), Path::new)
    }

    /// the set of zones which should be loaded
    pub fn zones(&self) -> &[ZoneConfig] {
        &self.zones
    }

    /// get the networks denied access to this server
    pub fn deny_networks(&self) -> &[IpNet] {
        &self.deny_networks
    }

    /// get the networks allowed to connect to this server
    pub fn allow_networks(&self) -> &[IpNet] {
        &self.allow_networks
    }
}

#[derive(Deserialize, Debug)]
struct ZoneConfigWithFile {
    file: Option<PathBuf>,
    #[serde(flatten)]
    config: ZoneConfig,
}

fn deserialize_with_file<'de, D>(deserializer: D) -> Result<Vec<ZoneConfig>, D::Error>
where
    D: Deserializer<'de>,
    D::Error: serde::de::Error,
{
    Vec::<ZoneConfigWithFile>::deserialize(deserializer)?
        .into_iter()
        .map(|ZoneConfigWithFile { file, mut config }| match file {
            Some(file) => match &mut config.zone_type_config {
                ZoneTypeConfig::Primary(server_config)
                | ZoneTypeConfig::Secondary(server_config) => {
                    if server_config
                        .stores
                        .iter()
                        .any(|store| matches!(store, ServerStoreConfig::File(_)))
                    {
                        Err(<D::Error as serde::de::Error>::custom(
                            "having `file` and `[zones.store]` item with type `file` is ambiguous",
                        ))
                    } else {
                        let store = ServerStoreConfig::File(FileConfig {
                            zone_file_path: file,
                        });

                        if server_config.stores.len() == 1
                            && matches!(&server_config.stores[0], ServerStoreConfig::Default)
                        {
                            server_config.stores[0] = store;
                        } else {
                            server_config.stores.push(store);
                        }
                        Ok(config)
                    }
                }
                _ => Err(<D::Error as serde::de::Error>::custom(
                    "cannot use `file` on a zone that is not primary or secondary",
                )),
            },

            _ => Ok(config),
        })
        .collect::<Result<Vec<_>, _>>()
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
    #[warn(clippy::wildcard_enum_match_arm)] // make sure all cases are handled despite of non_exhaustive
    pub async fn load(&self, zone_dir: &Path) -> Result<Vec<Arc<dyn AuthorityObject>>, String> {
        debug!("loading zone with config: {self:#?}");

        let zone_name = self
            .zone()
            .map_err(|err| format!("failed to read zone name: {err}"))?;
        let zone_type = self.zone_type();

        // load the zone and insert any configured authorities in the catalog.

        let mut authorities: Vec<Arc<dyn AuthorityObject>> = vec![];

        #[cfg(feature = "blocklist")]
        let handle_blocklist_store = |config| {
            let zone_name = zone_name.clone();

            async move {
                Result::<Arc<dyn AuthorityObject>, String>::Ok(Arc::new(
                    BlocklistAuthority::try_from_config(
                        zone_name.clone(),
                        zone_type,
                        config,
                        Some(zone_dir),
                    )
                    .await?,
                ))
            }
        };

        match &self.zone_type_config {
            ZoneTypeConfig::Primary(server_config) | ZoneTypeConfig::Secondary(server_config) => {
                debug!(
                    "loading authorities for {zone_name} with stores {:?}",
                    server_config.stores
                );

                let is_axfr_allowed = server_config.is_axfr_allowed();
                for store in &server_config.stores {
                    let authority: Arc<dyn AuthorityObject> = match store {
                        #[cfg(feature = "sqlite")]
                        ServerStoreConfig::Sqlite(config) => {
                            let authority = SqliteAuthority::try_from_config(
                                zone_name.clone(),
                                zone_type,
                                is_axfr_allowed,
                                server_config.is_dnssec_enabled(),
                                Some(zone_dir),
                                config,
                            )
                            .await?;

                            Arc::new(authority)
                        }

                        ServerStoreConfig::File(config) => {
                            let authority = FileAuthority::try_from_config(
                                zone_name.clone(),
                                zone_type,
                                is_axfr_allowed,
                                Some(zone_dir),
                                config,
                            )?;

                            Arc::new(authority)
                        }
                        _ => return Err("Unsupported store configuration".to_string()),
                    };

                    authorities.push(authority);
                }
            }
            ZoneTypeConfig::External { stores } => {
                debug!(
                    "loading authorities for {zone_name} with stores {:?}",
                    stores
                );

                #[cfg_attr(
                    not(any(feature = "blocklist", feature = "resolver")),
                    allow(unreachable_code, unused_variables, clippy::never_loop)
                )]
                for store in stores {
                    let authority: Arc<dyn AuthorityObject> = match store {
                        #[cfg(feature = "blocklist")]
                        ExternalStoreConfig::Blocklist(config) => {
                            handle_blocklist_store(config).await?
                        }
                        #[cfg(feature = "resolver")]
                        ExternalStoreConfig::Forward(config) => {
                            let forwarder = ForwardAuthority::builder_tokio(config.clone())
                                .with_origin(zone_name.clone())
                                .build()?;

                            Arc::new(forwarder)
                        }
                        #[cfg(feature = "recursor")]
                        ExternalStoreConfig::Recursor(config) => {
                            let recursor = RecursiveAuthority::try_from_config(
                                zone_name.clone(),
                                zone_type,
                                config,
                                Some(zone_dir),
                            )
                            .await?;

                            Arc::new(recursor)
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
            ZoneTypeConfig::Primary { .. } => ZoneType::Primary,
            ZoneTypeConfig::Secondary { .. } => ZoneType::Secondary,
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
    Primary(ServerZoneConfig),
    Secondary(ServerZoneConfig),
    External {
        /// Store configurations.  Note: we specify a default handler to get a Vec containing a
        /// StoreConfig::Default, which is used for authoritative file-based zones and legacy sqlite
        /// configurations. #[serde(default)] cannot be used, because it will invoke Default for Vec,
        /// i.e., an empty Vec and we cannot implement Default for StoreConfig and return a Vec.  The
        /// custom visitor is used to handle map (single store) or sequence (chained store) configurations.
        #[serde(default = "store_config_default")]
        #[serde(deserialize_with = "store_config_visitor")]
        stores: Vec<ExternalStoreConfig>,
    },
}

impl ZoneTypeConfig {
    pub fn as_server(&self) -> Option<&ServerZoneConfig> {
        match self {
            Self::Primary(c) | Self::Secondary(c) => Some(c),
            _ => None,
        }
    }
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct ServerZoneConfig {
    /// Allow AXFR (TODO: need auth)
    pub allow_axfr: Option<bool>,
    /// Store configurations.  Note: we specify a default handler to get a Vec containing a
    /// StoreConfig::Default, which is used for authoritative file-based zones and legacy sqlite
    /// configurations. #[serde(default)] cannot be used, because it will invoke Default for Vec,
    /// i.e., an empty Vec and we cannot implement Default for StoreConfig and return a Vec.  The
    /// custom visitor is used to handle map (single store) or sequence (chained store) configurations.
    #[serde(default = "store_config_default")]
    #[serde(deserialize_with = "store_config_visitor")]
    pub stores: Vec<ServerStoreConfig>,
}

impl ServerZoneConfig {
    /// path to the zone file, i.e. the base set of original records in the zone
    ///
    /// this is only used on first load, if dynamic update is enabled for the zone, then the journal
    /// file is the actual source of truth for the zone.
    pub fn file(&self) -> Option<&Path> {
        self.stores.iter().find_map(|store| match store {
            ServerStoreConfig::File(file_config) => Some(&*file_config.zone_file_path),
            #[cfg(feature = "sqlite")]
            ServerStoreConfig::Sqlite(sqlite_config) => Some(&*sqlite_config.zone_file_path),
            ServerStoreConfig::Default => None,
        })
    }

    /// enable AXFR transfers
    pub fn is_axfr_allowed(&self) -> bool {
        self.allow_axfr.unwrap_or(false)
    }

    /// declare that this zone should be signed, see keys for configuration of the keys for signing
    pub fn is_dnssec_enabled(&self) -> bool {
        false
    }
}

/// Enumeration over store types for secondary nameservers.
#[derive(Deserialize, Debug, Default)]
#[serde(tag = "type")]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum ServerStoreConfig {
    /// File based configuration
    File(FileConfig),
    /// Sqlite based configuration file
    #[cfg(feature = "sqlite")]
    Sqlite(SqliteConfig),
    /// This is used by the configuration processing code to represent a deprecated or main-block config without an associated store.
    #[default]
    Default,
}

/// Enumeration over store types for external nameservers.
#[allow(clippy::large_enum_variant)]
#[derive(Deserialize, Debug, Default)]
#[serde(rename_all = "lowercase", tag = "type")]
#[non_exhaustive]
pub enum ExternalStoreConfig {
    /// Blocklist configuration
    #[cfg(feature = "blocklist")]
    Blocklist(BlocklistConfig),
    /// Forwarding Resolver
    #[cfg(feature = "resolver")]
    Forward(ForwardConfig),
    /// Recursive Resolver
    #[cfg(feature = "recursor")]
    Recursor(Box<RecursiveConfig>),
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
