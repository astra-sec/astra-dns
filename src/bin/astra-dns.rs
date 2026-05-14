// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! The `astra-dns` binary for running a DNS server
//!
//! ```text
//! Usage: astra-dns [options]
//!       astra-dns (-h | --help | --version)
//!
//! Options:
//!    -h, --help              Show this message
//!    -v, --version           Show the version of hickory-dns
//!    -c FILE, --config=FILE  Path to configuration file, default is /etc/named.yaml
//! ```

#![recursion_limit = "128"]

#[cfg(feature = "metrics")]
use std::time::Duration;
use std::{
    fmt,
    io::Error,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::PathBuf,
    sync::{Arc, RwLock},
};

use async_trait::async_trait;
use clap::Parser;
#[cfg(feature = "metrics")]
use metrics::{Counter, Unit, counter, describe_counter, describe_gauge, gauge};
#[cfg(feature = "metrics")]
use metrics_process::Collector;
use socket2::{Domain, Socket, Type};
use time::OffsetDateTime;
#[cfg(unix)]
use tokio::signal::unix::{SignalKind, signal};
#[cfg(feature = "metrics")]
use tokio::time::sleep;
use tokio::{
    net::{TcpListener, UdpSocket},
    runtime,
};
use tracing::{Event, Level, Subscriber, error, info};
use tracing_subscriber::{
    EnvFilter,
    fmt::{FmtContext, FormatEvent, FormatFields, FormattedFields, format},
    layer::SubscriberExt,
    registry::LookupSpan,
    util::SubscriberInitExt,
};

#[cfg(feature = "prometheus-metrics")]
use astra_dns::PrometheusServer;
use astra_dns::{CompiledRuleSets, Config};
#[cfg(feature = "metrics")]
use astra_dns::{ExternalStoreConfig, ZoneConfig, ZoneTypeConfig};
use hickory_server::{
    authority::Catalog,
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo, ServerFuture},
};

/// Cli struct for all options managed with clap derive api.
#[derive(Debug, Parser)]
#[clap(name = "astra-dns", version, about)]
struct Cli {
    /// Test validation of configuration files
    #[clap(long = "validate")]
    validate: bool,

    /// Number of runtime workers, defaults to the number of CPU cores
    #[clap(long = "workers")]
    workers: Option<usize>,

    /// Path to configuration file of named server
    #[clap(
        short = 'c',
        long = "config",
        default_value = "/etc/named.yaml",
        value_name = "NAME",
        value_hint=clap::ValueHint::FilePath,
    )]
    config: PathBuf,

    /// Listening socket for Prometheus metrics,
    /// for remote access configure socket as needed (e.g. 0.0.0.0:9000)
    /// overrides any value in config file
    #[cfg(feature = "prometheus-metrics")]
    #[clap(
        long = "prometheus-listen-address",
        value_name = "PROMETHEUS-LISTEN-ADDRESS"
    )]
    prometheus_listen_addr: Option<SocketAddr>,

    /// Disable Prometheus metrics,
    /// overrides any value in config file
    #[cfg(feature = "prometheus-metrics")]
    #[clap(long = "disable-prometheus", conflicts_with = "prometheus_listen_addr")]
    disable_prometheus: bool,
}

/// Main method for running the named server.
fn main() -> Result<(), String> {
    // this is essential for custom formatting the returned error message.
    // the displayed message of termination impl trait is not pretty.
    // https://doc.rust-lang.org/stable/src/std/process.rs.html#2439
    if let Err(e) = run() {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
    Ok(())
}

fn run() -> Result<(), String> {
    let args = Cli::parse();

    // Setup tracing for logging based on input
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().event_format(TdnsFormatter))
        .with(
            EnvFilter::builder()
                .with_default_directive(Level::INFO.into())
                .from_env()
                .map_err(|err| {
                    format!("failed to parse environment variable for tracing: {err}")
                })?,
        )
        .init();

    info!("Hickory DNS {} starting...", hickory_client::version());

    let mut runtime = runtime::Builder::new_multi_thread();
    runtime.enable_all().thread_name("hickory-server-runtime");
    if let Some(workers) = args.workers {
        runtime.worker_threads(workers);
    }
    let runtime = runtime
        .build()
        .map_err(|err| format!("failed to initialize Tokio runtime: {err}"))?;

    runtime.block_on(async_run(args))
}

async fn async_run(args: Cli) -> Result<(), String> {
    // Load configuration files

    let config = args.config.clone();
    let config_path = std::path::Path::new(&config);

    info!("loading configuration from: {config_path:?}");

    let loaded = load_runtime_config(config_path).await?;
    let config = loaded.config;
    let mut reload_settings = ReloadSettings::from_effective_config(&args, &config, config_path)?;
    #[cfg(feature = "prometheus-metrics")]
    let prometheus_server = if !args.disable_prometheus && !config.disable_prometheus() {
        let socket_addr = args
            .prometheus_listen_addr
            .unwrap_or(config.prometheus_listen_addr());
        let listener = build_tcp_listener(socket_addr.ip(), socket_addr.port()).map_err(|err| {
            format!("failed to bind to Prometheus TCP socket address {socket_addr:?}: {err}")
        })?;
        let local_addr = listener
            .local_addr()
            .map_err(|err| format!("failed to look up local address: {err}"))?;

        // Set up Prometheus HTTP server.
        let server = PrometheusServer::new(listener)?;
        info!("listening for Prometheus metrics on {local_addr:?}");
        Some(server)
    } else {
        info!("Prometheus metrics are disabled");
        None
    };

    #[cfg(feature = "metrics")]
    let (process_metrics_collector, config_metrics) = {
        // setup process metrics (cpu, memory, ...) collection
        let collector = Collector::default();
        collector.describe(); // add metric descriptions

        let process_metrics_collector = tokio::spawn(async move {
            loop {
                sleep(Duration::from_secs(1)).await;
                collector.collect();
            }
        });

        // metrics need to be created after the recorder is registered
        // calling increment() after registration is not sufficient
        let config_metrics = ConfigMetrics::new(&config);
        (process_metrics_collector, config_metrics)
    };

    #[cfg(unix)]
    let mut terminate_signal = signal(SignalKind::terminate())
        .map_err(|e| format!("failed to register signal handler: {e}"))?;
    #[cfg(unix)]
    let mut reload_signal = signal(SignalKind::hangup())
        .map_err(|e| format!("failed to register signal handler: {e}"))?;

    let runtime_handles = RuntimeHandles {
        #[cfg(feature = "prometheus-metrics")]
        prometheus_server,
        #[cfg(feature = "metrics")]
        process_metrics_collector,
    };

    if args.validate {
        info!("configuration files are validated");
        return Ok(());
    }

    let listen_addrs = reload_settings.listen_addrs.clone();
    let listen_port = reload_settings.listen_port;
    let tcp_request_timeout = config.tcp_request_timeout();

    // now, run the server, based on the config
    let handler = ReloadableCatalog::new(loaded.catalog.clone());
    let mut server = ServerFuture::new(handler.clone());

    if !config.disable_udp() {
        // load all udp listeners
        for addr in &listen_addrs {
            info!("binding UDP to {addr:?}");

            let udp_socket = build_udp_socket(*addr, listen_port)
                .map_err(|err| format!("failed to bind to UDP socket address {addr:?}: {err}"))?;

            info!(
                "listening for UDP on {:?}",
                udp_socket
                    .local_addr()
                    .map_err(|err| format!("failed to lookup local address: {err}"))?
            );

            server.register_socket(udp_socket);
        }
    } else {
        info!("UDP protocol is disabled");
    }

    if !config.disable_tcp() {
        // load all tcp listeners
        for addr in &listen_addrs {
            info!("binding TCP to {addr:?}");

            let tcp_listener = build_tcp_listener(*addr, listen_port)
                .map_err(|err| format!("failed to bind to TCP socket address {addr:?}: {err}"))?;

            info!(
                "listening for TCP on {:?}",
                tcp_listener
                    .local_addr()
                    .map_err(|err| format!("failed to lookup local address: {err}"))?
            );

            server.register_listener(tcp_listener, tcp_request_timeout);
        }
    } else {
        info!("TCP protocol is disabled");
    }

    // Drop privileges on Unix systems only when both user and group are explicitly configured.
    #[cfg(target_family = "unix")]
    match (config.user.as_deref(), config.group.as_deref()) {
        (Some(user), Some(group)) => check_drop_privs(user, group)?,
        (None, None) => info!("running with current process user/group"),
        _ => {
            return Err(
                "both 'user' and 'group' must be set together when requesting privilege drop"
                    .to_string(),
            )
        }
    }
    #[cfg(not(target_family = "unix"))]
    if config.user.is_some() || config.group.is_some() {
        return Err("dropping privileges is only supported on Unix systems".to_string());
    }

    #[cfg(unix)]
    {
        let shutdown_token = server.shutdown_token().clone();
        let mut server_task = tokio::spawn(async move { server.block_until_done().await });

        banner();
        info!("server starting up, awaiting connections...");

        loop {
            tokio::select! {
                _ = terminate_signal.recv() => {
                    info!("termination signal received, shutting down");
                    shutdown_token.cancel();
                    break;
                }
                _ = reload_signal.recv() => {
                    match reload_runtime_config(config_path, &args, &handler, &mut reload_settings).await {
                        Ok(()) => info!("configuration reload completed"),
                        Err(err) => error!("configuration reload failed: {err}"),
                    }
                }
                result = &mut server_task => {
                    let result = result.map_err(|err| format!("server task failed: {err}"))?;
                    return finish_server_run(result, runtime_handles).await;
                }
            }
        }

        let result = server_task
            .await
            .map_err(|err| format!("server task failed: {err}"))?;
        return finish_server_run(result, runtime_handles).await;
    }

    #[cfg(not(unix))]
    banner();
    #[cfg(not(unix))]
    info!("server starting up, awaiting connections...");
    #[cfg(not(unix))]
    let result = server.block_until_done().await;
    #[cfg(not(unix))]
    finish_server_run(result, runtime_handles).await
}

async fn finish_server_run(
    result: Result<(), hickory_proto::ProtoError>,
    #[allow(unused_variables)] runtime_handles: RuntimeHandles,
) -> Result<(), String> {
    match result {
        Ok(()) => info!("Hickory DNS {} stopping", hickory_client::version()),
        Err(e) => {
            let error_msg = format!(
                "Hickory DNS {} has encountered an error: {}",
                hickory_client::version(),
                e
            );
            error!("{error_msg}");
            return Err(error_msg);
        }
    }

    #[cfg(feature = "prometheus-metrics")]
    if let Some(server) = runtime_handles.prometheus_server {
        server.stop().await;
    }

    #[cfg(feature = "metrics")]
    runtime_handles.process_metrics_collector.abort();

    Ok(())
}

struct RuntimeHandles {
    #[cfg(feature = "prometheus-metrics")]
    prometheus_server: Option<PrometheusServer>,
    #[cfg(feature = "metrics")]
    process_metrics_collector: tokio::task::JoinHandle<()>,
}

async fn load_runtime_config(config_path: &std::path::Path) -> Result<LoadedRuntimeConfig, String> {
    let config = Config::read_config(config_path)
        .map_err(|err| format!("failed to read config file from {config_path:?}: {err}"))?;
    let catalog = build_catalog(config_path, &config).await?;
    Ok(LoadedRuntimeConfig {
        config,
        catalog: Arc::new(catalog),
    })
}

async fn build_catalog(config_path: &std::path::Path, config: &Config) -> Result<Catalog, String> {
    let adblock_rules = match config.adblock_runtime_config() {
        Some(runtime_config) => Some(CompiledRuleSets::build(runtime_config, config_path).await?),
        None => None,
    };

    let mut catalog = Catalog::new();
    for zone in config.zones() {
        let zone_name = zone
            .zone()
            .map_err(|err| format!("failed to read zone name from {config_path:?}: {err}"))?;

        match zone.load(adblock_rules.as_ref()).await {
            Ok(authority) => catalog.upsert(zone_name.into(), authority),
            Err(err) => return Err(format!("could not load zone {zone_name}: {err}")),
        }
    }

    Ok(catalog)
}

async fn reload_runtime_config(
    config_path: &std::path::Path,
    args: &Cli,
    handler: &ReloadableCatalog,
    active_settings: &mut ReloadSettings,
) -> Result<(), String> {
    info!("reloading configuration from {config_path:?}");

    let loaded = load_runtime_config(config_path).await?;
    let new_settings = ReloadSettings::from_effective_config(args, &loaded.config, config_path)?;
    active_settings.ensure_reload_safe(&new_settings)?;
    handler.replace(loaded.catalog);
    *active_settings = new_settings;

    Ok(())
}

struct LoadedRuntimeConfig {
    config: Config,
    catalog: Arc<Catalog>,
}

#[derive(Clone)]
struct ReloadableCatalog {
    current: Arc<RwLock<Arc<Catalog>>>,
}

impl ReloadableCatalog {
    fn new(initial: Arc<Catalog>) -> Self {
        Self {
            current: Arc::new(RwLock::new(initial)),
        }
    }

    fn replace(&self, catalog: Arc<Catalog>) {
        *self
            .current
            .write()
            .expect("reloadable catalog lock poisoned") = catalog;
    }
}

#[async_trait]
impl RequestHandler for ReloadableCatalog {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        response_handle: R,
    ) -> ResponseInfo {
        let catalog = self
            .current
            .read()
            .expect("reloadable catalog lock poisoned")
            .clone();
        catalog.handle_request(request, response_handle).await
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ReloadSettings {
    listen_addrs: Vec<IpAddr>,
    listen_port: u16,
    udp_enabled: bool,
    tcp_enabled: bool,
    tcp_request_timeout_secs: u64,
    user: Option<String>,
    group: Option<String>,
}

impl ReloadSettings {
    fn from_effective_config(
        args: &Cli,
        config: &Config,
        config_path: &std::path::Path,
    ) -> Result<Self, String> {
        let v4addr = config
            .listen_addrs_ipv4()
            .map_err(|err| format!("failed to parse IPv4 addresses from {config_path:?}: {err}"))?;
        let v6addr = config
            .listen_addrs_ipv6()
            .map_err(|err| format!("failed to parse IPv6 addresses from {config_path:?}: {err}"))?;

        let mut listen_addrs: Vec<IpAddr> = v4addr
            .into_iter()
            .map(IpAddr::V4)
            .chain(v6addr.into_iter().map(IpAddr::V6))
            .collect();
        if listen_addrs.is_empty() {
            listen_addrs.push(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
            listen_addrs.push(IpAddr::V6(Ipv6Addr::UNSPECIFIED));
        }
        listen_addrs.sort();

        Ok(Self {
            listen_addrs,
            listen_port: config.listen_port(),
            udp_enabled: !config.disable_udp(),
            tcp_enabled: !config.disable_tcp(),
            tcp_request_timeout_secs: config.tcp_request_timeout().as_secs(),
            user: config.user.clone(),
            group: config.group.clone(),
        })
    }

    fn ensure_reload_safe(&self, new: &Self) -> Result<(), String> {
        let mut changed = Vec::new();

        if self.listen_addrs != new.listen_addrs {
            changed.push("listen addresses");
        }
        if self.listen_port != new.listen_port {
            changed.push("listen port");
        }
        if self.udp_enabled != new.udp_enabled {
            changed.push("UDP enable/disable state");
        }
        if self.tcp_enabled != new.tcp_enabled {
            changed.push("TCP enable/disable state");
        }
        if self.tcp_request_timeout_secs != new.tcp_request_timeout_secs {
            changed.push("TCP request timeout");
        }
        if self.user != new.user {
            changed.push("user");
        }
        if self.group != new.group {
            changed.push("group");
        }

        if changed.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "hot reload only supports resolver and filtering changes; restart required because these settings changed: {}",
                changed.join(", ")
            ))
        }
    }
}

fn banner() {
    #[cfg(not(feature = "ascii-art"))]
    const CRATE_LOGO: &str = "Hickory DNS";

    info!("");
    for line in CRATE_LOGO.lines() {
        info!(" {line}");
    }
    info!("");
}

struct TdnsFormatter;

impl<S, N> FormatEvent<S, N> for TdnsFormatter
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: format::Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let now = OffsetDateTime::now_utc();
        let now_secs = now.unix_timestamp();

        // Format values from the event's's metadata:
        let metadata = event.metadata();
        write!(
            &mut writer,
            "{}:{}:{}",
            now_secs,
            metadata.level(),
            metadata.target()
        )?;

        if let Some(line) = metadata.line() {
            write!(&mut writer, ":{line}")?;
        }

        // Format all the spans in the event's span context.
        if let Some(scope) = ctx.event_scope() {
            for span in scope.from_root() {
                write!(writer, ":{}", span.name())?;

                let ext = span.extensions();
                let fields = &ext
                    .get::<FormattedFields<N>>()
                    .expect("will never be `None`");

                // Skip formatting the fields if the span had no fields.
                if !fields.is_empty() {
                    write!(writer, "{{{fields}}}")?;
                }
            }
        }

        // Write fields on the event
        write!(writer, ":")?;
        ctx.field_format().format_fields(writer.by_ref(), event)?;

        writeln!(writer)
    }
}

#[cfg(feature = "metrics")]
struct ConfigMetrics {
    #[cfg(feature = "resolver")]
    zones_forwarder: Counter,
}

#[cfg(feature = "metrics")]
impl ConfigMetrics {
    fn new(config: &Config) -> Self {
        let hickory_info = gauge!("hickory_info", "version" => hickory_client::version());
        describe_gauge!("hickory_info", Unit::Count, "hickory service metadata");
        hickory_info.set(1);

        let hickory_config_info = gauge!("hickory_config_info",
            "disable_https" => config.disable_https().to_string(),
            "disable_quic" => config.disable_quic().to_string(),
            "disable_tcp" => config.disable_tcp().to_string(),
            "disable_tls" => config.disable_tls().to_string(),
            "disable_udp" => config.disable_udp().to_string(),
            "zones" => config.zones().len().to_string()
        );
        describe_gauge!(
            "hickory_config_info",
            Unit::Count,
            "hickory config metadata"
        );
        hickory_config_info.set(1);

        let zones_total_name = "hickory_zones_total";

        describe_counter!(
            zones_total_name,
            Unit::Count,
            "number of dns zones in storages"
        );

        #[cfg(feature = "resolver")]
        let zones_forwarder = counter!(zones_total_name, "store" => "forwarder");

        Self {
            #[cfg(feature = "resolver")]
            zones_forwarder,
        }
    }

    fn increment_zone_metrics(&self, zone: &ZoneConfig) {
        match &zone.zone_type_config {
            ZoneTypeConfig::External { stores } => {
                for store in stores {
                    if let ExternalStoreConfig::Forward(_) = store {
                        self.zones_forwarder.increment(1)
                    }
                }
            }
        }
    }
}

/// Build a TcpListener for a given IP, port pair; IPv6 listeners will not accept v4 connections
fn build_tcp_listener(ip: IpAddr, port: u16) -> Result<TcpListener, Error> {
    let sock = if ip.is_ipv4() {
        Socket::new(Domain::IPV4, Type::STREAM, None)?
    } else {
        let s = Socket::new(Domain::IPV6, Type::STREAM, None)?;
        s.set_only_v6(true)?;
        s
    };

    sock.set_nonblocking(true)?;

    let s_addr = SocketAddr::new(ip, port);
    sock.bind(&s_addr.into())?;

    // this is a fairly typical backlog value, but we don't have any good data to support it as of yet
    sock.listen(128)?;

    TcpListener::from_std(sock.into())
}

/// Build a UdpSocket for a given IP, port pair; IPv6 sockets will not accept v4 connections
fn build_udp_socket(ip: IpAddr, port: u16) -> Result<UdpSocket, Error> {
    let sock = if ip.is_ipv4() {
        Socket::new(Domain::IPV4, Type::DGRAM, None)?
    } else {
        let s = Socket::new(Domain::IPV6, Type::DGRAM, None)?;
        s.set_only_v6(true)?;
        s
    };

    sock.set_nonblocking(true)?;

    let s_addr = SocketAddr::new(ip, port);
    sock.bind(&s_addr.into())?;

    UdpSocket::from_std(sock.into())
}

/// Drop privileges on Unix systems if running as root. Errors that prevent dropping privileges will
/// halt the server.  This must be called after binding to low numbered sockets is complete.
#[cfg(target_family = "unix")]
fn check_drop_privs(user: &str, group: &str) -> Result<(), String> {
    use libc::{getegid, geteuid, getgid, getgrnam, getpwnam, getuid, setgid, setuid};
    use std::ffi::CString;

    // These calls are guaranteed to succeed in a POSIX-conforming environment. In non-conforming
    // environments, implementations may return -1 to indicate a process running without an
    // associated UID/EUID/GID/EGID. In that case, our main block below will not execute as
    // libc typedefs uid_t and gid_t to u32; -1 will be u32::MAX.
    //
    // POSIX reference: IEEE Std 1003.1-1024 getuid, geteuid, getgid, and getegid specifications
    // https://pubs.opengroup.org/onlinepubs/9799919799/functions/getuid.html
    // https://pubs.opengroup.org/onlinepubs/9799919799/functions/geteuid.html
    // https://pubs.opengroup.org/onlinepubs/9799919799/functions/getgid.html
    // https://pubs.opengroup.org/onlinepubs/9799919799/functions/getegid.html
    let (uid, gid, euid, egid) = unsafe { (getuid(), getgid(), geteuid(), getegid()) };

    if uid == 0 || euid == 0 {
        info!(
            "running as root (uid: {uid} gid: {gid} euid: {euid} egid: {egid})...dropping privileges.",
        );

        let Ok(user_cstring) = CString::new(user) else {
            return Err(format!("unable to create CString for user {user}"));
        };

        let Ok(group_cstring) = CString::new(group) else {
            return Err(format!(
                "unable to create CString for group {group}. Exiting."
            ));
        };

        // These functions must be supplied a NULL-terminated string, which is guaranteed by
        // std::ffi::CString.  Upon success, they will return a pointer to a struct passwd or
        // struct group, or NULL upon failure. Testing for a NULL return value is mandatory.
        //
        // POSIX reference: IEEE Std 1003.1-1024 getpwnam and getgrnam specifications
        // https://pubs.opengroup.org/onlinepubs/9799919799/functions/getpwnam.html
        // https://pubs.opengroup.org/onlinepubs/9799919799/functions/getgrnam.html
        let (user_info, group_info) = unsafe {
            (
                getpwnam(user_cstring.as_ptr()),
                getgrnam(group_cstring.as_ptr()),
            )
        };

        if user_info.is_null() {
            return Err(format!("unable to lookup user '{user}'. Exiting."));
        }

        if group_info.is_null() {
            return Err(format!("unable to lookup group '{group}'. Exiting."));
        }

        // These functions must be supplied a gid_t (setgid) and uid_t (setuid), which are
        // supplied by the passwd and group structs returned by getpwnam and getgrnam.
        // The structs are tested to be valid by the calls to is_null() above.
        //
        // The call to setgid must be completed before the call to setuid is made or the
        // process will almost certainly lack the privileges necessary to switch its real gid.
        //
        // POSIX reference: IEEE Std 1003.1-1024 setgid and setuid specifications
        // https://pubs.opengroup.org/onlinepubs/9799919799/functions/setgid.html
        // https://pubs.opengroup.org/onlinepubs/9799919799/functions/setuid.html
        let (setgid_rc, setuid_rc) =
            unsafe { (setgid((*group_info).gr_gid), setuid((*user_info).pw_uid)) };

        if setgid_rc < 0 {
            return Err("unable to set gid. Exiting.".into());
        }

        if setuid_rc < 0 {
            return Err("unable to set uid. Exiting.".into());
        }
    }

    let (uid, gid, euid, egid) = unsafe { (getuid(), getgid(), geteuid(), getegid()) };

    info!("now running as uid: {uid}, gid: {gid} (euid: {euid}, egid: {egid})",);
    Ok(())
}
