# astra-dns

`astra-dns` is a Rust DNS server built on top of Hickory DNS.

This project started from a very specific OpenWrt pain point discussed by the
community: if you want both ad blocking and Cloudflare best-IP redirection, you
often end up chaining multiple DNS components such as MosDNS, AdGuard Home, and
Mihomo, with a setup that works but is fairly complex to understand and
maintain. See these two discussions for the original motivation:

- OpenWrt Nikki discussion about combining MosDNS, AdGuard Home, and Mihomo:
  https://github.com/nikkinikki-org/OpenWrt-nikki/discussions/197
- CloudflareSpeedTest discussion about redirecting Cloudflare answers to the
  fastest IP with mosdns:
  https://github.com/XIU2/CloudflareSpeedTest/discussions/317

`astra-dns` exists to collapse that workflow into a smaller, more direct DNS
stack that can handle forwarding, filtering, and Cloudflare-oriented rewrite
logic in one place.

## Features

`astra-dns` focuses on a router-friendly forwarding and filtering
pipeline built on Hickory DNS. The repository currently works as:

- a forwarding DNS server
- a DNS-over-HTTPS upstream client with TLS certificate validation
- an ad-blocking DNS server for a focused subset of AdGuard Home-style rules
- a Cloudflare-oriented DNS rewrite layer for best-IP style redirection
- a small experimentation base for DNS filtering features

With the default example config in [named.yaml](./named.yaml), the server:

- listens on `0.0.0.0:8053`
- accepts both UDP and TCP DNS queries
- defines the root zone `.`
- forwards all queries to `8.8.8.8:53`
- reads dnsmasq/OpenWrt DHCP leases from `/var/dhcp.leases` for LAN hostname
  and reverse PTR overrides when that file exists

If ad-blocking config is added, the server can also:

- download remote filter lists from `filters[].url`
- parse a small subset of AdGuard-style domain blocking rules
- apply local `user_rules`
- apply DHCP lease hostnames and reverse PTRs as local answers
- apply a focused subset of `filtering.rewrites`
- allowlist domains before block rules are applied
- return sinkhole IPs or `NXDOMAIN` for blocked domains
- override exact domains with hosts-style local answers
- forward unmatched queries upstream

## Architecture

The main runtime is still Hickory-based:

- [src/bin/astra-dns.rs](./src/bin/astra-dns.rs): CLI entrypoint, Tokio
  runtime, config loading, server startup
- [src/lib.rs](./src/lib.rs): config schema and zone/store loading

The ad-blocking logic is intentionally split into its own module tree:

- [src/adblock/config.rs](./src/adblock/config.rs): the imported config subset
- [src/adblock/fetch.rs](./src/adblock/fetch.rs): remote filter download
- [src/adblock/rules.rs](./src/adblock/rules.rs): rule parsing, normalization,
  precedence, compiled rule sets
- [src/adblock/authority.rs](./src/adblock/authority.rs): custom Hickory
  authorities for exact overrides and domain blocking
- [src/adblock/mod.rs](./src/adblock/mod.rs): authority chain assembly

At startup, the ad-blocking path is assembled as:

1. `OverrideAuthority`
2. `RewriteAuthority`
2. `BlockAuthority`
3. Hickory `ForwardAuthority`

That ordering gives the current effective precedence:

1. exact hosts-style override
2. rewrite override
3. important allow rules
4. important block rules
5. normal allow rules
6. normal block rules
7. upstream forwarding

## Config Model

The server supports these core DNS settings:

- listen IPv4 / IPv6 addresses
- listen port
- `log_level`
- `filter_cache_dir`
- `filter_refresh_interval_secs`
- TCP / UDP enable or disable
- TCP timeout
- `External` zones
- `forward` stores

`log_level` supports `Trace`, `Debug`, `Info`, `Warn`, and `Error`.
The default is `Warn` so normal router deployments do not spam per-query `INFO`
logs unless you explicitly opt in.

`filter_cache_dir` controls where downloaded remote filter lists are cached.
The default is `/tmp/astra-dns/filters-cache`, which keeps router deployments
from writing these refreshes to flash unless you explicitly choose a persistent
directory. Startup and `SIGHUP` load cached lists without making network requests.
Missing lists are downloaded after DNS starts serving, with retry delays growing
up to 30 seconds if the network is unavailable. Until a first download succeeds,
local rules and any existing cached lists remain active.

`filter_refresh_interval_secs` controls scheduled remote filter refreshes and
defaults to `86400` (one day). Set it to `0` to disable scheduled refreshes.
Refreshes run while the existing DNS catalog continues serving requests; the
new catalog replaces it only after loading completes. If a download fails, the
cached list remains active.

For a simple router-style forwarding setup, the server also supports a compact
AdGuard Home-inspired syntax:

```yaml
dns:
  upstream_dns:
    - 127.0.0.1:7874
    - 8.8.8.8
```

That compact form is translated internally into a root `External` forward zone.
Do not combine it with `zones` in the same config file.

DNS-over-HTTPS upstreams use standard HTTPS URLs. Hostname endpoints are
resolved through the system resolver only for the initial connection; TLS
still verifies the hostname from the URL. To control that initial lookup,
provide ordinary DNS resolver addresses through `bootstrap_ips`:

```yaml
dns:
  upstream_dns:
    - https://doh.cleanbrowsing.org/doh/security-filter/
    - https://freedns.controld.com/p0
  bootstrap_ips:
    - 223.5.5.5
    - 119.29.29.29
  cache_size: 4096
```

`dns.bootstrap_ips` is shared by all domain-based DoH URLs in `upstream_dns`.
These bootstrap queries use plaintext DNS only to discover the HTTPS server
addresses; normal forwarded queries remain encrypted and verify each URL's TLS
hostname. If `bootstrap_ips` is omitted, the system resolver performs the
initial hostname lookups instead.

Hostname-based DoH upstreams are initialized independently in the background.
An unavailable bootstrap resolver does not prevent UDP/TCP listeners, local
rewrites, LAN hostnames, or cached filtering rules from starting. Queries that
need forwarding return `SERVFAIL` while no upstream is ready. Bootstrap lookups
have a five-second deadline and retry with exponential backoff from one to
30 seconds. An available upstream can serve queries while another is recovering.

Once resolved, an upstream keeps its resolver and DNS cache across transient
network failures. Its addresses are refreshed in the background; unchanged
addresses or a failed refresh do not discard that resolver. Network recovery
does not require a process restart. Configure `bootstrap_ips` when the system
resolver forwards to Astra itself, to avoid a DNS bootstrap loop. These settings
do not add a plaintext fallback for ordinary queries or disable TLS verification.

A URL whose host is already an IP address can use the compact form directly,
for example `https://1.1.1.1/dns-query`. DoH uses HTTP/2 with certificate
validation and defaults to `/dns-query` when the URL has no explicit path.

For ad-blocking, the server now imports a focused subset inspired by AdGuard
Home:

- `filters`
- `user_rules`
- `filtering.blocking_mode`
- `filtering.blocking_ipv4`
- `filtering.blocking_ipv6`
- `filtering.rewrites`

This is intentionally not full `config.all.yaml` compatibility.

For router LAN names, `lan_hosts` reads dnsmasq/OpenWrt lease files using the
standard five-column shape:

```text
expires mac ip hostname clientid
```

By default, this support is enabled and reads `/var/dhcp.leases`. Hostnames set
to `*` are ignored. Each lease hostname is exposed both as the bare hostname and
under the configured LAN domain, which defaults to `lan`. Reverse lookups return
the domain-qualified hostname when a domain is configured. Lease files are
loaded at startup and refreshed every 60 seconds by default; set
`refresh_interval_secs` to `0` to only load leases at startup or after a
`SIGHUP` reload.

```yaml
lan_hosts:
  enabled: true
  source: /var/dhcp.leases
  domain: lan
  include_unqualified: true
  refresh_interval_secs: 60
```

## Currently Supported Rule Syntax

Remote filter lists currently support:

- plain domains such as `ads.example.com`
- hosts-style entries such as `0.0.0.0 ads.example.com`
- AdGuard / ABP-style domain rules such as `||ads.example.com^`
- wildcard domain rules such as `||ac*.786ip.com^` or `||ping.*.sogou.com^`
- anchored patterns such as `|load.gtm.` and `|c.blue.*.com^|`
- leading-dot patterns such as `.bbelements.com^`
- regex rules such as `/^(\S+\.)?analytics(\-|\.)/`

Local `user_rules` currently support:

- allow rules such as `@@||good.example.com^`
- block rules such as `||ads.example.com^`
- hosts-style overrides such as `1.2.3.4 internal.example.com`
- the same wildcard, anchor, and regex forms accepted in remote filters

Currently supported `filtering.rewrites` shapes:

- exact domain rewrite such as `domain: time.facebook.com`
- wildcard subdomain rewrite such as `domain: '*.vrdesktop.net'`
- answer-IP rewrite based on CIDR match such as `ip: ["1.1.1.0/24"]`
- CNAME-target rewrite such as `cname: ["domain:cdn.cloudflare.net"]`
- `answer` may be either a single IP string or an array of IP strings; array answers return all listed A/AAAA records

Currently supported blocking modes:

- `default`
  returns sinkhole A/AAAA answers, defaulting to `0.0.0.0` / `::`
- `nxdomain`
  returns `NXDOMAIN`

Currently supported AdGuard-style modifiers:

- `$important`
- `$badfilter`
- `$dnstype=...`
- `$denyallow=...`

These were specifically extended to cover the rule formats present in the
filter sources referenced by `config.all.yaml`:

- AdGuard DNS filter
- AdAway hosts
- anti-AD
- 217heidai

## What Is Not Supported Yet

This repository is not yet a full AdGuard Home replacement.

Notably missing:

- full AdGuard Home rule syntax compatibility
- most non-DNS ABP / AdGuard modifiers
- client-specific filtering
- periodic filter refresh
- hot reload
- query log persistence
- per-filter statistics
- HTTP admin API or UI
- DHCP
- full rewrite syntax from `config.all.yaml` beyond the currently implemented
  `domain`, wildcard-domain, `ip`, and `cname` patterns
- DoT / DoQ upstream wiring

Some ABP-style rules are intentionally out of scope for now even if they can be
parsed elsewhere in the ecosystem:

- browser or HTTP request-context modifiers
- cosmetic filtering syntax
- script / resource-type specific behavior that has no DNS equivalent

## How To Run

Requires Rust 1.88 or newer (Hickory DNS 0.26.3).

Build and run:

```bash
cargo build
./target/debug/astra-dns -c named.yaml
```

Or use:

```bash
./run.sh
```

Validate config only:

```bash
./target/debug/astra-dns --validate -c named.yaml
```

`--validate` only checks local YAML content and locally defined rules. It does
not download remote filter lists.

Reload configuration after editing the YAML:

```bash
kill -HUP "$(pidof astra-dns)"
```

Current hot reload support is limited to resolver and filtering changes such as:

- `dns.upstream_dns`
- `dns.bootstrap_ips`
- `filters`
- `user_rules`
- `filtering.blocking_mode`
- `filtering.blocking_ipv4`
- `filtering.blocking_ipv6`
- `filtering.rewrites`
- `lan_hosts`

Lease file contents are also re-read when the catalog is rebuilt, including
after a successful `SIGHUP` reload.

Remote filter cache files are also re-read on `SIGHUP`, but they are not
downloaded again until `filter_refresh_interval_secs` elapses. A newly enabled
filter with no cache is downloaded in the background after the new local rules
are loaded, including when scheduled refreshes are disabled.

Changes to listener or process-level settings such as listen addresses, port,
TCP or UDP enablement, timeout, user, or group still require a full restart.

Query the server:

```bash
dig @127.0.0.1 -p 8053 example.com A
dig @127.0.0.1 -p 8053 example.com A +tcp
```
