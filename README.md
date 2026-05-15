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
- an ad-blocking DNS server for a focused subset of AdGuard Home-style rules
- a Cloudflare-oriented DNS rewrite layer for best-IP style redirection
- a small experimentation base for DNS filtering features

With the default example config in [named.yaml](./named.yaml), the server:

- listens on `0.0.0.0:8053`
- accepts both UDP and TCP DNS queries
- defines the root zone `.`
- forwards all queries to `8.8.8.8:53`

If ad-blocking config is added, the server can also:

- download remote filter lists from `filters[].url`
- parse a small subset of AdGuard-style domain blocking rules
- apply local `user_rules`
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
- TCP / UDP enable or disable
- TCP timeout
- `External` zones
- `forward` stores

`log_level` supports `Trace`, `Debug`, `Info`, `Warn`, and `Error`.
The default is `Warn` so normal router deployments do not spam per-query `INFO`
logs unless you explicitly opt in.

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

For ad-blocking, the server now imports a focused subset inspired by AdGuard
Home:

- `filters`
- `user_rules`
- `filtering.blocking_mode`
- `filtering.blocking_ipv4`
- `filtering.blocking_ipv6`
- `filtering.rewrites`

This is intentionally not full `config.all.yaml` compatibility.

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
- on-disk filter cache
- hot reload
- query log persistence
- per-filter statistics
- HTTP admin API or UI
- DHCP
- full rewrite syntax from `config.all.yaml` beyond the currently implemented
  `domain`, wildcard-domain, `ip`, and `cname` patterns
- complete DoH / DoT / DoQ product wiring

Some ABP-style rules are intentionally out of scope for now even if they can be
parsed elsewhere in the ecosystem:

- browser or HTTP request-context modifiers
- cosmetic filtering syntax
- script / resource-type specific behavior that has no DNS equivalent

## How To Run

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
- `filters`
- `user_rules`
- `filtering.blocking_mode`
- `filtering.blocking_ipv4`
- `filtering.blocking_ipv6`
- `filtering.rewrites`

Changes to listener or process-level settings such as listen addresses, port,
TCP or UDP enablement, timeout, user, or group still require a full restart.

Query the server:

```bash
dig @127.0.0.1 -p 8053 example.com A
dig @127.0.0.1 -p 8053 example.com A +tcp
```
