# dns-server

`dns-server` is a Rust DNS server built on top of Hickory DNS.

The project started as a small Hickory-based DNS wrapper with custom YAML
configuration. It now focuses on a router-friendly forwarding and filtering
pipeline: remote filter download, local user rules, sinkhole or `NXDOMAIN`
blocking, and simple hosts-style overrides, all chained in front of the
upstream forwarder.

## Current Status

The repository currently works as:

- a forwarding DNS server
- an ad-blocking DNS server for a focused subset of AdGuard Home-style rules
- a small experimentation base for DNS filtering features

The current implementation has been verified with:

- `cargo build`
- `cargo test`
- live DNS queries against a local test setup
- config validation against the filter sources listed in `config.all.yaml`

## What It Does Today

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

- [src/bin/dns-server.rs](./src/bin/dns-server.rs): CLI entrypoint, Tokio
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
- TCP / UDP enable or disable
- TCP timeout
- access control with `allow_networks` and `deny_networks`
- `External` zones
- `forward`, `blocklist`, and `recursor` stores

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
./target/debug/dns-server -c named.yaml
```

Or use:

```bash
./run.sh
```

Validate config only:

```bash
./target/debug/dns-server --validate -c named.yaml
```

Query the server:

```bash
dig @127.0.0.1 -p 8053 example.com A
dig @127.0.0.1 -p 8053 example.com A +tcp
```

## Example Ad-Blocking Config

```yaml
listen_addrs_ipv4: ["127.0.0.1"]
listen_port: 8053

filters:
  - enabled: true
    url: "https://example.com/filter.txt"

user_rules:
  - "@@||example.com^"
  - "1.2.3.4 internal.example.com"

filtering:
  blocking_mode: default
  blocking_ipv4: 0.0.0.0
  blocking_ipv6: "::"

zones:
  - zone: "."
    zone_type: "External"
    stores:
      - type: "forward"
        name_servers:
          - socket_addr: "8.8.8.8:53"
            protocol: "udp"
            trust_negative_responses: false
```

## TODO

### Near-Term

- add periodic filter refresh and retry behavior
- persist downloaded filter lists on disk
- add structured query logging
- add basic stats for total queries, blocked queries, and filter counts
- make block TTL configurable instead of hardcoded
- add more integration tests around chained filtering behavior

### Rule Coverage

- support more AdGuard / ABP-style modifiers where they make sense for DNS
- decide how to handle unsupported modifiers explicitly instead of silently
  narrowing behavior
- add wildcard and rewrite semantics beyond the current domain-focused subset
- evaluate whether full syntax compatibility is a goal or whether the project
  should intentionally remain DNS-centric

### Product Hardening

- replace `unwrap` in config loading paths with better errors
- add filter download timeouts and backoff
- add reload support without full restart
- document migration expectations relative to AdGuard Home configs

## About `config.all.yaml`

`config.all.yaml` should currently be treated as a reference document, not as a
fully supported contract.

It is useful for:

- identifying which AdGuard Home concepts may be worth borrowing
- comparing future feature coverage
- testing how close this server should get to AdGuard-style configuration

It is not yet accurate to say that this project "supports `config.all.yaml`".
