mod authority;
mod config;
mod fetch;
mod rules;

use std::{
    net::{Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use hickory_proto::rr::Name;
use hickory_server::{
    authority::AuthorityObject,
    store::forwarder::{ForwardAuthority, ForwardConfig},
};

pub use config::{BlockingMode, FilterConfig, FilteringConfig, LanHostsConfig};
pub use rules::{AdblockRuntimeConfig, CompiledRuleSets};

use self::authority::{BlockAuthority, OverrideAuthority, RewriteAuthority};

pub fn build_authorities(
    origin: Name,
    forward_config: ForwardConfig,
    compiled: &CompiledRuleSets,
) -> Result<Vec<Arc<dyn AuthorityObject>>, String> {
    let mut authorities: Vec<Arc<dyn AuthorityObject>> = Vec::new();

    if let Some(authority) = override_authority(origin.clone(), compiled)? {
        authorities.push(authority);
    }

    if let Some(authority) = rewrite_authority(origin.clone(), compiled)? {
        authorities.push(authority);
    }

    if let Some(authority) = block_authority(origin.clone(), compiled)? {
        authorities.push(authority);
    }

    let forwarder = ForwardAuthority::builder_tokio(forward_config)
        .with_origin(origin)
        .build()?;
    authorities.push(Arc::new(forwarder));

    Ok(authorities)
}

fn override_authority(
    origin: Name,
    compiled: &CompiledRuleSets,
) -> Result<Option<Arc<dyn AuthorityObject>>, String> {
    if compiled.overrides.is_empty()
        && compiled.ptr_overrides.is_empty()
        && !compiled.lan_hosts.enabled
    {
        return Ok(None);
    }

    let authority = OverrideAuthority::new(
        origin,
        compiled.overrides.clone(),
        compiled.ptr_overrides.clone(),
        compiled.lan_hosts.clone(),
    )?;
    Ok(Some(Arc::new(authority)))
}

fn block_authority(
    origin: Name,
    compiled: &CompiledRuleSets,
) -> Result<Option<Arc<dyn AuthorityObject>>, String> {
    if compiled.block_exact.is_empty()
        && compiled.block_subdomains.is_empty()
        && compiled.block_rules.is_empty()
        && compiled.allow_rules.is_empty()
    {
        return Ok(None);
    }

    let authority = BlockAuthority::new(
        origin,
        compiled.block_exact.clone(),
        compiled.block_subdomains.clone(),
        compiled.allow_exact.clone(),
        compiled.allow_subdomains.clone(),
        compiled.block_rules.clone(),
        compiled.allow_rules.clone(),
        compiled.blocking_mode,
        compiled.blocking_ipv4.unwrap_or(Ipv4Addr::UNSPECIFIED),
        compiled.blocking_ipv6.unwrap_or(Ipv6Addr::UNSPECIFIED),
        compiled.block_ttl,
    )?;
    Ok(Some(Arc::new(authority)))
}

fn rewrite_authority(
    origin: Name,
    compiled: &CompiledRuleSets,
) -> Result<Option<Arc<dyn AuthorityObject>>, String> {
    if compiled.domain_rewrites.is_empty()
        && compiled.answer_ip_rewrites.is_empty()
        && compiled.cname_rewrites.is_empty()
    {
        return Ok(None);
    }

    let authority = RewriteAuthority::new(
        origin,
        compiled.domain_rewrites.clone(),
        compiled.answer_ip_rewrites.clone(),
        compiled.cname_rewrites.clone(),
    )?;
    Ok(Some(Arc::new(authority)))
}

pub fn is_adblock_enabled(
    filters: &[FilterConfig],
    user_rules: &[String],
    filtering: &FilteringConfig,
    lan_hosts: &LanHostsConfig,
) -> bool {
    filters.iter().any(|filter| filter.enabled)
        || !user_rules.is_empty()
        || !filtering.rewrites.is_empty()
        || lan_hosts.enabled
}
