use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use ipnet::IpNet;
use tracing::warn;

use super::{
    BlockingMode, FilterConfig, FilteringConfig,
    config::RewriteConfig,
    fetch::fetch_filter,
};

#[derive(Clone, Debug)]
pub struct AdblockRuntimeConfig {
    pub filters: Vec<FilterConfig>,
    pub user_rules: Vec<String>,
    pub filtering: FilteringConfig,
}

#[derive(Clone, Debug, Default)]
pub struct OverrideRule {
    pub ipv4: Vec<Ipv4Addr>,
    pub ipv6: Vec<Ipv6Addr>,
}

#[derive(Clone, Debug, Default)]
pub struct RuleSets {
    pub overrides: HashMap<String, OverrideRule>,
    pub block_exact: HashSet<String>,
    pub block_subdomains: HashSet<String>,
    pub allow_exact: HashSet<String>,
    pub allow_subdomains: HashSet<String>,
}

#[derive(Clone, Debug)]
pub struct CompiledRuleSets {
    pub overrides: HashMap<String, OverrideRule>,
    pub block_exact: HashSet<String>,
    pub block_subdomains: HashSet<String>,
    pub allow_exact: HashSet<String>,
    pub allow_subdomains: HashSet<String>,
    pub domain_rewrites: Vec<DomainRewriteRule>,
    pub answer_ip_rewrites: Vec<AnswerIpRewriteRule>,
    pub cname_rewrites: Vec<CnameRewriteRule>,
    pub blocking_mode: BlockingMode,
    pub blocking_ipv4: Option<Ipv4Addr>,
    pub blocking_ipv6: Option<Ipv6Addr>,
    pub block_ttl: u32,
}

#[derive(Clone, Debug)]
pub struct DomainRewriteRule {
    pub pattern: DomainPattern,
    pub answer: OverrideRule,
}

#[derive(Clone, Debug)]
pub struct AnswerIpRewriteRule {
    pub nets: Vec<IpNet>,
    pub answer: OverrideRule,
}

#[derive(Clone, Debug)]
pub struct CnameRewriteRule {
    pub patterns: Vec<DomainPattern>,
    pub answer: OverrideRule,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum DomainPattern {
    Exact(String),
    WildcardSuffix(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuleDisposition {
    Block,
    Allow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuleOrigin {
    RemoteFilter,
    UserRule,
}

impl CompiledRuleSets {
    pub async fn build(config: AdblockRuntimeConfig) -> Result<Self, String> {
        let mut rules = RuleSets::default();

        for filter in config.filters.iter().filter(|filter| filter.enabled) {
            let contents = fetch_filter(filter).await?;
            parse_rule_lines(&contents, RuleOrigin::RemoteFilter, &mut rules);
        }

        for line in &config.user_rules {
            parse_rule_line(line, RuleOrigin::UserRule, &mut rules);
        }

        Ok(Self {
            overrides: rules.overrides,
            block_exact: rules.block_exact,
            block_subdomains: rules.block_subdomains,
            allow_exact: rules.allow_exact,
            allow_subdomains: rules.allow_subdomains,
            domain_rewrites: compile_domain_rewrites(&config.filtering.rewrites)?,
            answer_ip_rewrites: compile_answer_ip_rewrites(&config.filtering.rewrites)?,
            cname_rewrites: compile_cname_rewrites(&config.filtering.rewrites)?,
            blocking_mode: config.filtering.blocking_mode,
            blocking_ipv4: config.filtering.blocking_ipv4,
            blocking_ipv6: config.filtering.blocking_ipv6,
            block_ttl: 60,
        })
    }
}

fn parse_rule_lines(contents: &str, origin: RuleOrigin, rules: &mut RuleSets) {
    for line in contents.lines() {
        parse_rule_line(line, origin, rules);
    }
}

fn parse_rule_line(line: &str, origin: RuleOrigin, rules: &mut RuleSets) {
    let line = strip_comments(line).trim();
    if line.is_empty() {
        return;
    }

    if let Some((disposition, domain, include_subdomains)) = parse_adblock_domain_rule(line) {
        add_domain_rule(disposition, &domain, include_subdomains, rules);
        return;
    }

    if let Some((ip, domains)) = parse_hosts_rule(line) {
        match origin {
            RuleOrigin::RemoteFilter => {
                for domain in domains {
                    add_domain_rule(RuleDisposition::Block, &domain, false, rules);
                }
            }
            RuleOrigin::UserRule => {
                for domain in domains {
                    add_override(ip, &domain, rules);
                }
            }
        }
        return;
    }

    if let Some(domain) = normalize_domain(line) {
        add_domain_rule(RuleDisposition::Block, &domain, false, rules);
        return;
    }

    warn!("skipping unsupported rule line: {line}");
}

fn strip_comments(line: &str) -> &str {
    for marker in ['#', '!'] {
        if let Some((head, _)) = line.split_once(marker) {
            return head;
        }
    }

    line
}

fn parse_adblock_domain_rule(line: &str) -> Option<(RuleDisposition, String, bool)> {
    let (disposition, remainder) = if let Some(rest) = line.strip_prefix("@@") {
        (RuleDisposition::Allow, rest)
    } else {
        (RuleDisposition::Block, line)
    };

    let remainder = remainder.strip_prefix("||")?;
    let remainder = remainder.split('$').next().unwrap_or(remainder);
    let remainder = remainder.trim_end_matches('^');
    let remainder = remainder.trim_end_matches('|');
    let remainder = remainder.trim();
    let domain = normalize_domain(remainder)?;
    Some((disposition, domain, true))
}

fn parse_hosts_rule(line: &str) -> Option<(IpAddr, Vec<String>)> {
    let mut parts = line.split_whitespace();
    let ip = IpAddr::from_str(parts.next()?).ok()?;
    let domains: Vec<String> = parts.filter_map(normalize_domain).collect();
    if domains.is_empty() {
        return None;
    }
    Some((ip, domains))
}

fn normalize_domain(input: &str) -> Option<String> {
    let candidate = input
        .trim()
        .trim_matches('.')
        .trim_start_matches("*.")
        .to_ascii_lowercase();

    if candidate.is_empty()
        || candidate.contains('/')
        || candidate.contains(':')
        || candidate.contains(' ')
    {
        return None;
    }

    if !candidate
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-' || byte == b'_')
    {
        return None;
    }

    Some(candidate)
}

fn add_override(ip: IpAddr, domain: &str, rules: &mut RuleSets) {
    let entry = rules.overrides.entry(domain.to_owned()).or_default();
    match ip {
        IpAddr::V4(ipv4) => {
            if !entry.ipv4.contains(&ipv4) {
                entry.ipv4.push(ipv4);
            }
        }
        IpAddr::V6(ipv6) => {
            if !entry.ipv6.contains(&ipv6) {
                entry.ipv6.push(ipv6);
            }
        }
    }
}

fn add_domain_rule(
    disposition: RuleDisposition,
    domain: &str,
    include_subdomains: bool,
    rules: &mut RuleSets,
) {
    match disposition {
        RuleDisposition::Allow => {
            rules.block_exact.remove(domain);
            rules.block_subdomains.remove(domain);
            rules.allow_exact.insert(domain.to_owned());
            if include_subdomains {
                rules.allow_subdomains.insert(domain.to_owned());
            }
        }
        RuleDisposition::Block => {
            if is_allowed(domain, rules) {
                return;
            }
            rules.block_exact.insert(domain.to_owned());
            if include_subdomains {
                rules.block_subdomains.insert(domain.to_owned());
            }
        }
    }
}

fn is_allowed(domain: &str, rules: &RuleSets) -> bool {
    rules.allow_exact.contains(domain) || rules.allow_subdomains.iter().any(|suffix| suffix_match(domain, suffix))
}

fn suffix_match(domain: &str, suffix: &str) -> bool {
    domain == suffix
        || domain
            .strip_suffix(suffix)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

fn compile_domain_rewrites(rewrites: &[RewriteConfig]) -> Result<Vec<DomainRewriteRule>, String> {
    let mut compiled: HashMap<DomainPattern, OverrideRule> = HashMap::new();
    for rewrite in rewrites {
        let Some(domain) = rewrite.domain.as_ref() else {
            continue;
        };
        let answer = parse_override_answer(&rewrite.answer)?;
        let pattern = parse_domain_pattern(domain)?;
        let entry = compiled.entry(pattern).or_default();
        merge_override_rule(entry, &answer);
    }
    Ok(compiled
        .into_iter()
        .map(|(pattern, answer)| DomainRewriteRule { pattern, answer })
        .collect())
}

fn compile_answer_ip_rewrites(
    rewrites: &[RewriteConfig],
) -> Result<Vec<AnswerIpRewriteRule>, String> {
    let mut compiled = Vec::new();
    for rewrite in rewrites {
        if rewrite.ip.is_empty() {
            continue;
        }
        let answer = parse_override_answer(&rewrite.answer)?;
        let mut nets = Vec::new();
        for net in &rewrite.ip {
            nets.push(
                net.parse::<IpNet>()
                    .map_err(|err| format!("invalid rewrite IP network {net}: {err}"))?,
            );
        }
        compiled.push(AnswerIpRewriteRule { nets, answer });
    }
    Ok(compiled)
}

fn compile_cname_rewrites(rewrites: &[RewriteConfig]) -> Result<Vec<CnameRewriteRule>, String> {
    let mut compiled = Vec::new();
    for rewrite in rewrites {
        if rewrite.cname.is_empty() {
            continue;
        }
        let answer = parse_override_answer(&rewrite.answer)?;
        let mut patterns = Vec::new();
        for item in &rewrite.cname {
            let raw = item.strip_prefix("domain:").unwrap_or(item);
            patterns.push(parse_domain_pattern(raw)?);
        }
        compiled.push(CnameRewriteRule { patterns, answer });
    }
    Ok(compiled)
}

fn parse_override_answer(answer: &str) -> Result<OverrideRule, String> {
    let ip = IpAddr::from_str(answer)
        .map_err(|err| format!("invalid rewrite answer {answer}: {err}"))?;
    let mut rule = OverrideRule::default();
    match ip {
        IpAddr::V4(ipv4) => rule.ipv4.push(ipv4),
        IpAddr::V6(ipv6) => rule.ipv6.push(ipv6),
    }
    Ok(rule)
}

fn merge_override_rule(target: &mut OverrideRule, source: &OverrideRule) {
    for ip in &source.ipv4 {
        if !target.ipv4.contains(ip) {
            target.ipv4.push(*ip);
        }
    }
    for ip in &source.ipv6 {
        if !target.ipv6.contains(ip) {
            target.ipv6.push(*ip);
        }
    }
}

fn parse_domain_pattern(value: &str) -> Result<DomainPattern, String> {
    let normalized = normalize_domain(value)
        .ok_or_else(|| format!("invalid rewrite domain pattern: {value}"))?;
    if value.trim().starts_with("*.") {
        Ok(DomainPattern::WildcardSuffix(normalized))
    } else {
        Ok(DomainPattern::Exact(normalized))
    }
}

pub fn domain_pattern_matches(pattern: &DomainPattern, domain: &str) -> bool {
    match pattern {
        DomainPattern::Exact(exact) => domain == exact,
        DomainPattern::WildcardSuffix(suffix) => {
            domain != suffix && suffix_match(domain, suffix)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_adblock_and_hosts_rules() {
        let mut rules = RuleSets::default();

        parse_rule_line("||ads.example.com^", RuleOrigin::RemoteFilter, &mut rules);
        parse_rule_line("@@||good.example.com^", RuleOrigin::UserRule, &mut rules);
        parse_rule_line("1.2.3.4 internal.example.com", RuleOrigin::UserRule, &mut rules);

        assert!(rules.block_exact.contains("ads.example.com"));
        assert!(rules.block_subdomains.contains("ads.example.com"));
        assert!(rules.allow_exact.contains("good.example.com"));
        assert!(rules.allow_subdomains.contains("good.example.com"));
        assert_eq!(
            rules
                .overrides
                .get("internal.example.com")
                .expect("override missing")
                .ipv4,
            vec![Ipv4Addr::new(1, 2, 3, 4)]
        );
    }

    #[test]
    fn allowlist_prevents_later_block_rule() {
        let mut rules = RuleSets::default();

        parse_rule_line("@@||video.example.com^", RuleOrigin::UserRule, &mut rules);
        parse_rule_line("||video.example.com^", RuleOrigin::RemoteFilter, &mut rules);

        assert!(!rules.block_exact.contains("video.example.com"));
        assert!(rules.allow_subdomains.contains("video.example.com"));
    }

    #[test]
    fn wildcard_rewrite_pattern_matches_only_subdomains() {
        let pattern = DomainPattern::WildcardSuffix("vrdesktop.net".to_string());
        assert!(domain_pattern_matches(&pattern, "a.vrdesktop.net"));
        assert!(!domain_pattern_matches(&pattern, "vrdesktop.net"));
    }

    #[test]
    fn merges_duplicate_domain_rewrite_answers() {
        let rewrites = vec![
            RewriteConfig {
                domain: Some("its.pkupi.com".to_string()),
                answer: "198.41.198.152".to_string(),
                ..RewriteConfig::default()
            },
            RewriteConfig {
                domain: Some("its.pkupi.com".to_string()),
                answer: "104.27.105.80".to_string(),
                ..RewriteConfig::default()
            },
        ];

        let compiled = compile_domain_rewrites(&rewrites).expect("compile failed");
        assert_eq!(compiled.len(), 1);
        assert_eq!(compiled[0].answer.ipv4.len(), 2);
    }
}
