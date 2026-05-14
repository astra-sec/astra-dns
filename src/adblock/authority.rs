use std::{
    collections::{HashMap, HashSet},
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use async_trait::async_trait;
use hickory_proto::rr::{
    LowerName, Name, RData, Record, RecordType, RecordSet,
    rdata::{A, AAAA, CNAME},
};
use hickory_server::{
    authority::{
        AuthLookup, Authority, LookupControlFlow, LookupError, LookupOptions, LookupRecords,
        LookupObject, MessageRequest, UpdateResult, ZoneType,
    },
    proto::op::ResponseCode,
    server::RequestInfo,
};

use super::{
    BlockingMode,
    rules::{
        AnswerIpRewriteRule, CnameRewriteRule, CompiledMatchRule, DomainRewriteRule,
        OverrideRule, TypeConstraint, domain_pattern_matches,
    },
};

pub struct OverrideAuthority {
    origin: LowerName,
    overrides: HashMap<LowerName, OverrideRule>,
}

impl OverrideAuthority {
    pub fn new(origin: Name, overrides: HashMap<String, OverrideRule>) -> Result<Self, String> {
        let mut normalized = HashMap::new();
        for (domain, override_rule) in overrides {
            let mut name = Name::from_ascii(&domain)
                .map_err(|err| format!("invalid override domain {domain}: {err}"))?;
            name.set_fqdn(true);
            normalized.insert(LowerName::from(name), override_rule);
        }

        Ok(Self {
            origin: LowerName::from(origin),
            overrides: normalized,
        })
    }
}

#[async_trait]
impl Authority for OverrideAuthority {
    type Lookup = AuthLookup;

    fn zone_type(&self) -> ZoneType {
        ZoneType::External
    }

    fn is_axfr_allowed(&self) -> bool {
        false
    }

    async fn update(&self, _update: &MessageRequest) -> UpdateResult<bool> {
        Err(ResponseCode::NotImp)
    }

    fn origin(&self) -> &LowerName {
        &self.origin
    }

    async fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup> {
        use LookupControlFlow::{Break, Skip};

        let Some(override_rule) = self.overrides.get(name) else {
            return Skip;
        };

        let records = override_lookup_records(name, override_rule, rtype, lookup_options);
        Break(Ok(records))
    }

    async fn search(
        &self,
        request_info: RequestInfo<'_>,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup> {
        self.lookup(
            request_info.query.name(),
            request_info.query.query_type(),
            lookup_options,
        )
        .await
    }

    async fn get_nsec_records(
        &self,
        _name: &LowerName,
        _lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup> {
        LookupControlFlow::Continue(Err(LookupError::from(io::Error::other(
            "Getting NSEC records is unimplemented for overrides",
        ))))
    }

}

pub struct BlockAuthority {
    origin: LowerName,
    block_exact: HashSet<String>,
    block_subdomains: HashSet<String>,
    allow_exact: HashSet<String>,
    allow_subdomains: HashSet<String>,
    block_rules: Vec<CompiledMatchRule>,
    allow_rules: Vec<CompiledMatchRule>,
    blocking_mode: BlockingMode,
    blocking_ipv4: Ipv4Addr,
    blocking_ipv6: Ipv6Addr,
    ttl: u32,
}

pub struct RewriteAuthority {
    origin: LowerName,
    domain_rewrites: Vec<DomainRewriteRule>,
    answer_ip_rewrites: Vec<AnswerIpRewriteRule>,
    cname_rewrites: Vec<CnameRewriteRule>,
}

impl RewriteAuthority {
    pub fn new(
        origin: Name,
        domain_rewrites: Vec<DomainRewriteRule>,
        answer_ip_rewrites: Vec<AnswerIpRewriteRule>,
        cname_rewrites: Vec<CnameRewriteRule>,
    ) -> Result<Self, String> {
        Ok(Self {
            origin: LowerName::from(origin),
            domain_rewrites,
            answer_ip_rewrites,
            cname_rewrites,
        })
    }
}

impl BlockAuthority {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        origin: Name,
        block_exact: HashSet<String>,
        block_subdomains: HashSet<String>,
        allow_exact: HashSet<String>,
        allow_subdomains: HashSet<String>,
        block_rules: Vec<CompiledMatchRule>,
        allow_rules: Vec<CompiledMatchRule>,
        blocking_mode: BlockingMode,
        blocking_ipv4: Ipv4Addr,
        blocking_ipv6: Ipv6Addr,
        ttl: u32,
    ) -> Result<Self, String> {
        Ok(Self {
            origin: LowerName::from(origin),
            block_exact,
            block_subdomains,
            allow_exact,
            allow_subdomains,
            block_rules,
            allow_rules,
            blocking_mode,
            blocking_ipv4,
            blocking_ipv6,
            ttl,
        })
    }

    fn matches_allowlist(&self, domain: &str) -> bool {
        self.allow_exact.contains(domain)
            || self
                .allow_subdomains
                .iter()
                .any(|suffix| suffix_match(domain, suffix))
    }

    fn matches_blocklist(&self, domain: &str) -> bool {
        self.block_exact.contains(domain)
            || self
                .block_subdomains
                .iter()
                .any(|suffix| suffix_match(domain, suffix))
    }

    fn matches_rule_list(
        &self,
        rules: &[CompiledMatchRule],
        domain: &str,
        rtype: RecordType,
    ) -> bool {
        rules.iter().any(|rule| {
            if !rule_allows_type(rule, rtype) {
                return false;
            }
            if rule
                .denyallow
                .iter()
                .any(|pattern| domain_pattern_matches(pattern, domain))
            {
                return false;
            }
            match &rule.matcher {
                super::rules::Matcher::Regex(regex) => regex.is_match(domain),
            }
        })
    }

    fn matches_allowlist_important(&self, domain: &str, rtype: RecordType) -> bool {
        self.allow_rules
            .iter()
            .filter(|rule| rule.important)
            .any(|rule| complex_rule_matches(rule, domain, rtype))
    }

    fn matches_blocklist_important(&self, domain: &str, rtype: RecordType) -> bool {
        self.block_rules
            .iter()
            .filter(|rule| rule.important)
            .any(|rule| complex_rule_matches(rule, domain, rtype))
    }
}

#[async_trait]
impl Authority for BlockAuthority {
    type Lookup = AuthLookup;

    fn zone_type(&self) -> ZoneType {
        ZoneType::External
    }

    fn is_axfr_allowed(&self) -> bool {
        false
    }

    async fn update(&self, _update: &MessageRequest) -> UpdateResult<bool> {
        Err(ResponseCode::NotImp)
    }

    fn origin(&self) -> &LowerName {
        &self.origin
    }

    async fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup> {
        use LookupControlFlow::Skip;

        let domain = normalized_query_name(name);
        if self.matches_allowlist_important(&domain, rtype) {
            return Skip;
        }

        if self.matches_blocklist_important(&domain, rtype) {
            return self.block_response(name, rtype, lookup_options);
        }

        let allowed_normal = self.matches_allowlist(&domain)
            || self.matches_rule_list(&self.allow_rules, &domain, rtype);
        let blocked_normal = self.matches_blocklist(&domain)
            || self.matches_rule_list(&self.block_rules, &domain, rtype);

        if allowed_normal || !blocked_normal {
            return Skip;
        }

        self.block_response(name, rtype, lookup_options)
    }

    async fn search(
        &self,
        request_info: RequestInfo<'_>,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup> {
        self.lookup(
            request_info.query.name(),
            request_info.query.query_type(),
            lookup_options,
        )
        .await
    }

    async fn get_nsec_records(
        &self,
        _name: &LowerName,
        _lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup> {
        LookupControlFlow::Continue(Err(LookupError::from(io::Error::other(
            "Getting NSEC records is unimplemented for the blocklist",
        ))))
    }

}

impl BlockAuthority {
    fn block_response(
        &self,
        name: &LowerName,
        rtype: RecordType,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        use LookupControlFlow::Break;

        match self.blocking_mode {
            BlockingMode::Default => Break(Ok(block_lookup_records(
                name,
                rtype,
                lookup_options,
                self.blocking_ipv4,
                self.blocking_ipv6,
                self.ttl,
            ))),
            BlockingMode::Nxdomain => Break(Err(LookupError::from(ResponseCode::NXDomain))),
        }
    }
}

#[async_trait]
impl Authority for RewriteAuthority {
    type Lookup = AuthLookup;

    fn zone_type(&self) -> ZoneType {
        ZoneType::External
    }

    fn is_axfr_allowed(&self) -> bool {
        false
    }

    async fn update(&self, _update: &MessageRequest) -> UpdateResult<bool> {
        Err(ResponseCode::NotImp)
    }

    fn origin(&self) -> &LowerName {
        &self.origin
    }

    async fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup> {
        use LookupControlFlow::{Break, Skip};

        let domain = normalized_query_name(name);
        let Some(rule) = self
            .domain_rewrites
            .iter()
            .find(|rule| domain_pattern_matches(&rule.pattern, &domain))
        else {
            return Skip;
        };

        Break(Ok(override_lookup_records(
            name,
            &rule.answer,
            rtype,
            lookup_options,
        )))
    }

    async fn consult(
        &self,
        name: &LowerName,
        rtype: RecordType,
        lookup_options: LookupOptions,
        last_result: LookupControlFlow<Box<dyn LookupObject>>,
    ) -> LookupControlFlow<Box<dyn LookupObject>> {
        use LookupControlFlow::{Break, Continue};

        let lookup = match last_result {
            Break(Ok(lookup)) | Continue(Ok(lookup)) => lookup,
            Break(Err(err)) => return Break(Err(err)),
            Continue(Err(err)) => return Continue(Err(err)),
            LookupControlFlow::Skip => return LookupControlFlow::Skip,
        };

        let records: Vec<Record> = lookup.iter().cloned().collect();

        if let Some(rule) = self.match_answer_ip_rewrite(&records) {
            return Break(Ok(Box::new(override_lookup_records(
                name,
                &rule.answer,
                rtype,
                lookup_options,
            ))));
        }

        if let Some(rule) = self.match_cname_rewrite(&records) {
            return Break(Ok(Box::new(override_lookup_records(
                name,
                &rule.answer,
                rtype,
                lookup_options,
            ))));
        }

        Continue(Ok(lookup))
    }

    async fn search(
        &self,
        request_info: RequestInfo<'_>,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup> {
        self.lookup(
            request_info.query.name(),
            request_info.query.query_type(),
            lookup_options,
        )
        .await
    }

    async fn get_nsec_records(
        &self,
        _name: &LowerName,
        _lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup> {
        LookupControlFlow::Continue(Err(LookupError::from(io::Error::other(
            "Getting NSEC records is unimplemented for rewrites",
        ))))
    }
}

impl RewriteAuthority {
    fn match_answer_ip_rewrite<'a>(
        &'a self,
        records: &[Record],
    ) -> Option<&'a AnswerIpRewriteRule> {
        self.answer_ip_rewrites.iter().find(|rule| {
            records.iter().any(|record| {
                let Some(ip) = record_ip(record) else {
                    return false;
                };
                rule.nets.iter().any(|net| net.contains(&ip))
            })
        })
    }

    fn match_cname_rewrite<'a>(&'a self, records: &[Record]) -> Option<&'a CnameRewriteRule> {
        self.cname_rewrites.iter().find(|rule| {
            records.iter().any(|record| {
                let Some(target) = record_cname(record) else {
                    return false;
                };
                rule.patterns
                    .iter()
                    .any(|pattern| domain_pattern_matches(pattern, &target))
            })
        })
    }
}

fn override_lookup_records(
    name: &LowerName,
    override_rule: &OverrideRule,
    rtype: RecordType,
    lookup_options: LookupOptions,
) -> AuthLookup {
    let mut record_sets = Vec::new();
    let fqdn_name = Name::from(name);

    if matches!(rtype, RecordType::A | RecordType::ANY) && !override_rule.ipv4.is_empty() {
        let mut set = RecordSet::with_ttl(fqdn_name.clone(), RecordType::A, 60);
        for ip in &override_rule.ipv4 {
            set.add_rdata(RData::A(A(*ip)));
        }
        record_sets.push(Arc::new(set));
    }

    if matches!(rtype, RecordType::AAAA | RecordType::ANY) && !override_rule.ipv6.is_empty() {
        let mut set = RecordSet::with_ttl(fqdn_name, RecordType::AAAA, 60);
        for ip in &override_rule.ipv6 {
            set.add_rdata(RData::AAAA(AAAA(*ip)));
        }
        record_sets.push(Arc::new(set));
    }

    if record_sets.is_empty() {
        return AuthLookup::from(LookupRecords::default());
    }

    AuthLookup::from(LookupRecords::many(lookup_options, record_sets))
}

fn block_lookup_records(
    name: &LowerName,
    rtype: RecordType,
    lookup_options: LookupOptions,
    blocking_ipv4: Ipv4Addr,
    blocking_ipv6: Ipv6Addr,
    ttl: u32,
) -> AuthLookup {
    let fqdn_name = Name::from(name);
    let mut record_sets = Vec::new();

    if matches!(rtype, RecordType::A | RecordType::ANY) {
        let mut set = RecordSet::with_ttl(fqdn_name.clone(), RecordType::A, ttl);
        set.add_rdata(RData::A(A(blocking_ipv4)));
        record_sets.push(Arc::new(set));
    }

    if matches!(rtype, RecordType::AAAA | RecordType::ANY) {
        let mut set = RecordSet::with_ttl(fqdn_name, RecordType::AAAA, ttl);
        set.add_rdata(RData::AAAA(AAAA(blocking_ipv6)));
        record_sets.push(Arc::new(set));
    }

    if record_sets.is_empty() {
        return AuthLookup::from(LookupRecords::default());
    }

    AuthLookup::from(LookupRecords::many(lookup_options, record_sets))
}

fn normalized_query_name(name: &LowerName) -> String {
    Name::from(name)
        .to_ascii()
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

fn record_ip(record: &Record) -> Option<IpAddr> {
    match record.data() {
        RData::A(A(ipv4)) => Some(IpAddr::V4(*ipv4)),
        RData::AAAA(AAAA(ipv6)) => Some(IpAddr::V6(*ipv6)),
        _ => None,
    }
}

fn record_cname(record: &Record) -> Option<String> {
    match record.data() {
        RData::CNAME(CNAME(target)) => Some(
            target
                .to_ascii()
                .trim_end_matches('.')
                .to_ascii_lowercase(),
        ),
        _ => None,
    }
}

fn suffix_match(domain: &str, suffix: &str) -> bool {
    domain == suffix
        || domain
            .strip_suffix(suffix)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

fn rule_allows_type(rule: &CompiledMatchRule, rtype: RecordType) -> bool {
    match &rule.dnstypes {
        None => true,
        Some(TypeConstraint::Include(types)) => types.contains(&rtype),
        Some(TypeConstraint::Exclude(types)) => !types.contains(&rtype),
    }
}

fn complex_rule_matches(rule: &CompiledMatchRule, domain: &str, rtype: RecordType) -> bool {
    if !rule_allows_type(rule, rtype) {
        return false;
    }
    if rule
        .denyallow
        .iter()
        .any(|pattern| domain_pattern_matches(pattern, domain))
    {
        return false;
    }
    match &rule.matcher {
        super::rules::Matcher::Regex(regex) => regex.is_match(domain),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suffix_matching_requires_label_boundary() {
        assert!(suffix_match("ads.example.com", "example.com"));
        assert!(suffix_match("example.com", "example.com"));
        assert!(!suffix_match("badexample.com", "example.com"));
    }

    #[test]
    fn extracts_record_ip() {
        let record = Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            60,
            RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
        );
        assert_eq!(record_ip(&record), Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
    }
}
