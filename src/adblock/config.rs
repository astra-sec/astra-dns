use std::net::{Ipv4Addr, Ipv6Addr};

use serde::Deserialize;

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FilterConfig {
    pub enabled: bool,
    pub url: String,
    pub name: Option<String>,
    pub id: Option<u64>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum BlockingMode {
    #[default]
    Default,
    Nxdomain,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FilteringConfig {
    pub blocking_ipv4: Option<Ipv4Addr>,
    pub blocking_ipv6: Option<Ipv6Addr>,
    pub blocking_mode: BlockingMode,
    pub rewrites: Vec<RewriteConfig>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RewriteConfig {
    pub domain: Option<String>,
    pub ip: Vec<String>,
    pub cname: Vec<String>,
    pub answer: RewriteAnswerConfig,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(untagged)]
pub enum RewriteAnswerConfig {
    #[default]
    Empty,
    Single(String),
    Multiple(Vec<String>),
}

impl RewriteAnswerConfig {
    pub fn values(&self) -> &[String] {
        match self {
            Self::Empty => &[],
            Self::Single(value) => std::slice::from_ref(value),
            Self::Multiple(values) => values.as_slice(),
        }
    }
}
