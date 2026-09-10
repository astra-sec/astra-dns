use std::{collections::HashSet, hint::black_box, time::Duration};

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

const PRODUCTION_RULE_COUNT: usize = 215_127;

struct LinearScanIndex {
    exact: HashSet<String>,
    subdomains: HashSet<String>,
}

impl LinearScanIndex {
    fn from_subdomain_rules(rules: &[String]) -> Self {
        Self {
            exact: rules.iter().cloned().collect(),
            subdomains: rules.iter().cloned().collect(),
        }
    }

    fn matches(&self, domain: &str) -> bool {
        self.exact.contains(domain)
            || self
                .subdomains
                .iter()
                .any(|suffix| suffix_match(domain, suffix))
    }
}

struct ParentLookupIndex {
    exact: HashSet<String>,
    subdomains: HashSet<String>,
}

impl ParentLookupIndex {
    fn from_subdomain_rules(rules: &[String]) -> Self {
        Self {
            exact: rules.iter().cloned().collect(),
            subdomains: rules.iter().cloned().collect(),
        }
    }

    fn matches(&self, domain: &str) -> bool {
        if self.exact.contains(domain) {
            return true;
        }

        let mut candidate = domain;
        loop {
            if self.subdomains.contains(candidate) {
                return true;
            }

            let Some(dot) = candidate.find('.') else {
                return false;
            };
            candidate = &candidate[dot + 1..];
        }
    }
}

fn suffix_match(domain: &str, suffix: &str) -> bool {
    domain == suffix
        || domain
            .strip_suffix(suffix)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

fn generate_rules(count: usize) -> Vec<String> {
    (0..count)
        .map(|index| format!("tracker-{index}.ads.example"))
        .collect()
}

fn benchmark_domain_matching(c: &mut Criterion) {
    for count in [1_000, 10_000, PRODUCTION_RULE_COUNT] {
        let rules = generate_rules(count);
        let linear_scan = LinearScanIndex::from_subdomain_rules(&rules);
        let parent_lookup = ParentLookupIndex::from_subdomain_rules(&rules);
        let exact = rules[count / 2].clone();
        let subdomains: Vec<String> = (1..=16)
            .map(|part| format!("cdn.{}", rules[count * part / 17]))
            .collect();
        let miss = "gist.github.com";

        for query in [miss, exact.as_str()] {
            assert_eq!(linear_scan.matches(query), parent_lookup.matches(query));
        }
        for query in &subdomains {
            assert_eq!(linear_scan.matches(query), parent_lookup.matches(query));
        }

        let mut group = c.benchmark_group(format!("domain_matching/{count}"));
        group.throughput(Throughput::Elements(1));
        group.warm_up_time(Duration::from_millis(500));
        group.measurement_time(Duration::from_secs(2));
        group.sample_size(30);

        for (case, query) in [("miss", miss), ("exact", exact.as_str())] {
            group.bench_with_input(BenchmarkId::new("linear_scan", case), query, |b, query| {
                b.iter(|| linear_scan.matches(black_box(query)));
            });
            group.bench_with_input(
                BenchmarkId::new("parent_lookup", case),
                query,
                |b, query| {
                    b.iter(|| parent_lookup.matches(black_box(query)));
                },
            );
        }

        group.bench_function(BenchmarkId::new("linear_scan", "subdomain"), |b| {
            let mut index = 0usize;
            b.iter(|| {
                let query = &subdomains[index & 15];
                index = index.wrapping_add(1);
                linear_scan.matches(black_box(query))
            });
        });
        group.bench_function(BenchmarkId::new("parent_lookup", "subdomain"), |b| {
            let mut index = 0usize;
            b.iter(|| {
                let query = &subdomains[index & 15];
                index = index.wrapping_add(1);
                parent_lookup.matches(black_box(query))
            });
        });

        group.finish();
    }
}

criterion_group!(benches, benchmark_domain_matching);
criterion_main!(benches);
