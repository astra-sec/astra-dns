use std::{
    collections::hash_map::DefaultHasher,
    fs,
    hash::{Hash, Hasher},
    path::{Path, PathBuf},
    time::Duration,
};

use reqwest::Client;
use tracing::{info, warn};

use super::FilterConfig;

const DEFAULT_FILTER_FETCH_TIMEOUT_SECS: u64 = 15;

#[derive(Clone, Debug)]
pub struct FilterFetchOptions {
    cache_dir: PathBuf,
    timeout: Duration,
}

impl FilterFetchOptions {
    pub fn for_config_path(config_path: &Path) -> Self {
        let cache_root = config_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("filters-cache");

        Self {
            cache_dir: cache_root,
            timeout: Duration::from_secs(DEFAULT_FILTER_FETCH_TIMEOUT_SECS),
        }
    }

    fn cache_path_for(&self, filter: &FilterConfig) -> PathBuf {
        let cache_key = filter.id.map(|id| id.to_string()).unwrap_or_else(|| {
            let mut hasher = DefaultHasher::new();
            filter.url.hash(&mut hasher);
            format!("{:016x}", hasher.finish())
        });

        self.cache_dir.join(format!("{cache_key}.txt"))
    }
}

pub async fn fetch_filter(
    filter: &FilterConfig,
    options: &FilterFetchOptions,
) -> Result<String, String> {
    let cache_path = options.cache_path_for(filter);

    match fetch_filter_from_network(filter, options.timeout).await {
        Ok(contents) => {
            persist_cached_filter(&cache_path, &contents)?;
            info!(
                "downloaded remote filter {} into {:?}",
                filter.url, cache_path
            );
            Ok(contents)
        }
        Err(err) => match fs::read_to_string(&cache_path) {
            Ok(contents) => {
                warn!(
                    "failed to download filter {}, using cached copy from {:?}: {}",
                    filter.url, cache_path, err
                );
                Ok(contents)
            }
            Err(_) => Err(format!(
                "failed to download filter {} and no cached copy was available: {}",
                filter.url, err
            )),
        },
    }
}

async fn fetch_filter_from_network(
    filter: &FilterConfig,
    timeout: Duration,
) -> Result<String, String> {
    let client = Client::builder()
        .connect_timeout(timeout)
        .timeout(timeout)
        .build()
        .map_err(|err| format!("failed to build HTTP client for filters: {err}"))?;

    let response = client
        .get(&filter.url)
        .send()
        .await
        .map_err(|err| format!("failed to download filter {}: {err}", filter.url))?;

    let response = response.error_for_status().map_err(|err| {
        format!(
            "filter download returned an error for {}: {err}",
            filter.url
        )
    })?;

    let bytes = response
        .bytes()
        .await
        .map_err(|err| format!("failed to read filter body from {}: {err}", filter.url))?;

    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn persist_cached_filter(cache_path: &Path, contents: &str) -> Result<(), String> {
    if let Some(parent) = cache_path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "failed to create filter cache directory {:?}: {err}",
                parent
            )
        })?;
    }

    fs::write(cache_path, contents)
        .map_err(|err| format!("failed to write filter cache {:?}: {err}", cache_path))
}
