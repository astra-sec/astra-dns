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

const DEFAULT_FILTER_CONNECT_TIMEOUT_SECS: u64 = 10;
const DEFAULT_FILTER_READ_TIMEOUT_SECS: u64 = 30;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FilterFetchMode {
    CacheFirst,
    Refresh,
}

#[derive(Clone, Debug)]
pub struct FilterFetchOptions {
    cache_dir: PathBuf,
    connect_timeout: Duration,
    read_timeout: Duration,
}

impl FilterFetchOptions {
    pub fn new(cache_dir: PathBuf) -> Self {
        Self {
            cache_dir,
            connect_timeout: Duration::from_secs(DEFAULT_FILTER_CONNECT_TIMEOUT_SECS),
            read_timeout: Duration::from_secs(DEFAULT_FILTER_READ_TIMEOUT_SECS),
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
    mode: FilterFetchMode,
) -> Result<String, String> {
    let cache_path = options.cache_path_for(filter);

    if mode == FilterFetchMode::CacheFirst
        && let Ok(contents) = fs::read_to_string(&cache_path)
    {
        info!(
            "loaded remote filter {} from cache {:?}",
            filter.url, cache_path
        );
        return Ok(contents);
    }

    match download_filter_body(filter, options.connect_timeout, options.read_timeout).await {
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

fn persist_cached_filter(cache_path: &Path, contents: &str) -> Result<(), String> {
    if matches!(fs::read_to_string(cache_path), Ok(existing) if existing == contents) {
        return Ok(());
    }

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

async fn download_filter_body(
    filter: &FilterConfig,
    connect_timeout: Duration,
    read_timeout: Duration,
) -> Result<String, String> {
    // Remote lists can be several megabytes on small routers, so use a short
    // connect timeout but avoid a hard total request deadline for the body.
    let client = Client::builder()
        .connect_timeout(connect_timeout)
        .read_timeout(read_timeout)
        .build()
        .map_err(|err| format!("failed to build HTTP client for filters: {err}"))?;

    let response = client
        .get(&filter.url)
        .send()
        .await
        .map_err(|err| format!("failed to download filter {}: {err:?}", filter.url))?;

    let response = response.error_for_status().map_err(|err| {
        format!(
            "filter download returned an error for {}: {err:?}",
            filter.url
        )
    })?;

    let bytes = response
        .bytes()
        .await
        .map_err(|err| format!("failed to read filter body from {}: {err:?}", filter.url))?;

    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        io::ErrorKind,
        net::TcpListener,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::*;

    #[tokio::test]
    async fn cache_first_does_not_contact_remote_server() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("test listener should bind");
        listener
            .set_nonblocking(true)
            .expect("test listener should be nonblocking");
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let cache_dir = std::env::temp_dir().join(format!(
            "astra-dns-filter-cache-{}-{unique}",
            std::process::id()
        ));
        let options = FilterFetchOptions::new(cache_dir.clone());
        let filter = FilterConfig {
            enabled: true,
            url: format!("http://{}/filter.txt", listener.local_addr().unwrap()),
            name: None,
            id: Some(7),
        };
        let cache_path = options.cache_path_for(&filter);
        fs::create_dir_all(&cache_dir).expect("cache directory should be created");
        fs::write(&cache_path, "cached rule\n").expect("cached filter should be written");

        let contents = fetch_filter(&filter, &options, FilterFetchMode::CacheFirst)
            .await
            .expect("cached filter should load");

        assert_eq!(contents, "cached rule\n");
        assert!(matches!(listener.accept(), Err(err) if err.kind() == ErrorKind::WouldBlock));
        fs::remove_dir_all(cache_dir).expect("test cache should be removed");
    }
}
