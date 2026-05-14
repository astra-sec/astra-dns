use reqwest::Client;

use super::FilterConfig;

pub async fn fetch_filter(filter: &FilterConfig) -> Result<String, String> {
    let client = Client::builder()
        .build()
        .map_err(|err| format!("failed to build HTTP client for filters: {err}"))?;

    let response = client
        .get(&filter.url)
        .send()
        .await
        .map_err(|err| format!("failed to download filter {}: {err}", filter.url))?;

    let response = response
        .error_for_status()
        .map_err(|err| format!("filter download returned an error for {}: {err}", filter.url))?;

    response
        .text()
        .await
        .map_err(|err| format!("failed to read filter body from {}: {err}", filter.url))
}
