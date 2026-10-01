use crate::{
    Error,
    common::{
        errors::new_io_error,
        http::{ClashHTTPClientExt, DEFAULT_USER_AGENT, HttpClient},
    },
};
use async_recursion::async_recursion;
use futures::StreamExt;
use http_body_util::{BodyDataStream, Empty};
use rand::distr::uniform::{SampleRange, SampleUniform};
use sha2::Digest;
use std::{
    collections::HashMap,
    fmt::Write,
    num::ParseIntError,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
use tracing::debug;

pub fn rand_range<T, R>(range: R) -> T
where
    T: SampleUniform,
    R: SampleRange<T>,
{
    rand::random_range(range)
}

pub fn rand_fill(buf: &mut [u8]) {
    rand::fill(buf)
}

#[allow(dead_code)]
pub fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

pub fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{b:02x}").unwrap();
    }
    s
}

pub fn sha256(bytes: &[u8]) -> Vec<u8> {
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    hasher.finalize().to_vec()
}

pub fn md5(bytes: &[u8]) -> Vec<u8> {
    let mut hasher = md5::Md5::new();
    hasher.update(bytes);
    hasher.finalize().to_vec()
}

pub fn md5_str(bytes: &[u8]) -> String {
    let mut hasher = md5::Md5::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

pub fn current_timestamp_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Default value true for bool on serde
/// use this if you don't want do deal with Option<bool>
/// Use Default::default() for false
pub fn default_bool_true() -> bool {
    true
}

pub fn serialize_duration<S>(
    duration: &std::time::Duration,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let millis = duration.as_millis();
    let capped = u16::try_from(millis).unwrap_or(u16::MAX);
    serializer.serialize_u16(capped)
}

pub async fn download<P>(
    url: &str,
    path: P,
    http_client: &HttpClient,
) -> anyhow::Result<()>
where
    P: AsRef<Path> + std::marker::Send,
{
    let ext = {
        let fragments = url.rsplit_once('#').map(|x| x.1).unwrap_or_default();
        let pairs = fragments.split('&').filter_map(|x| {
            let mut kv = x.splitn(2, '=');
            if let (Some(k), Some(v)) = (kv.next(), kv.next()) {
                Some((k.to_owned(), v.to_owned()))
            } else {
                None
            }
        });

        let params: HashMap<String, String> = pairs.collect();
        ClashHTTPClientExt {
            outbound: params.get("_clash_outbound").cloned(),
        }
    };

    download_with_ext(url, path, http_client, ext, 10).await
}

#[async_recursion]
async fn download_with_ext<P>(
    url: &str,
    path: P,
    http_client: &HttpClient,
    req_ext: ClashHTTPClientExt,
    max_redirects: usize,
) -> anyhow::Result<()>
where
    P: AsRef<Path> + std::marker::Send,
{
    debug!("downloading data from {url}");
    // Strip URI fragment before parsing: HTTP clients must not include
    // fragments in request-target URIs (RFC 7230 §5.3), and hyper::Uri
    // rejects them.
    let url_no_fragment = url.rsplit_once('#').map(|x| x.0).unwrap_or(url);
    let url = url_no_fragment.parse::<hyper::Uri>()?;
    let mut req = http::Request::builder()
        .header(http::header::USER_AGENT, DEFAULT_USER_AGENT)
        .uri(&url)
        .method(http::Method::GET)
        .body(Empty::<bytes::Bytes>::new())?;
    req.extensions_mut().insert(req_ext.clone());

    let res = http_client.request(req).await?;

    if res.status().is_redirection() {
        let redirected = res
            .headers()
            .get("Location")
            .ok_or(new_io_error(
                format!("failed to download from {url}").as_str(),
            ))?
            .to_str()?;
        debug!("redirected to {redirected}");
        if max_redirects == 0 {
            return Err(Error::InvalidConfig(
                "too many redirects, max redirects reached".to_string(),
            )
            .into());
        }
        return download_with_ext(
            redirected,
            path,
            http_client,
            req_ext,
            max_redirects - 1,
        )
        .await;
    }

    if !res.status().is_success() {
        return Err(Error::InvalidConfig(format!(
            "data download failed: {}",
            res.status()
        ))
        .into());
    }

    debug!("downloading data to {}", path.as_ref().to_string_lossy());
    // Write to a temp file in the same directory, then atomically rename so
    // concurrent readers (e.g. parallel CI tests) never see a partial file.
    let parent = path.as_ref().parent().unwrap_or(Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    let mut stream = BodyDataStream::new(res.into_body());
    while let Some(chunk) = stream.next().await {
        std::io::Write::write_all(&mut tmp, &chunk?)?;
    }
    // persist() is an atomic rename on POSIX; on Windows it may fail if the
    // destination is held open by another handle, so fall back to copy+delete.
    if let Err(e) = tmp.persist(path.as_ref()) {
        std::fs::copy(e.file.path(), path.as_ref())?;
    }

    Ok(())
}
