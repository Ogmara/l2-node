//! IPFS HTTP API client for media upload and retrieval.
//!
//! Interfaces with a local Kubo node via the HTTP API (spec 04-ipfs.md).
//! Supports upload (with pinning), retrieval by CID, and pin management.

use std::time::Duration;

use anyhow::{Context, Result};
use bytes::Bytes;
use serde::Deserialize;
use tracing::{debug, info, warn};

use crate::config::IpfsConfig;

/// Allowed MIME types for media uploads (spec 04-ipfs.md section 3.1).
const ALLOWED_MIME_PREFIXES: &[&str] = &[
    "image/",
    "video/",
    "audio/",
    "application/pdf",
    "text/plain",
];

/// Maximum bytes to read from a stat-shaped IPFS response (files/stat,
/// object/stat). Real Kubo responses are ~200 bytes JSON; this is
/// generous headroom while still protecting against a hostile or
/// corrupted daemon streaming gigabytes into our lightweight probes.
const MAX_STAT_RESPONSE_BYTES: usize = 8 * 1024;

/// Read a `reqwest::Response` body into a `Vec<u8>` with an
/// INCREMENTAL size cap. The cap is enforced as bytes accumulate
/// rather than after the full body is buffered — important because
/// a `Content-Length`-less chunked-transfer response can otherwise
/// stream unbounded data into the post-buffer length check before
/// any limit fires.
///
/// Used by the stat-shaped endpoints (`get_size`, `exists_local`)
/// where we always expect a tiny response and any large body is a
/// signal that something is wrong with the upstream Kubo.
///
/// Returns `Err` if the response declares a `Content-Length` larger
/// than `max_bytes`, OR if accumulated bytes exceed `max_bytes`
/// during the streamed read, OR on transport-level read failures.
async fn read_body_capped(
    resp: reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>> {
    // Cheap pre-check: reject early when the server declares an
    // oversize Content-Length. Saves the streaming round-trip when
    // the server is honest about its body size.
    if let Some(declared) = resp.content_length() {
        if declared > max_bytes as u64 {
            anyhow::bail!(
                "response too large: declared {} bytes (max {})",
                declared,
                max_bytes
            );
        }
    }
    let mut resp = resp;
    let mut buf: Vec<u8> = Vec::with_capacity(max_bytes.min(8 * 1024));
    while let Some(chunk) = resp
        .chunk()
        .await
        .context("reading body chunk")?
    {
        if buf.len() + chunk.len() > max_bytes {
            anyhow::bail!(
                "response exceeded {} bytes during streamed read",
                max_bytes
            );
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// IPFS client for the Ogmara L2 node.
#[derive(Clone)]
pub struct IpfsClient {
    /// Base URL for the IPFS HTTP API (e.g., "http://127.0.0.1:5001").
    api_url: String,
    /// Base URL for the IPFS gateway (e.g., "http://127.0.0.1:8080").
    gateway_url: String,
    /// Maximum upload size in bytes.
    max_upload_bytes: u64,
    /// HTTP client.
    http: reqwest::Client,
}

/// Response from IPFS `add` endpoint.
#[derive(Debug, Deserialize)]
struct IpfsAddResponse {
    #[serde(rename = "Hash")]
    hash: String,
    #[serde(rename = "Size")]
    size: String,
    #[serde(rename = "Name")]
    name: String,
}

/// Result of a successful media upload.
#[derive(Debug, Clone)]
pub struct UploadResult {
    /// IPFS CID (CIDv1 base32).
    pub cid: String,
    /// File size in bytes.
    pub size: u64,
    /// Detected MIME type.
    pub mime_type: String,
    /// Original filename.
    pub filename: Option<String>,
}

impl IpfsClient {
    /// Create a new IPFS client from configuration.
    pub fn new(config: &IpfsConfig) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(120)) // uploads can be slow
            .build()
            .context("creating IPFS HTTP client")?;

        Ok(Self {
            api_url: config.api_url.clone(),
            gateway_url: config.gateway_url.clone(),
            max_upload_bytes: config.max_upload_size_mb * 1024 * 1024,
            http,
        })
    }

    /// Check if the IPFS node is reachable.
    pub async fn health_check(&self) -> Result<bool> {
        let url = format!("{}/api/v0/id", self.api_url);
        match self.http.post(&url).send().await {
            Ok(resp) => Ok(resp.status().is_success()),
            Err(_) => Ok(false),
        }
    }

    /// Upload a file to IPFS with automatic pinning.
    ///
    /// Validates file size and MIME type before uploading.
    pub async fn upload(
        &self,
        data: Vec<u8>,
        filename: Option<String>,
        mime_type: &str,
    ) -> Result<UploadResult> {
        // Validate file size
        if data.len() as u64 > self.max_upload_bytes {
            anyhow::bail!(
                "file too large: {} bytes (max: {} bytes)",
                data.len(),
                self.max_upload_bytes
            );
        }

        // Validate MIME type
        if !is_allowed_mime(mime_type) {
            anyhow::bail!("MIME type not allowed: {}", mime_type);
        }

        let size = data.len() as u64;

        // Upload to IPFS with pinning
        let url = format!("{}/api/v0/add?pin=true&cid-version=1", self.api_url);

        let part = reqwest::multipart::Part::bytes(data)
            .file_name(filename.clone().unwrap_or_else(|| "upload".to_string()));

        let form = reqwest::multipart::Form::new().part("file", part);

        let resp: IpfsAddResponse = self
            .http
            .post(&url)
            .multipart(form)
            .send()
            .await
            .context("uploading to IPFS")?
            .json()
            .await
            .context("parsing IPFS add response")?;

        info!(cid = %resp.hash, size, "File uploaded to IPFS");

        Ok(UploadResult {
            cid: resp.hash,
            size,
            mime_type: mime_type.to_string(),
            filename,
        })
    }

    /// Retrieve content from IPFS by CID.
    ///
    /// Returns the raw bytes, bounded by `max_upload_bytes` to prevent
    /// memory exhaustion. The IPFS node will fetch from the network
    /// if the content is not cached locally.
    pub async fn get(&self, cid: &str) -> Result<Bytes> {
        validate_cid(cid)?;

        let url = format!("{}/api/v0/cat?arg={}", self.api_url, cid);

        let resp = self
            .http
            .post(&url)
            .send()
            .await
            .context("fetching from IPFS")?;

        // Check Content-Length if available to reject oversized responses early
        if let Some(len) = resp.content_length() {
            if len > self.max_upload_bytes {
                anyhow::bail!(
                    "IPFS content too large: {} bytes (max: {})",
                    len,
                    self.max_upload_bytes
                );
            }
        }

        let bytes = resp
            .bytes()
            .await
            .context("reading IPFS response bytes")?;

        if bytes.len() as u64 > self.max_upload_bytes {
            anyhow::bail!(
                "IPFS content too large: {} bytes (max: {})",
                bytes.len(),
                self.max_upload_bytes
            );
        }

        debug!(cid = %cid, bytes = bytes.len(), "Retrieved from IPFS");

        // Return reference-counted `Bytes` instead of `Vec<u8>` so that
        // callers (chiefly the media handler's LRU cache) can clone and
        // slice the body without copying the underlying buffer.
        Ok(bytes)
    }

    /// Fetch a byte range of an IPFS object without loading the whole
    /// blob into memory. Used by the media handler when the requested
    /// range is smaller than the cache threshold (large videos), so we
    /// never buffer megabytes we won't serve.
    ///
    /// Uses Kubo's `/api/v0/cat?offset=&length=` parameters. Both are
    /// in bytes; `length` capped server-side at the file size minus
    /// `offset`. Returns the raw range as `Bytes` (zero-copy share).
    pub async fn get_range(&self, cid: &str, offset: u64, length: u64) -> Result<Bytes> {
        validate_cid(cid)?;

        // Refuse ranges larger than max_upload_bytes — same defense as
        // `get()` but applied to the requested slice. An attacker who
        // requests `length = u64::MAX` should not be able to coerce us
        // into a multi-GB allocation; cap it here.
        if length > self.max_upload_bytes {
            anyhow::bail!(
                "IPFS range too large: {} bytes (max: {})",
                length,
                self.max_upload_bytes
            );
        }

        let url = format!(
            "{}/api/v0/cat?arg={}&offset={}&length={}",
            self.api_url, cid, offset, length
        );

        let resp = self
            .http
            .post(&url)
            .send()
            .await
            .context("fetching IPFS range")?;

        if let Some(len) = resp.content_length() {
            if len > self.max_upload_bytes {
                anyhow::bail!(
                    "IPFS range response too large: {} bytes (max: {})",
                    len,
                    self.max_upload_bytes
                );
            }
        }

        let bytes = resp
            .bytes()
            .await
            .context("reading IPFS range response")?;

        if bytes.len() as u64 > self.max_upload_bytes {
            anyhow::bail!(
                "IPFS range response too large: {} bytes (max: {})",
                bytes.len(),
                self.max_upload_bytes
            );
        }

        debug!(
            cid = %cid,
            offset = offset,
            length = length,
            actual = bytes.len(),
            "Retrieved IPFS range"
        );

        Ok(bytes)
    }

    /// Get the actual file size of an IPFS object in bytes without
    /// fetching its content. Used by the media handler for Range
    /// bounds validation and `Content-Range: bytes start-end/<total>`.
    ///
    /// Uses Kubo's `/api/v0/files/stat?arg=/ipfs/<cid>` endpoint and
    /// returns the `Size` field — the ACTUAL file size, not the
    /// `CumulativeSize` from `object/stat` (which over-counts DAG
    /// framing on chunked uploads and produces wrong `Content-Range`
    /// totals).
    ///
    /// The `&offline=true` parameter restricts the lookup to the local
    /// blockstore. Without it, an attacker could spam queries for
    /// random CIDs and force the Kubo daemon into expensive DHT walks
    /// (audit security finding W-3). Callers that DO want network
    /// resolution (e.g. unconditional gateway-style fetch) use
    /// `get()` directly, which falls back to the network as needed.
    pub async fn get_size(&self, cid: &str) -> Result<u64> {
        validate_cid(cid)?;

        let url = format!(
            "{}/api/v0/files/stat?arg=/ipfs/{}&offline=true",
            self.api_url, cid
        );

        let resp = self
            .http
            .post(&url)
            .send()
            .await
            .context("fetching IPFS files/stat")?;

        // Stream-read with an INCREMENTAL cap. The v0.39 code buffered
        // the full body and then checked size — fine when Kubo declares
        // Content-Length, but a chunked-transfer response with no
        // Content-Length could stream gigabytes before the post-buffer
        // check fired (audit security warning W-2). `read_body_capped`
        // aborts the read as soon as accumulated bytes exceed the cap.
        let body = read_body_capped(resp, MAX_STAT_RESPONSE_BYTES)
            .await
            .context("reading IPFS stat body")?;

        let val: serde_json::Value = serde_json::from_slice(&body)
            .context("parsing IPFS files/stat response")?;

        // `Size` is the actual file size in bytes (not `CumulativeSize`).
        let size = val["Size"]
            .as_u64()
            .context("files/stat returned no Size")?;

        Ok(size)
    }

    /// Check whether the given CID is present in the LOCAL blockstore
    /// without triggering a DHT walk or remote fetch. Used by the
    /// media handler's `If-None-Match` 304 short-circuit so an
    /// attacker can't weaponize the existence probe into a network-
    /// amplification vector.
    ///
    /// Returns `Ok(true)` when the object resolves locally,
    /// `Ok(false)` when it doesn't, and `Err` only on transport-level
    /// failures (Kubo unreachable, etc.). A "not found" response is
    /// not treated as an error — it's the expected answer for an
    /// unknown CID.
    ///
    /// **Behavior across Kubo versions** (v0.40 audit hardening):
    /// Kubo has historically signalled "not local" in two ways:
    ///   * HTTP 500 + error JSON  (current convention)
    ///   * HTTP 200 + `{"Error": "..."}` body (older builds, and a
    ///     plausible future regression — Kubo's HTTP API has flipped
    ///     between these before)
    /// We treat BOTH as "not local" to make the probe stable across
    /// Kubo upgrades. A successful response with no `Error` key is
    /// the only path that reports the CID as local.
    pub async fn exists_local(&self, cid: &str) -> Result<bool> {
        validate_cid(cid)?;

        let url = format!(
            "{}/api/v0/files/stat?arg=/ipfs/{}&offline=true",
            self.api_url, cid
        );

        let resp = self
            .http
            .post(&url)
            .send()
            .await
            .context("checking IPFS local existence")?;

        // Non-success status → not local. The most common case is
        // Kubo's "block not found locally" returned as 500.
        if !resp.status().is_success() {
            return Ok(false);
        }

        // 2xx body — parse to disambiguate between a real
        // local-stat response and the older `200 + {"Error":...}`
        // convention. Bounded INCREMENTAL read protects against a
        // hostile chunked-transfer body that could otherwise stream
        // gigabytes before a post-buffer check (audit security W-2).
        let body = match read_body_capped(resp, MAX_STAT_RESPONSE_BYTES).await {
            Ok(b) => b,
            Err(e) => {
                // Body too large or read error → conservative answer.
                // Logging at debug — this is expected in some failure
                // modes and isn't an action item for the operator.
                debug!(cid = %cid, error = %e, "exists_local body read failed");
                return Ok(false);
            }
        };
        let val: serde_json::Value =
            match serde_json::from_slice(&body) {
                Ok(v) => v,
                Err(_) => {
                    // Unparseable success body — Kubo is misbehaving.
                    // Conservative answer: not local.
                    return Ok(false);
                }
            };
        // Treat any `Error` key (string or nested object) as
        // "not local", regardless of HTTP status.
        if !val["Error"].is_null() {
            return Ok(false);
        }
        Ok(true)
    }

    /// Pin a CID on the local IPFS node.
    pub async fn pin(&self, cid: &str) -> Result<()> {
        validate_cid(cid)?;
        let url = format!("{}/api/v0/pin/add?arg={}", self.api_url, cid);

        self.http
            .post(&url)
            .send()
            .await
            .context("pinning on IPFS")?;

        debug!(cid = %cid, "Pinned on IPFS");
        Ok(())
    }

    /// Unpin a CID from the local IPFS node.
    pub async fn unpin(&self, cid: &str) -> Result<()> {
        validate_cid(cid)?;
        let url = format!("{}/api/v0/pin/rm?arg={}", self.api_url, cid);

        self.http
            .post(&url)
            .send()
            .await
            .context("unpinning from IPFS")?;

        debug!(cid = %cid, "Unpinned from IPFS");
        Ok(())
    }

    /// Get IPFS repo statistics (total size and pinned object count).
    ///
    /// Used by the metrics collector for dashboard stats (spec 10-dashboard.md §6.1).
    pub async fn repo_stat(&self) -> Result<(u64, u64)> {
        // Get repo size
        let url = format!("{}/api/v0/repo/stat", self.api_url);
        let resp: serde_json::Value = self
            .http
            .post(&url)
            .send()
            .await
            .context("fetching IPFS repo stat")?
            .json()
            .await
            .context("parsing IPFS repo stat response")?;

        let repo_size = resp["RepoSize"].as_u64().unwrap_or(0);
        let num_objects = resp["NumObjects"].as_u64().unwrap_or(0);

        Ok((repo_size, num_objects))
    }

    /// Get the gateway URL for a CID (for serving to clients).
    pub fn gateway_url_for(&self, cid: &str) -> Result<String> {
        validate_cid(cid)?;
        Ok(format!("{}/ipfs/{}", self.gateway_url, cid))
    }
}

/// Check if a MIME type is in the allowlist.
fn is_allowed_mime(mime_type: &str) -> bool {
    ALLOWED_MIME_PREFIXES
        .iter()
        .any(|prefix| mime_type.starts_with(prefix))
}

/// Validate a CID string format to prevent injection.
///
/// Accepts CIDv0 (Qm...) and CIDv1 (bafy...) formats.
/// Only allows alphanumeric characters and safe base-encoding chars.
fn validate_cid(cid: &str) -> Result<()> {
    if cid.is_empty() || cid.len() > 128 {
        anyhow::bail!("invalid CID length: {}", cid.len());
    }
    // CIDs are base-encoded and should only contain safe characters
    for ch in cid.chars() {
        if !ch.is_ascii_alphanumeric() {
            anyhow::bail!("invalid character in CID: {:?}", ch);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allowed_mime_types() {
        assert!(is_allowed_mime("image/png"));
        assert!(is_allowed_mime("image/jpeg"));
        assert!(is_allowed_mime("video/mp4"));
        assert!(is_allowed_mime("audio/mpeg"));
        assert!(is_allowed_mime("application/pdf"));
        assert!(is_allowed_mime("text/plain"));

        assert!(!is_allowed_mime("application/javascript"));
        assert!(!is_allowed_mime("application/x-executable"));
        assert!(!is_allowed_mime("application/zip"));
        assert!(!is_allowed_mime("text/html"));
    }
}
