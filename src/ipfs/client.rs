//! IPFS HTTP API client for media upload and retrieval.
//!
//! Interfaces with a local Kubo node via the HTTP API (spec 04-ipfs.md).
//! Supports upload (with pinning), retrieval by CID, and pin management.

use std::time::Duration;

use anyhow::{Context, Result};
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
    pub async fn get(&self, cid: &str) -> Result<Vec<u8>> {
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

        Ok(bytes.to_vec())
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
