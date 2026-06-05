//! Device-to-wallet identity resolver with in-memory caching.
//!
//! Provides fast device_address → wallet_address resolution using a DashMap
//! cache backed by RocksDB. Cache misses read through to the DEVICE_WALLET_MAP
//! column family and populate the cache for subsequent lookups.

use anyhow::Result;
use dashmap::DashMap;
use tracing::warn;

use super::rocks::{DeviceClaim, Storage};

/// Maximum number of cached device→wallet mappings.
/// Only positive mappings (registered devices) are cached. Negative lookups
/// (no mapping) are not cached to prevent memory exhaustion from random addresses.
const MAX_CACHE_ENTRIES: usize = 50_000;

/// Resolves device addresses to wallet addresses with caching.
///
/// The resolver maintains an in-memory cache (DashMap) for O(1) lookups
/// on hot paths (auth middleware, message routing). Cache entries are
/// populated on first lookup and invalidated on registration/revocation.
///
/// Only positive results (device has a wallet mapping) are cached. Negative
/// results read through to RocksDB every time, which prevents cache exhaustion
/// from queries with random/non-existent device addresses.
///
/// Fallback behavior: if no mapping exists, the device address IS the
/// wallet address (built-in wallet mode). The `resolve` method returns
/// the device address itself in this case — callers never need to handle
/// `None`.
#[derive(Clone)]
pub struct IdentityResolver {
    /// In-memory cache: device_address → wallet_address (positive mappings only).
    cache: DashMap<String, String>,
    storage: Storage,
}

impl IdentityResolver {
    /// Create a new identity resolver backed by the given storage.
    pub fn new(storage: Storage) -> Self {
        Self {
            cache: DashMap::new(),
            storage,
        }
    }

    /// Resolve a device address to its wallet address.
    ///
    /// Returns the wallet address if a mapping exists, or the device
    /// address itself as fallback (built-in wallet mode).
    ///
    /// Positive results are cached for fast repeated lookups.
    pub fn resolve(&self, device_address: &str) -> Result<String> {
        // Fast path: check cache (only contains positive mappings)
        if let Some(entry) = self.cache.get(device_address) {
            return Ok(entry.value().clone());
        }

        // Slow path: read through to RocksDB
        let wallet = self.storage.resolve_wallet(device_address)?;

        match wallet {
            Some(wallet_addr) => {
                // Cache positive result (bounded by MAX_CACHE_ENTRIES)
                if self.cache.len() < MAX_CACHE_ENTRIES {
                    self.cache.insert(device_address.to_string(), wallet_addr.clone());
                }
                Ok(wallet_addr)
            }
            // No mapping — return device address as-is (built-in wallet mode).
            // Not cached to prevent memory exhaustion from random addresses.
            None => Ok(device_address.to_string()),
        }
    }

    /// Register a device and update the cache.
    ///
    /// **Cross-wallet hijack defense (Security Audit C1, 0.46.8).**
    /// Before writing, we look up the current forward-map entry for
    /// `claim.device_address`. If the device is already mapped to a
    /// DIFFERENT wallet, the registration is refused with an
    /// `Err`. The legitimate path to re-assign a device to a new
    /// wallet is: the old wallet publishes a `DeviceRevocation`
    /// envelope (which removes the forward-map entry), then the new
    /// wallet publishes a `DeviceDelegation`. Without this check, a
    /// wallet B publishing a `DeviceDelegation` envelope that names
    /// a device key D currently registered under wallet A would
    /// silently overwrite the forward map and "steal" device D
    /// across the entire mesh — `DeviceDelegationPayload` does not
    /// carry a proof-of-possession of the device's private key, so
    /// the wallet's signature on the envelope is not by itself
    /// authorisation to claim an arbitrary device pubkey. Closing
    /// the hijack vector at the storage boundary protects both the
    /// local `register_device` HTTP path AND the cross-node
    /// `update_indexes` apply arm with a single guard.
    ///
    /// Same-wallet re-registrations (legitimate claim refresh) and
    /// fresh registrations into an unmapped device address both
    /// proceed normally.
    pub fn register_device(&self, claim: &DeviceClaim) -> Result<()> {
        // Resolve directly against storage (not the cache) to avoid
        // racing with concurrent revocations that may have just
        // invalidated a cached entry.
        if let Some(existing_wallet) =
            self.storage.resolve_wallet(&claim.device_address)?
        {
            if existing_wallet != claim.wallet_address {
                anyhow::bail!(
                    "device {} is already mapped to wallet {}; refuse to \
                     reassign to {} without an explicit revocation first \
                     (cross-wallet device-hijack defense)",
                    claim.device_address,
                    existing_wallet,
                    claim.wallet_address,
                );
            }
        }
        self.storage.register_device(claim)?;
        // Update cache — always insert for existing keys (update), but respect
        // MAX_CACHE_ENTRIES for new entries to bound memory growth.
        if self.cache.contains_key(&claim.device_address)
            || self.cache.len() < MAX_CACHE_ENTRIES
        {
            self.cache.insert(
                claim.device_address.clone(),
                claim.wallet_address.clone(),
            );
        }
        Ok(())
    }

    /// Revoke a device registration and invalidate the cache. `revoked_at` is
    /// the revocation timestamp written to the P-2 tombstone so later stale
    /// delegations are rejected.
    ///
    /// Returns `true` if the device was registered and is now revoked.
    pub fn revoke_device(
        &self,
        device_address: &str,
        wallet_address: &str,
        revoked_at: u64,
    ) -> Result<bool> {
        let revoked = self
            .storage
            .revoke_device(device_address, wallet_address, revoked_at)?;
        if revoked {
            // Remove from cache so next resolve falls back to device address
            self.cache.remove(device_address);
        }
        Ok(revoked)
    }

    /// Revocation-tombstone timestamp for a device, if any (P-2).
    pub fn get_device_revoked_at(&self, device_address: &str) -> Result<Option<u64>> {
        self.storage.get_device_revoked_at(device_address)
    }

    /// List all devices registered to a wallet.
    pub fn list_devices(&self, wallet_address: &str) -> Result<Vec<DeviceClaim>> {
        self.storage.list_devices(wallet_address)
    }

    /// Warm the cache by loading all device mappings from RocksDB.
    ///
    /// Call once at startup to avoid cold-cache latency on the first
    /// batch of requests. Loads up to `MAX_CACHE_ENTRIES` mappings.
    pub fn warm_cache(&self) -> Result<usize> {
        let entries = self.storage.prefix_iter_cf(
            super::schema::cf::DEVICE_WALLET_MAP,
            &[],
            MAX_CACHE_ENTRIES,
        )?;

        let count = entries.len();
        if count >= MAX_CACHE_ENTRIES {
            warn!(
                limit = MAX_CACHE_ENTRIES,
                "identity cache warm limit reached — some device mappings not cached"
            );
        }

        for (key, value) in entries {
            let device = match String::from_utf8(key) {
                Ok(s) => s,
                Err(e) => {
                    warn!(error = %e, "corrupt device address in DEVICE_WALLET_MAP — skipping");
                    continue;
                }
            };
            let wallet = match String::from_utf8(value) {
                Ok(s) => s,
                Err(e) => {
                    warn!(device = %device, error = %e, "corrupt wallet address in DEVICE_WALLET_MAP — skipping");
                    continue;
                }
            };
            self.cache.insert(device, wallet);
        }

        Ok(count)
    }

    /// Number of cached entries (for diagnostics).
    pub fn cache_size(&self) -> usize {
        self.cache.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_storage() -> (Storage, TempDir) {
        let dir = TempDir::new().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        (storage, dir)
    }

    fn test_claim(device: &str, wallet: &str) -> DeviceClaim {
        DeviceClaim {
            device_address: device.to_string(),
            wallet_address: wallet.to_string(),
            device_pubkey_hex: "ab".repeat(32),
            wallet_signature: "cd".repeat(64),
            registered_at: 1_700_000_000_000,
        }
    }

    #[test]
    fn resolve_returns_device_when_no_mapping() {
        let (storage, _dir) = test_storage();
        let resolver = IdentityResolver::new(storage);

        let result = resolver.resolve("klv1device111").unwrap();
        assert_eq!(result, "klv1device111");
    }

    #[test]
    fn register_and_resolve() {
        let (storage, _dir) = test_storage();
        let resolver = IdentityResolver::new(storage);

        let claim = test_claim("klv1device222", "klv1wallet222");
        resolver.register_device(&claim).unwrap();

        let result = resolver.resolve("klv1device222").unwrap();
        assert_eq!(result, "klv1wallet222");
    }

    #[test]
    fn revoke_clears_mapping() {
        let (storage, _dir) = test_storage();
        let resolver = IdentityResolver::new(storage);

        let claim = test_claim("klv1device333", "klv1wallet333");
        resolver.register_device(&claim).unwrap();

        let revoked = resolver
            .revoke_device("klv1device333", "klv1wallet333", 1000)
            .unwrap();
        assert!(revoked);
        // P-2: tombstone now blocks a stale re-delegation (ts <= revoked_at)
        // and allows a genuine newer one.
        assert_eq!(resolver.get_device_revoked_at("klv1device333").unwrap(), Some(1000));

        let result = resolver.resolve("klv1device333").unwrap();
        assert_eq!(result, "klv1device333"); // falls back to device address
    }

    #[test]
    fn register_same_wallet_again_is_idempotent_update() {
        // Re-registering the same (wallet, device) tuple just updates
        // the claim row — this is the legitimate refresh path, e.g.
        // when a wallet rotates the claim signature with a fresher
        // timestamp.
        let (storage, _dir) = test_storage();
        let resolver = IdentityResolver::new(storage);
        let claim1 = test_claim("klv1deviceREFRESH", "klv1walletREFRESH");
        resolver.register_device(&claim1).unwrap();
        let mut claim2 = claim1.clone();
        claim2.registered_at = claim1.registered_at + 1000;
        resolver
            .register_device(&claim2)
            .expect("same-wallet refresh must succeed");
        assert_eq!(
            resolver.resolve("klv1deviceREFRESH").unwrap(),
            "klv1walletREFRESH"
        );
    }

    #[test]
    fn register_blocks_cross_wallet_overwrite() {
        // Security Audit C1 (0.46.8): a second wallet cannot
        // overwrite the forward map for a device already owned by
        // the first wallet, regardless of timestamp. The legitimate
        // path to reassign is: original wallet revokes, then new
        // wallet registers.
        let (storage, _dir) = test_storage();
        let resolver = IdentityResolver::new(storage);

        let claim_a = test_claim("klv1deviceHIJACK", "klv1walletA");
        resolver.register_device(&claim_a).unwrap();

        let claim_b = test_claim("klv1deviceHIJACK", "klv1walletB");
        let err = resolver
            .register_device(&claim_b)
            .expect_err("cross-wallet overwrite must be refused");
        let msg = format!("{err}");
        assert!(msg.contains("already mapped"), "error must explain: {msg}");
        assert!(msg.contains("hijack"), "error must reference hijack: {msg}");

        // Forward map is intact.
        assert_eq!(
            resolver.resolve("klv1deviceHIJACK").unwrap(),
            "klv1walletA"
        );
    }

    #[test]
    fn register_after_revoke_allows_new_wallet() {
        // Sanity: the cross-wallet defense allows reassignment after
        // an explicit revocation — the legitimate operator path.
        let (storage, _dir) = test_storage();
        let resolver = IdentityResolver::new(storage);

        let claim_a = test_claim("klv1deviceREVOKED", "klv1walletA");
        resolver.register_device(&claim_a).unwrap();
        let revoked = resolver
            .revoke_device("klv1deviceREVOKED", "klv1walletA", 1000)
            .unwrap();
        assert!(revoked);

        let claim_b = test_claim("klv1deviceREVOKED", "klv1walletB");
        resolver
            .register_device(&claim_b)
            .expect("post-revocation registration must succeed");
        assert_eq!(
            resolver.resolve("klv1deviceREVOKED").unwrap(),
            "klv1walletB"
        );
    }

    #[test]
    fn revoke_wrong_wallet_returns_false() {
        let (storage, _dir) = test_storage();
        let resolver = IdentityResolver::new(storage);

        let claim = test_claim("klv1device444", "klv1wallet444");
        resolver.register_device(&claim).unwrap();

        let revoked = resolver
            .revoke_device("klv1device444", "klv1wrongwallet", 1000)
            .unwrap();
        assert!(!revoked);

        // Mapping still intact
        let result = resolver.resolve("klv1device444").unwrap();
        assert_eq!(result, "klv1wallet444");
    }

    #[test]
    fn list_devices_for_wallet() {
        let (storage, _dir) = test_storage();
        let resolver = IdentityResolver::new(storage);

        let claim1 = test_claim("klv1deviceA", "klv1wallet555");
        let claim2 = test_claim("klv1deviceB", "klv1wallet555");
        resolver.register_device(&claim1).unwrap();
        resolver.register_device(&claim2).unwrap();

        let devices = resolver.list_devices("klv1wallet555").unwrap();
        assert_eq!(devices.len(), 2);

        let addrs: Vec<&str> = devices.iter().map(|c| c.device_address.as_str()).collect();
        assert!(addrs.contains(&"klv1deviceA"));
        assert!(addrs.contains(&"klv1deviceB"));
    }

    #[test]
    fn warm_cache_loads_existing_mappings() {
        let (storage, _dir) = test_storage();

        // Register directly via storage (simulating pre-existing data)
        let claim = test_claim("klv1device666", "klv1wallet666");
        storage.register_device(&claim).unwrap();

        // New resolver with cold cache
        let resolver = IdentityResolver::new(storage);
        assert_eq!(resolver.cache_size(), 0);

        let warmed = resolver.warm_cache().unwrap();
        assert_eq!(warmed, 1);
        assert_eq!(resolver.cache_size(), 1);

        // Should resolve from cache without DB hit
        let result = resolver.resolve("klv1device666").unwrap();
        assert_eq!(result, "klv1wallet666");
    }

    #[test]
    fn idempotent_registration() {
        let (storage, _dir) = test_storage();
        let resolver = IdentityResolver::new(storage);

        let claim = test_claim("klv1device777", "klv1wallet777");
        resolver.register_device(&claim).unwrap();
        resolver.register_device(&claim).unwrap(); // same again

        let devices = resolver.list_devices("klv1wallet777").unwrap();
        assert_eq!(devices.len(), 1);
    }
}
