//! The anchored chain mirror (l2-node 0.148.0, spec 02 §7, spec 03 §3.6).
//!
//! `ANCHORED_STATE` holds exactly what the anchored state root (v4) commits
//! to: the node's mirror of the Ogmara smart contract's users, channels and
//! device delegations. It is written ONLY by the chain scanner (from SC
//! transactions, in chain order) and by its repair sweep (records confirmed
//! through SC views), never by gossip, the router or the API — so two nodes
//! that have seen the same chain hold byte-identical rows.
//!
//! Every leaf field must be obtainable identically on both write paths.
//! `getUserRegisteredAt` / `getChannelInfo` are only populated since SC
//! 0.6.1 (0 for older records) while the scanner sees the transaction
//! timestamp, so registration and creation times are NOT leaf fields; the
//! delegation record is unchanged since the first SC version and is mirrored
//! whole.
//!
//! Keys: `b'u' ++ address`, `b'c' ++ channel_id_be8`,
//! `b'd' ++ user ++ 0x00 ++ device_key`. Values: the canonical JSON of the
//! record structs below — serde emits fields in declaration order, which is
//! alphabetical, with no whitespace.

use anyhow::{Context, Result};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use super::rocks::Storage;
use super::schema::cf;

/// Key prefix of user rows.
pub const USER_PREFIX: u8 = b'u';
/// Key prefix of channel rows.
pub const CHANNEL_PREFIX: u8 = b'c';
/// Key prefix of delegation rows.
pub const DELEGATION_PREFIX: u8 = b'd';

/// An on-chain user registration. Fields in alphabetical order (canonical).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchoredUser {
    pub address: String,
    /// Hex public key exactly as the SC stores it (`getUserPubKey`).
    pub public_key: String,
}

/// An on-chain channel. Fields in alphabetical order (canonical).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchoredChannel {
    pub channel_id: u64,
    /// Current owner (after any `transferChannel`).
    pub creator: String,
    pub slug: String,
}

/// An on-chain device delegation — the SC's `DelegationRecord` plus its
/// key. Fields in alphabetical order (canonical).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchoredDelegation {
    pub created_at: u64,
    /// Device key exactly as the SC stores it.
    pub device_key: String,
    pub expires_at: u64,
    pub permissions: u8,
    /// 0 while not revoked.
    pub revoked_at: u64,
    pub user: String,
}

/// Key of a user row.
pub fn user_key(address: &str) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + address.len());
    k.push(USER_PREFIX);
    k.extend_from_slice(address.as_bytes());
    k
}

/// Key of a channel row.
pub fn channel_key(channel_id: u64) -> Vec<u8> {
    let mut k = Vec::with_capacity(9);
    k.push(CHANNEL_PREFIX);
    k.extend_from_slice(&channel_id.to_be_bytes());
    k
}

/// Key of a delegation row. `0x00` cannot occur in a bech32 address, so the
/// split is unambiguous.
pub fn delegation_key(user: &str, device_key: &str) -> Vec<u8> {
    let mut k = Vec::with_capacity(2 + user.len() + device_key.len());
    k.push(DELEGATION_PREFIX);
    k.extend_from_slice(user.as_bytes());
    k.push(0);
    k.extend_from_slice(device_key.as_bytes());
    k
}

/// The canonical leaf value of a record.
pub fn encode<T: Serialize>(record: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(record).context("encoding anchored record")
}

/// `registered_at` of a `USERS` row derived from the chain mirror (snapshot
/// bootstrap): registered on-chain, registration time unknown (the leaf does
/// not carry it). Readers treat any value below [`REGISTERED_AT_KNOWN_MIN`]
/// as "registered, time unknown".
pub const REGISTERED_AT_UNKNOWN: u64 = 1;
/// Smallest `registered_at` that is a real unix-seconds timestamp.
pub const REGISTERED_AT_KNOWN_MIN: u64 = 1_000_000_000;

/// Check a peer-supplied mirror row: it must decode as the record its key
/// prefix names, in canonical form, under exactly the key that record
/// derives. Snapshot apply refuses anything else, so a row can never be
/// filed under another identity.
pub fn validate_row(key: &[u8], value: &[u8]) -> Result<()> {
    fn check<T: Serialize + DeserializeOwned>(value: &[u8], key_of: impl Fn(&T) -> Vec<u8>, key: &[u8]) -> Result<()> {
        let record: T = serde_json::from_slice(value).context("undecodable anchored row")?;
        anyhow::ensure!(encode(&record)? == value, "anchored row is not in canonical form");
        anyhow::ensure!(key_of(&record) == key, "anchored row is filed under the wrong key");
        Ok(())
    }
    match key.first() {
        Some(&USER_PREFIX) => check::<AnchoredUser>(value, |u| user_key(&u.address), key),
        Some(&CHANNEL_PREFIX) => check::<AnchoredChannel>(value, |c| channel_key(c.channel_id), key),
        Some(&DELEGATION_PREFIX) => {
            check::<AnchoredDelegation>(value, |d| delegation_key(&d.user, &d.device_key), key)
        }
        _ => anyhow::bail!("anchored row has an unknown key prefix"),
    }
}

impl Storage {
    fn get_anchored<T: DeserializeOwned>(&self, key: &[u8]) -> Result<Option<T>> {
        self.get_cf(cf::ANCHORED_STATE, key)?
            .map(|raw| serde_json::from_slice(&raw).context("decoding anchored record"))
            .transpose()
    }

    fn put_anchored<T: Serialize>(&self, key: &[u8], record: &T) -> Result<()> {
        self.put_cf(cf::ANCHORED_STATE, key, &encode(record)?)
    }

    /// Whether the mirror holds a row under `key`.
    pub fn anchored_contains(&self, key: &[u8]) -> Result<bool> {
        self.exists_cf(cf::ANCHORED_STATE, key)
    }

    /// Scanner: `register`.
    pub fn anchored_register_user(&self, address: &str, public_key: &str) -> Result<()> {
        let record = AnchoredUser { address: address.into(), public_key: public_key.into() };
        self.put_anchored(&user_key(address), &record)
    }

    /// Scanner: `updatePublicKey`. A user the mirror does not hold (its
    /// registration was missed) is left to the repair sweep, which reads the
    /// current key from the SC.
    pub fn anchored_update_user_key(&self, address: &str, public_key: &str) -> Result<()> {
        let key = user_key(address);
        if let Some(mut user) = self.get_anchored::<AnchoredUser>(&key)? {
            user.public_key = public_key.into();
            self.put_anchored(&key, &user)?;
        }
        Ok(())
    }

    /// Scanner: `createChannel` (unconditionally — L2 deletion or a local
    /// private-row collision does not change what the chain says).
    pub fn anchored_create_channel(&self, channel_id: u64, slug: &str, creator: &str) -> Result<()> {
        let record = AnchoredChannel { channel_id, creator: creator.into(), slug: slug.into() };
        self.put_anchored(&channel_key(channel_id), &record)
    }

    /// Scanner: `transferChannel`. A channel the mirror does not hold is
    /// left to the repair sweep (it reads the current creator).
    pub fn anchored_transfer_channel(&self, channel_id: u64, to: &str) -> Result<()> {
        let key = channel_key(channel_id);
        if let Some(mut channel) = self.get_anchored::<AnchoredChannel>(&key)? {
            channel.creator = to.into();
            self.put_anchored(&key, &channel)?;
        }
        Ok(())
    }

    /// Scanner: `delegateDevice` (a re-delegation replaces the record, as
    /// on-chain).
    pub fn anchored_delegate(&self, record: &AnchoredDelegation) -> Result<()> {
        self.put_anchored(&delegation_key(&record.user, &record.device_key), record)
    }

    /// Scanner: `revokeDevice` at `revoked_at` (the transaction's block
    /// timestamp, which is what the SC records).
    pub fn anchored_revoke(&self, user: &str, device_key: &str, revoked_at: u64) -> Result<()> {
        let key = delegation_key(user, device_key);
        if let Some(mut d) = self.get_anchored::<AnchoredDelegation>(&key)? {
            d.revoked_at = revoked_at;
            self.put_anchored(&key, &d)?;
        }
        Ok(())
    }

    /// The user record, if mirrored.
    #[cfg(test)]
    pub fn anchored_user(&self, address: &str) -> Result<Option<AnchoredUser>> {
        self.get_anchored(&user_key(address))
    }

    /// Unix seconds of the last "not registered" answer for `address`.
    pub fn anchored_repair_negative_at(&self, address: &str) -> Result<Option<u64>> {
        let mut k = vec![b'n'];
        k.extend_from_slice(address.as_bytes());
        Ok(self
            .get_cf(cf::ANCHORED_REPAIR, &k)?
            .and_then(|raw| Some(u64::from_be_bytes(raw.as_slice().try_into().ok()?))))
    }

    /// Record a "not registered" answer for `address` at `now`.
    pub fn set_anchored_repair_negative(&self, address: &str, now: u64) -> Result<()> {
        let mut k = vec![b'n'];
        k.extend_from_slice(address.as_bytes());
        self.put_cf(cf::ANCHORED_REPAIR, &k, &now.to_be_bytes())
    }

    /// Advance the chain cursor and record that the mirror is current up to
    /// it (`ANCHORED_MIRROR_CURSOR`) in one atomic batch — a crash between
    /// two separate writes would trigger a needless re-verification.
    pub fn set_chain_cursor_with_mirror(&self, block_height: u64) -> Result<()> {
        let handle = self.cf_handle(cf::NODE_STATE)?;
        let mut batch = rocksdb::WriteBatch::default();
        batch.put_cf(&handle, super::schema::state_keys::CHAIN_CURSOR, block_height.to_be_bytes());
        batch.put_cf(&handle, super::schema::state_keys::ANCHORED_MIRROR_CURSOR, block_height.to_be_bytes());
        drop(handle);
        self.write_batch(batch).context("advancing the chain cursor")
    }

    /// Whether the first repair pass has filled the mirror.
    pub fn anchored_state_migrated(&self) -> Result<bool> {
        Ok(self
            .get_cf(cf::NODE_STATE, super::schema::state_keys::ANCHORED_STATE_MIGRATED_V1)?
            .is_some())
    }

    /// Mark the first repair pass done.
    pub fn set_anchored_state_migrated(&self) -> Result<()> {
        self.put_cf(cf::NODE_STATE, super::schema::state_keys::ANCHORED_STATE_MIGRATED_V1, &[1])
    }

    /// After a snapshot filled the mirror: derive the chain-owned parts of
    /// the `USERS` / `CHANNELS` / `DELEGATIONS` rows the rest of the node
    /// reads, as the chain scanner would have written them. Gossip-owned
    /// fields (profiles, channel metadata, memberships beyond the creator)
    /// are left for the signed sync paths. Existing gossip rows are merged,
    /// never replaced. Returns `(users, channels, delegations)` derived.
    pub fn derive_rows_from_anchored_state(&self, now: u64) -> Result<(u64, u64, u64)> {
        use crate::chain::types::{ChannelRecord, DelegationRecord, UserRecord};
        let mut counts = (0, 0, 0);

        for (_, raw) in self.prefix_iter_cf(cf::ANCHORED_STATE, &[USER_PREFIX], usize::MAX)? {
            let u: AnchoredUser = serde_json::from_slice(&raw)?;
            let row = match self.get_cf(cf::USERS, u.address.as_bytes())? {
                // A gossip-created row (ProfileUpdate before registration was
                // known): keep every field, add the chain facts.
                Some(existing) => {
                    let mut v: serde_json::Value = serde_json::from_slice(&existing).unwrap_or_else(|_| serde_json::json!({}));
                    let Some(obj) = v.as_object_mut() else { continue };
                    obj.insert("address".into(), u.address.clone().into());
                    obj.insert("public_key".into(), u.public_key.clone().into());
                    if obj.get("registered_at").and_then(|r| r.as_u64()).unwrap_or(0) == 0 {
                        obj.insert("registered_at".into(), REGISTERED_AT_UNKNOWN.into());
                    }
                    serde_json::to_vec(&v)?
                }
                // `profile_updated_at: None` = "not checked yet", so the
                // identity-sync sweep fetches the profile.
                None => serde_json::to_vec(&UserRecord {
                    address: u.address.clone(),
                    public_key: u.public_key,
                    registered_at: REGISTERED_AT_UNKNOWN,
                    display_name: None,
                    avatar_cid: None,
                    bio: None,
                    profile_updated_at: None,
                })?,
            };
            self.put_cf(cf::USERS, u.address.as_bytes(), &row)?;
            counts.0 += 1;
        }

        for (_, raw) in self.prefix_iter_cf(cf::ANCHORED_STATE, &[CHANNEL_PREFIX], usize::MAX)? {
            let c: AnchoredChannel = serde_json::from_slice(&raw)?;
            if self.exists_cf(cf::CHANNELS, &c.channel_id.to_be_bytes())? {
                continue;
            }
            // The on-chain type and creation time are not in the leaf; the
            // channel starts Public and the metadata reconciler applies the
            // L2-authoritative type.
            let record = ChannelRecord {
                channel_id: c.channel_id,
                slug: c.slug,
                creator: c.creator.clone(),
                channel_type: 0,
                created_at: 0,
                display_name: None,
                description: None,
                member_count: 0,
            };
            self.put_channel_and_replay_pending_member_removals(c.channel_id, &serde_json::to_vec(&record)?)?;
            let member_key = super::schema::encode_channel_member_key(c.channel_id, &c.creator);
            self.put_cf(cf::CHANNEL_MEMBERS, &member_key, br#"{"joined_at":0,"role":"creator"}"#)?;
            self.mark_channel_creator_verified(c.channel_id, now)?;
            counts.1 += 1;
        }

        for (_, raw) in self.prefix_iter_cf(cf::ANCHORED_STATE, &[DELEGATION_PREFIX], usize::MAX)? {
            let d: AnchoredDelegation = serde_json::from_slice(&raw)?;
            let record = DelegationRecord {
                user_address: d.user.clone(),
                device_pub_key: d.device_key.clone(),
                permissions: d.permissions,
                expires_at: d.expires_at,
                created_at: d.created_at,
                active: d.revoked_at == 0,
            };
            let key = super::schema::encode_delegation_key(&d.user, &d.device_key);
            self.put_cf(cf::DELEGATIONS, &key, &serde_json::to_vec(&record)?)?;
            counts.2 += 1;
        }
        Ok(counts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_values_are_alphabetical_compact_json() {
        let u = AnchoredUser { address: "klv1a".into(), public_key: "ab".into() };
        assert_eq!(encode(&u).unwrap(), br#"{"address":"klv1a","public_key":"ab"}"#);
        let c = AnchoredChannel { channel_id: 20, creator: "klv1c".into(), slug: "testnet".into() };
        assert_eq!(encode(&c).unwrap(), br#"{"channel_id":20,"creator":"klv1c","slug":"testnet"}"#);
        let d = AnchoredDelegation {
            created_at: 5,
            device_key: "dd".into(),
            expires_at: 0,
            permissions: 7,
            revoked_at: 0,
            user: "klv1u".into(),
        };
        assert_eq!(
            encode(&d).unwrap(),
            br#"{"created_at":5,"device_key":"dd","expires_at":0,"permissions":7,"revoked_at":0,"user":"klv1u"}"#
        );
    }

    #[test]
    fn peer_rows_must_be_canonical_and_correctly_keyed() {
        let u = AnchoredUser { address: "klv1a".into(), public_key: "ab".into() };
        let v = encode(&u).unwrap();
        assert!(validate_row(&user_key("klv1a"), &v).is_ok());
        // Filed under another identity.
        assert!(validate_row(&user_key("klv1b"), &v).is_err());
        // Wrong record type for the prefix.
        assert!(validate_row(&channel_key(1), &v).is_err());
        // Non-canonical encoding (extra field / whitespace).
        assert!(validate_row(&user_key("klv1a"), br#"{"address":"klv1a","public_key":"ab","x":1}"#).is_err());
        assert!(validate_row(&user_key("klv1a"), br#"{"address": "klv1a","public_key":"ab"}"#).is_err());
        assert!(validate_row(b"zzz", &v).is_err());
    }

    #[test]
    fn derived_rows_merge_into_gossip_rows() {
        let dir = tempfile::tempdir().unwrap();
        let s = Storage::open(dir.path()).unwrap();
        s.anchored_register_user("klv1a", "k1").unwrap();
        s.anchored_register_user("klv1b", "k2").unwrap();
        // A gossip row for klv1b with a profile.
        s.put_cf(cf::USERS, b"klv1b", br#"{"address":"klv1b","registered_at":0,"display_name":"Bee"}"#).unwrap();
        s.anchored_create_channel(5, "dev", "klv1a").unwrap();
        s.anchored_delegate(&AnchoredDelegation {
            created_at: 5,
            device_key: "dd".into(),
            expires_at: 0,
            permissions: 7,
            revoked_at: 9,
            user: "klv1a".into(),
        })
        .unwrap();
        assert_eq!(s.derive_rows_from_anchored_state(100).unwrap(), (2, 1, 1));
        let b: serde_json::Value = serde_json::from_slice(&s.get_cf(cf::USERS, b"klv1b").unwrap().unwrap()).unwrap();
        assert_eq!(b["display_name"], "Bee");
        assert_eq!(b["registered_at"], REGISTERED_AT_UNKNOWN);
        assert_eq!(b["public_key"], "k2");
        let a: serde_json::Value = serde_json::from_slice(&s.get_cf(cf::USERS, b"klv1a").unwrap().unwrap()).unwrap();
        assert!(a["profile_updated_at"].is_null());
        assert!(s.exists_cf(cf::CHANNELS, &5u64.to_be_bytes()).unwrap());
        let d: serde_json::Value = serde_json::from_slice(
            &s.get_cf(cf::DELEGATIONS, &crate::storage::schema::encode_delegation_key("klv1a", "dd")).unwrap().unwrap(),
        )
        .unwrap();
        assert_eq!(d["active"], false);
    }

    #[test]
    fn keys_are_prefixed_and_unambiguous() {
        assert_eq!(user_key("klv1a"), b"uklv1a");
        assert_eq!(channel_key(20), [b'c', 0, 0, 0, 0, 0, 0, 0, 20]);
        assert_eq!(delegation_key("klv1u", "dd"), b"dklv1u\0dd");
    }

    #[test]
    fn scanner_mutations_and_insert_if_absent() {
        let dir = tempfile::tempdir().unwrap();
        let s = Storage::open(dir.path()).unwrap();
        s.anchored_register_user("klv1a", "k1").unwrap();
        s.anchored_update_user_key("klv1a", "k2").unwrap();
        // An update for an unknown user writes nothing.
        s.anchored_update_user_key("klv1b", "k9").unwrap();
        assert_eq!(s.anchored_user("klv1a").unwrap().unwrap().public_key, "k2");
        assert!(s.anchored_user("klv1b").unwrap().is_none());

        s.anchored_create_channel(3, "news", "klv1a").unwrap();
        s.anchored_transfer_channel(3, "klv1b").unwrap();
        let raw = s.get_cf(cf::ANCHORED_STATE, &channel_key(3)).unwrap().unwrap();
        assert_eq!(raw, br#"{"channel_id":3,"creator":"klv1b","slug":"news"}"#);

        let d = AnchoredDelegation {
            created_at: 5,
            device_key: "dd".into(),
            expires_at: 0,
            permissions: 7,
            revoked_at: 0,
            user: "klv1a".into(),
        };
        s.anchored_delegate(&d).unwrap();
        s.anchored_revoke("klv1a", "dd", 9).unwrap();
        let got: AnchoredDelegation = s.get_anchored(&delegation_key("klv1a", "dd")).unwrap().unwrap();
        assert_eq!(got.revoked_at, 9);
    }
}
