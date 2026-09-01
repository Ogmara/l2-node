//! Small shared utilities.

/// Maximum length (bytes) of a canonical normalized tag.
pub const MAX_TAG_LEN: usize = 64;

/// Canonical normalized form of a news hashtag (protocol §3.5).
///
/// Procedure: trim ASCII whitespace → lowercase → strip a single leading
/// `#` → trim again → require `^[a-z0-9-]{1,64}$` (bytes). Returns `None`
/// when the input has no canonical representation: empty, longer than
/// [`MAX_TAG_LEN`], or containing any character outside `[a-z0-9-]` after
/// the steps above.
///
/// The L2 node indexes (`news_by_tag`), routes (`/news/tag/{tag}`), filters
/// (`GET /api/v1/news?tag=` / `?tags=`) and counts (Hot Topics, spec 3 §3.9)
/// tags in this form only. The `@ogmara/sdk` `normalizeHashtag()` helper MUST
/// produce byte-identical output for identical input — a follow/filter that
/// normalizes differently silently matches nothing.
pub fn normalize_tag(raw: &str) -> Option<String> {
    let lowered = raw.trim().to_lowercase();
    let stripped = lowered.strip_prefix('#').unwrap_or(&lowered).trim();
    if stripped.is_empty() || stripped.len() > MAX_TAG_LEN {
        return None;
    }
    if !stripped
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return None;
    }
    Some(stripped.to_string())
}

/// Normalize each tag in `raw`, drop the ones with no canonical form, and
/// de-duplicate while preserving first-seen order. Used for the `?tags=`
/// OR-set feed filter and for digesting a `NewsPost`'s tag list.
pub fn normalize_tags_dedup(raw: impl IntoIterator<Item = impl AsRef<str>>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for t in raw {
        if let Some(n) = normalize_tag(t.as_ref()) {
            if !out.contains(&n) {
                out.push(n);
            }
        }
    }
    out
}

/// Current wall-clock time in milliseconds since the Unix epoch. Saturates
/// to 0 if the clock is somehow before the epoch.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Truncate a string to at most `max` bytes, never splitting a multibyte
/// UTF-8 character.
///
/// audit 2026-06-07 (W16): naive `&s[..s.len().min(max)]` byte slicing
/// panics when `max` lands in the middle of a multibyte char — which can
/// happen with RPC / Kubo error bodies that contain UTF-8. This floors
/// `max` down to the nearest char boundary so the slice is always valid.
pub fn truncate_str(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    // Find the largest char-boundary index that is <= max.
    let end = s
        .char_indices()
        .map(|(i, _)| i)
        .take_while(|&i| i <= max)
        .last()
        .unwrap_or(0);
    &s[..end]
}

#[cfg(test)]
mod tests {
    use super::{normalize_tag, normalize_tags_dedup, truncate_str};

    #[test]
    fn normalize_tag_canonical_cases() {
        assert_eq!(normalize_tag("klever").as_deref(), Some("klever"));
        assert_eq!(normalize_tag("Klever").as_deref(), Some("klever"));
        assert_eq!(normalize_tag("#Klever").as_deref(), Some("klever"));
        assert_eq!(normalize_tag("  #Klever  ").as_deref(), Some("klever"));
        assert_eq!(normalize_tag("# klever").as_deref(), Some("klever"));
        assert_eq!(normalize_tag("web-3").as_deref(), Some("web-3"));
        assert_eq!(normalize_tag("ONCHAIN2026").as_deref(), Some("onchain2026"));
    }

    #[test]
    fn normalize_tag_rejects_non_canonical() {
        assert_eq!(normalize_tag(""), None);
        assert_eq!(normalize_tag("   "), None);
        assert_eq!(normalize_tag("#"), None);
        assert_eq!(normalize_tag("tag with spaces"), None);
        assert_eq!(normalize_tag("under_score"), None);
        assert_eq!(normalize_tag("emoji🔥"), None);
        assert_eq!(normalize_tag("Кириллица"), None);
        assert_eq!(normalize_tag(&"a".repeat(65)), None);
        assert_eq!(normalize_tag(&"a".repeat(64)).map(|s| s.len()), Some(64));
    }

    #[test]
    fn normalize_tags_dedup_drops_and_dedupes_preserving_order() {
        let got = normalize_tags_dedup(["#Klever", "klever", "bad tag", "DeFi", "defi", "web-3"]);
        assert_eq!(got, vec!["klever", "defi", "web-3"]);
    }

    #[test]
    fn truncate_ascii() {
        assert_eq!(truncate_str("hello world", 5), "hello");
        assert_eq!(truncate_str("hi", 5), "hi");
        assert_eq!(truncate_str("", 5), "");
    }

    #[test]
    fn truncate_multibyte_no_panic() {
        // "€" is 3 bytes (0xE2 0x82 0xAC). Slicing at a mid-char byte
        // index would panic with naive slicing.
        let s = "€€€€€"; // 15 bytes, 5 chars
        for max in 0..=20 {
            let out = truncate_str(s, max);
            // Must be a prefix and never panic / split a char.
            assert!(s.starts_with(out));
            assert!(out.len() <= max || out.is_empty());
        }
        // max=4 lands mid-second-char → must floor to 3 bytes (one "€").
        assert_eq!(truncate_str(s, 4), "€");
        // max=2 lands mid-first-char → must floor to empty.
        assert_eq!(truncate_str(s, 2), "");
    }

    #[test]
    fn truncate_mixed() {
        let s = "ab€cd"; // a(1) b(1) €(3) c(1) d(1) = 7 bytes
        assert_eq!(truncate_str(s, 7), "ab€cd"); // whole string
        assert_eq!(truncate_str(s, 6), "ab€c"); // byte 6 boundary (d at 6)
        assert_eq!(truncate_str(s, 5), "ab€"); // byte 5 boundary (c at 5)
        assert_eq!(truncate_str(s, 4), "ab"); // byte 4 mid-€ → floor to "ab"
        assert_eq!(truncate_str(s, 2), "ab");
    }
}
