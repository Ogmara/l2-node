//! Small shared utilities.

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
    use super::truncate_str;

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
