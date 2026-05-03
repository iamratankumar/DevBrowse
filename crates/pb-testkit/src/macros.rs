//! Assertion macros, Module 0.5 subtask 3.
//!
//! Both macros are exported at the crate root via `#[macro_export]`.

/// Fail the test if `Display`-formatting `$err` produces a string that
/// looks like it leaks any of: a filesystem path, a UUID, a domain name,
/// or an email address.
///
/// This is the L27 enforcement primitive: every error type that flows
/// across an IPC or log boundary must `Display` opaquely. Tests use this
/// instead of hand-coding the regex for every error.
///
/// The detection is intentionally conservative — a false positive here is
/// a real bug surface (an error type *might* leak), and a false negative
/// would silently degrade L27. Specifically:
///   * **path** — anything containing `/` followed by a non-space, or a
///     Windows-style drive prefix `[A-Za-z]:\`.
///   * **UUID** — the canonical hyphenated form
///     `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`.
///   * **domain** — two or more dot-separated labels where every label is
///     ASCII alphanumeric with optional internal hyphens, and at least
///     one label has a vowel-bearing TLD-shape (length 2..=24).
///   * **email** — a local-part containing `@` followed by a domain.
///
/// Use the unsuffixed form for the common case. The `_with_message` form
/// adds a custom assertion message:
///
/// ```ignore
/// pb_testkit::assert_redacted!(my_error);
/// pb_testkit::assert_redacted!(my_error, "should never leak the partition path");
/// ```
#[macro_export]
macro_rules! assert_redacted {
    ($err:expr $(,)?) => {{
        let s = format!("{}", $err);
        $crate::macros::__check_redacted(&s, "");
    }};
    ($err:expr, $msg:expr $(,)?) => {{
        let s = format!("{}", $err);
        $crate::macros::__check_redacted(&s, $msg);
    }};
}

/// Fail the test if any storage value reachable under partition `$a` is
/// reachable under partition `$b`. Catches §5.2 partition-key bypass
/// regressions.
///
/// The macro accepts two closures, each of which performs a `get`-shaped
/// lookup and returns `Option<Vec<u8>>` (or any `PartialEq` value). The
/// invariant is: there exists no key for which both closures return
/// `Some(_)` with byte-equal payload. Concretely:
///
/// ```ignore
/// pb_testkit::assert_partition_isolated!(
///     "secret-key",
///     |k| storage.get_under(partition_a, k),
///     |k| storage.get_under(partition_b, k),
/// );
/// ```
///
/// The macro asserts that the second closure does NOT return any value
/// equal to what the first returns. It does not assume the closures are
/// pure; each is invoked exactly once with the supplied key.
#[macro_export]
macro_rules! assert_partition_isolated {
    ($key:expr, $a_lookup:expr, $b_lookup:expr $(,)?) => {{
        let a_val = ($a_lookup)($key);
        let b_val = ($b_lookup)($key);
        $crate::macros::__check_partition_isolated(&a_val, &b_val, stringify!($key));
    }};
}

// ── implementation helpers (called from the macros) ──────────────────────────

#[doc(hidden)]
pub fn __check_redacted(rendered: &str, custom: &str) {
    if let Some(reason) = leak_reason(rendered) {
        let prefix = if custom.is_empty() {
            String::new()
        } else {
            format!("{}: ", custom)
        };
        panic!(
            "{prefix}error Display leaked {reason}: {rendered:?} \
             (L27 redaction violation — error must not surface paths, \
             UUIDs, domains, or emails through Display)"
        );
    }
}

#[doc(hidden)]
pub fn __check_partition_isolated<T: std::fmt::Debug + PartialEq>(a: &T, b: &T, key_label: &str) {
    if a == b && !is_none_like(a) {
        panic!(
            "partition isolation violated for key `{key_label}`: \
             value reachable under both partitions: {a:?}"
        );
    }
}

// `Option::None` should not trigger isolation failure; we want to detect
// only the case where a *value* is shared. We approximate Noneness via
// Debug formatting because the macro is generic over `T`.
fn is_none_like<T: std::fmt::Debug>(v: &T) -> bool {
    let s = format!("{v:?}");
    s == "None" || s == "Ok(None)" || s == "Err(\"\")"
}

fn leak_reason(s: &str) -> Option<&'static str> {
    if contains_uuid(s) {
        return Some("a UUID");
    }
    if contains_email(s) {
        return Some("an email address");
    }
    if contains_path(s) {
        return Some("a filesystem path");
    }
    if contains_domain(s) {
        return Some("a domain name");
    }
    None
}

fn contains_uuid(s: &str) -> bool {
    // Canonical hyphenated UUID: 8-4-4-4-12 hex.
    let mut bytes = s.as_bytes();
    while bytes.len() >= 36 {
        if matches_uuid(&bytes[..36]) {
            return true;
        }
        bytes = &bytes[1..];
    }
    false
}

fn matches_uuid(b: &[u8]) -> bool {
    if b.len() != 36 {
        return false;
    }
    let groups = [(0, 8), (9, 13), (14, 18), (19, 23), (24, 36)];
    let dashes = [8, 13, 18, 23];
    for d in dashes {
        if b[d] != b'-' {
            return false;
        }
    }
    for (start, end) in groups {
        if !b[start..end].iter().all(|c| c.is_ascii_hexdigit()) {
            return false;
        }
    }
    true
}

fn contains_email(s: &str) -> bool {
    if let Some(at) = s.find('@') {
        let before = &s[..at];
        let after = &s[at + 1..];
        let local_len = before
            .chars()
            .rev()
            .take_while(|c| email_local_char(*c))
            .count();
        if local_len >= 1 {
            // Only the leading domain-shaped prefix of `after` matters;
            // the rest of the surrounding sentence is irrelevant.
            let domain_prefix: String = after.chars().take_while(|c| is_domain_char(*c)).collect();
            if contains_domain_at_start(&domain_prefix) {
                return true;
            }
        }
    }
    false
}

fn email_local_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-')
}

fn contains_path(s: &str) -> bool {
    // Unix-style: `/<non-space>` chunk that is not a bare `/` before
    // whitespace or end of string.
    if let Some(idx) = s.find('/') {
        let after = &s[idx + 1..];
        if let Some(c) = after.chars().next() {
            if !c.is_whitespace() && c != '/' {
                return true;
            }
        }
    }
    // Windows-style: `[A-Za-z]:\` or `[A-Za-z]:/`.
    let bytes = s.as_bytes();
    for i in 0..bytes.len().saturating_sub(2) {
        if bytes[i].is_ascii_alphabetic()
            && bytes[i + 1] == b':'
            && (bytes[i + 2] == b'\\' || bytes[i + 2] == b'/')
        {
            return true;
        }
    }
    false
}

fn contains_domain(s: &str) -> bool {
    for word in s.split(|c: char| !is_domain_char(c)) {
        if contains_domain_at_start(word) {
            return true;
        }
    }
    false
}

fn contains_domain_at_start(word: &str) -> bool {
    if word.len() < 4 {
        return false;
    }
    let labels: Vec<&str> = word.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    if labels.iter().any(|l| l.is_empty()) {
        return false;
    }
    if !labels.iter().all(|l| {
        let bytes = l.as_bytes();
        if bytes.len() > 63 {
            return false;
        }
        if bytes[0] == b'-' || bytes[bytes.len() - 1] == b'-' {
            return false;
        }
        l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    }) {
        return false;
    }
    let tld = labels.last().unwrap();
    if tld.len() < 2 || tld.len() > 24 {
        return false;
    }
    if !tld.chars().all(|c| c.is_ascii_alphabetic()) {
        return false;
    }
    true
}

fn is_domain_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '.' || c == '-'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_uuid() {
        assert!(contains_uuid(
            "request id is 550e8400-e29b-41d4-a716-446655440000 sorry"
        ));
        assert!(!contains_uuid("just a number 12345 here"));
    }

    #[test]
    fn detects_path_unix_and_windows() {
        assert!(contains_path("error opening /home/user/.config/x"));
        assert!(contains_path("could not read C:\\Users\\foo"));
        assert!(!contains_path("error / no detail"));
    }

    #[test]
    fn detects_domain() {
        assert!(contains_domain("could not reach example.com today"));
        assert!(contains_domain("connecting to a.b.c.example.org"));
        assert!(!contains_domain("plain word here"));
        assert!(!contains_domain("ratio 1.5 reported"));
    }

    #[test]
    fn detects_email() {
        assert!(contains_email("user@example.com requested"));
        assert!(!contains_email("just an @ sign"));
    }

    #[test]
    fn opaque_message_passes() {
        assert!(leak_reason("storage backend error").is_none());
        assert!(leak_reason("partition key mismatch").is_none());
        assert!(leak_reason("connection closed").is_none());
    }

    #[test]
    fn macro_fires_on_leaky_error() {
        let result = std::panic::catch_unwind(|| {
            let leaky: &str = "open /home/user/.local/share/devbrowse failed";
            crate::assert_redacted!(leaky);
        });
        assert!(result.is_err());
    }

    #[test]
    fn macro_passes_on_redacted_error() {
        let opaque: &str = "storage backend error";
        crate::assert_redacted!(opaque);
    }

    #[test]
    fn partition_isolation_macro_passes_when_only_one_side_has_value() {
        crate::assert_partition_isolated!("k", |_k: &str| Some(b"alpha".to_vec()), |_k: &str| {
            Option::<Vec<u8>>::None
        },);
    }

    #[test]
    fn partition_isolation_macro_fires_when_value_shared() {
        let result = std::panic::catch_unwind(|| {
            crate::assert_partition_isolated!(
                "k",
                |_k: &str| Some(b"shared".to_vec()),
                |_k: &str| Some(b"shared".to_vec()),
            );
        });
        assert!(result.is_err());
    }
}
