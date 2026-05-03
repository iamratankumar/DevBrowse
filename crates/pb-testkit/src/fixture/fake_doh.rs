//! `fixture::fake_doh` — scripted DNS-over-HTTPS responses.
//!
//! Subtask 2 of Module 0.5. Phase 4 (Module 20) will land the production
//! DoH client. Until then, `pb-network` does not exist as a runtime
//! crate, so the fixture's contract is shaped to be drop-in for the
//! eventual production trait.
//!
//! Phase 4 onward must extend this file to take a `dyn DohClient`-shaped
//! trait once Module 20 declares it; the current stand-alone shape is a
//! placeholder that lets Phase 4 tests start writing assertions against
//! a programmable DNS surface today.
//
// TODO(Module 20): once pb-network's DoH client trait lands, change
//   FakeDohResolver to implement that trait directly so fixture call
//   sites do not have to switch shape.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use thiserror::Error;

/// One scripted DoH response. Matches what Module 20's parsed-response
/// struct is expected to carry: a name, a vec of A/AAAA records, and a
/// minimum TTL across the answer set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptedDohResponse {
    pub name: String,
    pub addresses: Vec<IpAddr>,
    pub ttl_secs: u32,
}

/// Errors the fake resolver can produce. Mirrors the shape Module 20 is
/// expected to expose; once that lands, `From` impls bridge the two.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum FakeDohError {
    /// No scripted response for the queried name. Lets a test prove
    /// "exactly these names were queried, no others".
    #[error("DoH resolver failure")]
    Unscripted,
}

/// Scripted DoH resolver. Lookups are exact-match on the queried name
/// (lowercased). Multiple lookups for the same name return the same
/// response — DoH responses are cacheable per RFC 8484, but the fake
/// does not model TTL expiry; tests that need that should advance time
/// in the consumer.
pub struct FakeDohResolver {
    table: Mutex<HashMap<String, ScriptedDohResponse>>,
    queries: Mutex<Vec<String>>,
}

impl FakeDohResolver {
    pub fn new() -> Self {
        Self {
            table: Mutex::new(HashMap::new()),
            queries: Mutex::new(Vec::new()),
        }
    }

    /// Add or replace the scripted response for `response.name`.
    pub fn script(&self, response: ScriptedDohResponse) {
        let key = response.name.to_ascii_lowercase();
        self.table.lock().unwrap().insert(key, response);
    }

    /// Look up `name`. Records the query for later assertions.
    pub fn lookup(&self, name: &str) -> Result<ScriptedDohResponse, FakeDohError> {
        let key = name.to_ascii_lowercase();
        self.queries.lock().unwrap().push(key.clone());
        self.table
            .lock()
            .unwrap()
            .get(&key)
            .cloned()
            .ok_or(FakeDohError::Unscripted)
    }

    /// Recorded queries, in order. Used to assert "the network layer
    /// queried exactly these names".
    pub fn queries(&self) -> Vec<String> {
        self.queries.lock().unwrap().clone()
    }
}

impl Default for FakeDohResolver {
    fn default() -> Self {
        Self::new()
    }
}

/// Free-function form to match the `fixture::fake_doh()` call shape.
pub fn fake_doh() -> FakeDohResolver {
    FakeDohResolver::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn scripted_lookup_returns_response() {
        let r = fake_doh();
        r.script(ScriptedDohResponse {
            name: "example.test".into(),
            addresses: vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))],
            ttl_secs: 300,
        });
        let got = r.lookup("example.test").unwrap();
        assert_eq!(got.addresses, vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))]);
    }

    #[test]
    fn unscripted_lookup_errors() {
        let r = fake_doh();
        assert_eq!(
            r.lookup("not-scripted.test").unwrap_err(),
            FakeDohError::Unscripted
        );
    }

    #[test]
    fn name_match_is_case_insensitive() {
        let r = fake_doh();
        r.script(ScriptedDohResponse {
            name: "Example.Test".into(),
            addresses: vec![],
            ttl_secs: 0,
        });
        assert!(r.lookup("EXAMPLE.test").is_ok());
    }

    #[test]
    fn queries_recorded_in_order() {
        let r = fake_doh();
        let _ = r.lookup("a.test");
        let _ = r.lookup("b.test");
        assert_eq!(
            r.queries(),
            vec!["a.test".to_string(), "b.test".to_string()]
        );
    }
}
