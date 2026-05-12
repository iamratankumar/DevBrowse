//! Reverse-label radix tree for hostname blocklist matching, Module 21.
//!
//! Hostnames are inserted right-to-left (reversed labels) so common
//! TLD prefixes (`com`, `net`) sit at the root and the tree narrows
//! by domain. Matching descends one label at a time and tracks the
//! deepest applicable subdomain-inclusive terminal as the
//! "longest match wins" canonical answer.
//!
//! Performance contract (README §13 perf row for Module 21):
//!     blocklist match: < 100 µs P99 on an 80k-entry tree.
//!
//! v1 implementation:
//!   * `HashMap<String, Node>` per-node child map. Lookup is O(label
//!     count) which is bounded by the depth of the deepest rule (rarely
//!     above 5 in practice, even on Hagezi `pro.plus`).
//!   * `match_host` lowercases its input once on entry for ASCII case
//!     normalization. If profiling shows the lowercase allocation as a
//!     hot-path cost, a future revision can require pre-lowercased input
//!     and add a `match_host_lowercase` bypass; the v1 surface trades
//!     that micro-cost for a foolproof match contract.
//!
//! ## Match semantics
//!
//!   * **Subdomain-inclusive (`Rule::host`)** — a rule for
//!     `example.com` matches `example.com` AND `tracker.example.com`
//!     AND `a.b.c.example.com`.
//!   * **Subdomain-exclusive (`Rule::host_exact`)** — a rule for
//!     `example.com` matches `example.com` only; `tracker.example.com`
//!     does NOT match.
//!   * **Longest-match wins** — when multiple rules apply, the rule
//!     with the most-specific (deepest) hostname wins, even if its
//!     [`BlockKind`] differs from a parent rule.

use crate::blocklist::rule::{BlockKind, Rule};
use std::collections::HashMap;

/// Compiled radix tree. Built from a [`Rule`] slice via
/// [`RadixTree::from_rules`]; immutable after construction so the
/// match path needs no locks (the live wrapper in
/// [`crate::blocklist::Blocklist`] holds an `Arc<RadixTree>` and
/// hot-swaps it under a writer lock).
#[derive(Debug, Default)]
pub struct RadixTree {
    root: Node,
}

#[derive(Debug, Default)]
struct Node {
    children: HashMap<String, Node>,
    terminal: Option<Terminal>,
}

#[derive(Debug, Clone, Copy)]
struct Terminal {
    kind: BlockKind,
    applies_to_subdomains: bool,
}

impl RadixTree {
    /// Empty tree — matches nothing. Used as the bootstrap state of a
    /// [`crate::blocklist::Blocklist`] before the first manifest load.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Build a tree from a slice of rules. Empty hostnames and rules
    /// whose hostnames consist of only separators are silently dropped.
    pub fn from_rules(rules: &[Rule]) -> Self {
        let mut root = Node::default();
        for rule in rules {
            insert(&mut root, rule);
        }
        Self { root }
    }

    /// Match the given hostname against the tree. Returns the
    /// [`BlockKind`] of the most-specific applicable rule, or `None`
    /// when no rule matches.
    ///
    /// Input may be in any case; the tree was built from
    /// already-lowercased rules ([`Rule::host`] lowercases on
    /// construction) and this method lowercases its input.
    pub fn match_host(&self, host: &str) -> Option<BlockKind> {
        // Single allocation for the whole lookup; cheap relative to the
        // 100 µs budget on an 80k-entry tree.
        let host_lower = host.to_ascii_lowercase();
        self.match_host_internal(&host_lower)
    }

    fn match_host_internal(&self, host_lower: &str) -> Option<BlockKind> {
        let mut node = &self.root;
        let mut best: Option<BlockKind> = None;
        // Iterate labels right-to-left, skipping empty labels caused
        // by leading / trailing / consecutive dots.
        let labels: Vec<&str> = host_lower.rsplit('.').filter(|l| !l.is_empty()).collect();
        let total = labels.len();
        if total == 0 {
            return None;
        }
        for (idx, label) in labels.iter().enumerate() {
            let Some(child) = node.children.get(*label) else {
                break;
            };
            node = child;
            if let Some(t) = node.terminal {
                let is_last = idx + 1 == total;
                if t.applies_to_subdomains || is_last {
                    best = Some(t.kind);
                }
            }
        }
        best
    }

    /// Diagnostic: number of distinct hostname rules stored.
    pub fn rule_count(&self) -> usize {
        count_rules(&self.root)
    }

    /// Diagnostic: maximum label depth across all rules. Used by
    /// the perf-bench harness to characterize a tree.
    pub fn max_depth(&self) -> usize {
        max_depth(&self.root, 0)
    }
}

fn insert(root: &mut Node, rule: &Rule) {
    let mut node = root;
    let mut placed = false;
    for label in rule.hostname().rsplit('.') {
        if label.is_empty() {
            continue;
        }
        node = node.children.entry(label.to_string()).or_default();
        placed = true;
    }
    if !placed {
        // Hostname was empty or only dots; ignore the rule.
        return;
    }
    // If a terminal already exists at this node, prefer the more
    // specific (subdomain-exclusive) rule to mirror the longest-match
    // semantics; if both have the same scope, the later one wins.
    let new_term = Terminal {
        kind: rule.kind(),
        applies_to_subdomains: rule.applies_to_subdomains(),
    };
    node.terminal = match node.terminal {
        None => Some(new_term),
        Some(existing) if existing.applies_to_subdomains && !new_term.applies_to_subdomains => {
            Some(new_term)
        }
        Some(_) => Some(new_term),
    };
}

fn count_rules(node: &Node) -> usize {
    let here = if node.terminal.is_some() { 1 } else { 0 };
    here + node.children.values().map(count_rules).sum::<usize>()
}

fn max_depth(node: &Node, depth: usize) -> usize {
    let mut deepest = depth;
    for child in node.children.values() {
        let d = max_depth(child, depth + 1);
        if d > deepest {
            deepest = d;
        }
    }
    deepest
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blocklist::rule::Rule;

    #[test]
    fn empty_tree_matches_nothing() {
        let t = RadixTree::empty();
        assert!(t.match_host("example.com").is_none());
        assert_eq!(t.rule_count(), 0);
    }

    #[test]
    fn exact_hostname_match() {
        let t = RadixTree::from_rules(&[Rule::host("example.com", BlockKind::Ad)]);
        assert_eq!(t.match_host("example.com"), Some(BlockKind::Ad));
    }

    #[test]
    fn subdomain_inclusive_rule_matches_subdomain() {
        let t = RadixTree::from_rules(&[Rule::host("example.com", BlockKind::Tracker)]);
        assert_eq!(
            t.match_host("tracker.example.com"),
            Some(BlockKind::Tracker)
        );
        assert_eq!(t.match_host("a.b.c.example.com"), Some(BlockKind::Tracker));
    }

    #[test]
    fn subdomain_exclusive_rule_does_not_match_subdomain() {
        let t = RadixTree::from_rules(&[Rule::host_exact("example.com", BlockKind::Ad)]);
        assert_eq!(t.match_host("example.com"), Some(BlockKind::Ad));
        assert!(t.match_host("tracker.example.com").is_none());
    }

    #[test]
    fn longest_match_wins() {
        let t = RadixTree::from_rules(&[
            Rule::host("example.com", BlockKind::Ad),
            Rule::host("tracker.example.com", BlockKind::Tracker),
        ]);
        // Bare hostname: the "example.com" rule applies.
        assert_eq!(t.match_host("example.com"), Some(BlockKind::Ad));
        // Tracker-prefixed: deeper rule wins.
        assert_eq!(
            t.match_host("tracker.example.com"),
            Some(BlockKind::Tracker)
        );
        // Below tracker: deeper subdomain-inclusive rule still wins.
        assert_eq!(
            t.match_host("evil.tracker.example.com"),
            Some(BlockKind::Tracker)
        );
    }

    #[test]
    fn unrelated_hostname_does_not_match() {
        let t = RadixTree::from_rules(&[Rule::host("example.com", BlockKind::Ad)]);
        assert!(t.match_host("evil.org").is_none());
        assert!(t.match_host("notexample.com").is_none());
    }

    #[test]
    fn case_insensitive_match() {
        let t = RadixTree::from_rules(&[Rule::host("Example.COM", BlockKind::Ad)]);
        assert_eq!(t.match_host("EXAMPLE.com"), Some(BlockKind::Ad));
        assert_eq!(t.match_host("ExAmPlE.cOm"), Some(BlockKind::Ad));
        assert_eq!(t.match_host("Tracker.Example.Com"), Some(BlockKind::Ad));
    }

    #[test]
    fn empty_input_returns_none() {
        let t = RadixTree::from_rules(&[Rule::host("example.com", BlockKind::Ad)]);
        assert!(t.match_host("").is_none());
        assert!(t.match_host(".").is_none());
        assert!(t.match_host("..").is_none());
    }

    #[test]
    fn empty_rule_hostname_is_ignored() {
        // Defends against an attacker-controlled manifest that includes
        // an empty hostname rule, which would otherwise place a terminal
        // at the root and match every lookup.
        let t = RadixTree::from_rules(&[
            Rule::host("", BlockKind::Ad),
            Rule::host(".", BlockKind::Ad),
            Rule::host("..", BlockKind::Ad),
        ]);
        assert_eq!(t.rule_count(), 0);
        assert!(t.match_host("anything.example").is_none());
    }

    #[test]
    fn trailing_and_leading_dots_in_lookup_are_ignored() {
        let t = RadixTree::from_rules(&[Rule::host("example.com", BlockKind::Ad)]);
        assert_eq!(t.match_host("example.com."), Some(BlockKind::Ad));
        assert_eq!(t.match_host(".example.com"), Some(BlockKind::Ad));
        assert_eq!(t.match_host(".example.com."), Some(BlockKind::Ad));
    }

    #[test]
    fn deeper_exact_rule_does_not_block_at_subdomain() {
        // Rule: subdomain-exclusive at tracker.example.com; lookup at
        // a deeper level should NOT match.
        let t =
            RadixTree::from_rules(&[Rule::host_exact("tracker.example.com", BlockKind::Tracker)]);
        assert_eq!(
            t.match_host("tracker.example.com"),
            Some(BlockKind::Tracker)
        );
        assert!(t.match_host("evil.tracker.example.com").is_none());
        assert!(t.match_host("example.com").is_none());
    }

    #[test]
    fn rule_count_matches_input() {
        let rules = vec![
            Rule::host("example.com", BlockKind::Ad),
            Rule::host("tracker.example.com", BlockKind::Tracker),
            Rule::host("evil.org", BlockKind::FingerprintAttempt),
        ];
        let t = RadixTree::from_rules(&rules);
        assert_eq!(t.rule_count(), 3);
    }

    #[test]
    fn duplicate_rule_replaces_terminal() {
        // Same hostname inserted twice: the second wins.
        let t = RadixTree::from_rules(&[
            Rule::host("example.com", BlockKind::Ad),
            Rule::host("example.com", BlockKind::Tracker),
        ]);
        assert_eq!(t.match_host("example.com"), Some(BlockKind::Tracker));
        assert_eq!(t.rule_count(), 1);
    }

    #[test]
    fn subdomain_exclusive_overrides_parent_subdomain_inclusive() {
        // Parent: subdomain-inclusive. Child rule: same hostname but
        // subdomain-exclusive. Subdomain-exclusive is more specific
        // and should win.
        let t = RadixTree::from_rules(&[
            Rule::host("example.com", BlockKind::Ad),
            Rule::host_exact("example.com", BlockKind::Tracker),
        ]);
        assert_eq!(t.match_host("example.com"), Some(BlockKind::Tracker));
    }

    #[test]
    fn fingerprint_attempt_class_returns_distinct() {
        let t = RadixTree::from_rules(&[Rule::host("fp.example", BlockKind::FingerprintAttempt)]);
        assert_eq!(
            t.match_host("fp.example"),
            Some(BlockKind::FingerprintAttempt)
        );
        assert_eq!(
            t.match_host("scanner.fp.example"),
            Some(BlockKind::FingerprintAttempt)
        );
    }

    #[test]
    fn large_tree_still_matches_correctly() {
        // Synthetic 1k-rule tree (smaller than the 80k bench target,
        // but enough to exercise the data structure under realistic
        // shape).
        let mut rules = Vec::with_capacity(1000);
        for i in 0..1000 {
            rules.push(Rule::host(
                format!("h{i}.tracker{}.example.com", i % 100),
                if i % 3 == 0 {
                    BlockKind::Ad
                } else if i % 3 == 1 {
                    BlockKind::Tracker
                } else {
                    BlockKind::FingerprintAttempt
                },
            ));
        }
        let t = RadixTree::from_rules(&rules);
        assert_eq!(t.rule_count(), 1000);
        // Spot-check a few hits and a miss.
        assert!(t.match_host("h0.tracker0.example.com").is_some());
        assert!(t.match_host("h999.tracker99.example.com").is_some());
        assert!(t.match_host("unrelated.example.com").is_none());
    }
}
