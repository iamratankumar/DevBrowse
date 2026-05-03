//! Property-based test scaffolding, Module 0.5 subtask 4.
//!
//! Three property invariants are exposed here. Each one is a pure
//! `proptest::prelude::Strategy` plus a free function that runs the
//! corresponding `proptest!` block. Tests in production crates call the
//! free function from a `#[test]` so the property check participates in
//! the normal `cargo test` flow.
//!
//! Properties:
//!   1. Partition-key derivation is injective on its (origin, profile,
//!      context) inputs (architecture §5.2).
//!   2. IPC framing round-trips through DuplexConnection for arbitrary
//!      byte sequences within MAX_MESSAGE_BYTES (Module 4 framing).
//!   3. Vault format round-trip — placeholder for Module 83 (Phase 11.5).
//!      The strategy and assertion shape are fixed now so Module 83 has a
//!      drop-in target; the body returns immediately because the vault
//!      type does not yet exist.

use proptest::prelude::*;
use uuid::Uuid;

/// Strategy: arbitrary site origin string.
///
/// The production gatekeeper trusts upstream normalization so any
/// non-empty string is valid input. We bias toward shorter strings to
/// keep runtime predictable.
pub fn arb_site_origin() -> impl Strategy<Value = String> {
    "[a-z0-9.-]{1,32}".prop_map(|s| s.to_string())
}

/// Strategy: arbitrary UUID. Generated from a u128 so proptest's shrinker
/// can produce simpler counterexamples.
pub fn arb_uuid() -> impl Strategy<Value = Uuid> {
    any::<u128>().prop_map(Uuid::from_u128)
}

/// Strategy: arbitrary IPC payload up to `max` bytes (must be
/// `<= MAX_MESSAGE_BYTES` per the framing contract).
pub fn arb_ipc_payload(max: usize) -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(any::<u8>(), 0..=max)
}

/// Run the partition-key injectivity property.
///
/// Two distinct (origin, profile, context) triples must derive distinct
/// keys with overwhelming probability. SHA-256 makes a collision a
/// cryptographic-failure event, so this is effectively a smoke test for
/// the encoding (length-prefix correctness, domain-separation label
/// presence).
pub fn run_partition_key_injectivity_property() {
    let mut runner = proptest::test_runner::TestRunner::default();
    runner
        .run(
            &(
                arb_site_origin(),
                arb_uuid(),
                arb_uuid(),
                arb_site_origin(),
                arb_uuid(),
                arb_uuid(),
            ),
            |(o1, p1, c1, o2, p2, c2)| {
                let k1 = pb_storage::derive_partition_key(&o1, p1, c1);
                let k2 = pb_storage::derive_partition_key(&o2, p2, c2);
                let triples_equal = (o1.as_str(), p1, c1) == (o2.as_str(), p2, c2);
                let keys_equal = k1.as_bytes() == k2.as_bytes();
                prop_assert_eq!(
                    triples_equal,
                    keys_equal,
                    "injectivity violated: same triple iff same key"
                );
                Ok(())
            },
        )
        .expect("partition-key derivation must be injective on inputs");
}

/// Run the IPC framing round-trip property.
///
/// For arbitrary bytes within MAX_MESSAGE_BYTES, sending then receiving
/// over a DuplexConnection yields the original payload. Catches any
/// regression in the length-prefix encoding or partial-read handling.
pub fn run_ipc_framing_roundtrip_property() {
    // The proptest runner is synchronous; we drive a tokio runtime per
    // case. Cap the payload at 64 KiB so wall-clock stays under the
    // Module 0.5 30-second budget even with the default proptest
    // 256 cases.
    let mut runner = proptest::test_runner::TestRunner::default();
    runner
        .run(&arb_ipc_payload(64 * 1024), |payload| {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio runtime");
            let received: Vec<u8> = rt.block_on(async {
                let (mut a, mut b) = pb_ipc::testkit::DuplexConnection::pair();
                a.send(&payload).await.expect("send");
                b.recv().await.expect("recv")
            });
            prop_assert_eq!(payload, received);
            Ok(())
        })
        .expect("framing must round-trip arbitrary bytes");
}

/// Placeholder for Module 83 (Phase 11.5) vault format round-trip.
///
/// The vault type does not yet exist. When Module 83 lands its
/// `VaultBlob` type (or whatever it ends up named), this function must
/// be filled in with a proper round-trip property. Until then, calling
/// it is a no-op so phase-4-onward modules can wire the call into their
/// own test files without an "unknown function" error.
//
// TODO(Module 83): swap the body for a real proptest! block that
//   serializes a randomly-generated vault, deserializes it, and asserts
//   structural equality. Coordinate with Module 83 on the public type.
pub fn run_vault_roundtrip_property() {
    // intentional no-op until Module 83 ships a vault type.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partition_key_property_holds() {
        run_partition_key_injectivity_property();
    }

    #[test]
    fn ipc_framing_property_holds() {
        run_ipc_framing_roundtrip_property();
    }

    #[test]
    fn vault_roundtrip_placeholder_runs() {
        // Will be replaced with a real assertion when Module 83 ships.
        run_vault_roundtrip_property();
    }
}
