// Partition key derivation — Module 12.
// Standalone, auditable hash function:
//   key = hash( site_origin + identity_profile_id + context_id )
// Technology: SHA-256 via sha2 crate.
