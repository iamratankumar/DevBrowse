//! IndexedDB adapter, Module 16 (deferred).
//!
//! IndexedDB is a versioned, transactional, asynchronous object database
//! with object stores, indexes, key ranges, cursors, and a per-database
//! upgrade ceremony. A correct v1 implementation is out of scope for
//! Module 16 and is deferred to a dedicated future module/phase.
//!
//! This file is intentionally empty of API surface so that:
//!   1. The `pb-storage` crate has the placeholder file already in
//!      place (no later refactor of `primitives/mod.rs` needed when IDB
//!      lands).
//!   2. There is no half-implemented IDB API for callers to mistake for
//!      something that works.
//!
//! When the deferral is lifted:
//!   * Add `pub struct IndexedDb;` and `impl StorageStore for IndexedDb`
//!     so it slots into Module 18 (strict-wipe) the same way the other
//!     primitives do.
//!   * Schema additions go into a new `STORAGE_SCHEMA_VERSION` bump
//!     with a forward-only migration (architecture §7 deferred item:
//!     migration policy).
//!   * Every public op must start with `gatekeeper.authorize(req)?`
//!     (§5.2 invariant).
