//! Storage process — Layer 2, Phase 3 (Modules 13–18).
//!
//! The storage process is the sole gatekeeper for all persistent state.
//! Partition key checked on every read/write — no exceptions
//! (architecture §5.2). Storage data is encrypted at rest via the OS user
//! profile permission posture (0700 dir / 0600 db on Unix); cross-process
//! isolation comes from the sandbox profile (`pb-sandbox`, §5.8).

#![forbid(unsafe_code)]

pub mod gatekeeper;
pub mod partition_key;
pub mod primitives;
pub mod process;
pub mod strict_wipe;

pub use gatekeeper::{Gatekeeper, GatekeeperError, StorageRequest};
pub use partition_key::{
    derive as derive_partition_key, PartitionKey, PARTITION_KEY_DOMAIN, PARTITION_KEY_LEN,
};
pub use primitives::cache::{Cache, CacheEntry};
pub use primitives::cookies::{CookieRecord, Cookies, SameSite};
pub use primitives::local_storage::LocalStorage;
pub use primitives::service_worker::{ServiceWorker, ServiceWorkerRegistration};
pub use primitives::session_storage::SessionStorage;
pub use primitives::{StorageStore, StoreError};
pub use process::{bootstrap, StorageError, StorageProcess, STORAGE_SCHEMA_VERSION};
pub use strict_wipe::{default_stores, wipe_partitions, WipeReport};
