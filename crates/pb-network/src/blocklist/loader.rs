//! Blocklist loader, Module 21.
//!
//! Production wiring (deferred) consumes the signed manifest feed
//! from Module 67 (Phase 9 — `pb-update`); v1 ships the trait + an
//! [`InMemoryLoader`] for tests, plus a [`SignedManifestLoader`]
//! stub that returns [`LoaderError::ModuleNotReady`] until Module 67
//! lands.
//!
//! ## Failure modes (per spec)
//!
//!   * **Empty / corrupt manifest after signature verify**: the
//!     scheduler keeps the previous tree live and emits a Module 11
//!     warning. The loader's contract is "return a typed error";
//!     the scheduler decides whether to keep, swap, or warn.
//!   * **Network outage**: same as above — typed error, scheduler
//!     retains live tree.
//!
//! ## Why a trait
//!
//! The trait keeps the scheduler isolated from the production
//! Module 67 surface so:
//!   * tests can drive a deterministic load sequence without any
//!     network, signature, or filesystem dep
//!   * the orchestrator can swap loaders at boot (e.g. an
//!     enterprise-managed loader override)
//
// TODO(Module 67): replace the SignedManifestLoader stub with the
//   real implementation that consumes pb-update's signed-feed
//   surface (Ed25519 verify + format-version gate + atomic swap).

use crate::blocklist::rule::Manifest;
use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;

/// Errors produced by a loader. L27: every Display string is
/// opaque; loader detail (URL of the feed, signature mismatch
/// hex, etc.) flows only through `Error::source()` for in-process
/// tracing.
#[derive(Debug, thiserror::Error)]
pub enum LoaderError {
    /// Production loader's underlying module is not yet wired.
    /// The scheduler treats this as a benign no-op.
    #[error("blocklist loader: module 67 not ready")]
    ModuleNotReady,

    /// Network / IO failure reaching the manifest feed.
    #[error("blocklist loader: transport failure")]
    Transport,

    /// Signature verification failed.
    #[error("blocklist loader: signature mismatch")]
    Signature,

    /// Manifest parsed but failed schema / version validation.
    #[error("blocklist loader: invalid manifest")]
    InvalidManifest,

    /// Manifest's content version is not strictly newer than the
    /// live one. Scheduler treats this as a benign no-op.
    #[error("blocklist loader: no new content")]
    NoNewContent,
}

/// Future returned by a loader. Boxed so the trait stays
/// object-safe.
pub type LoadFuture<'a> = Pin<Box<dyn Future<Output = Result<Manifest, LoaderError>> + Send + 'a>>;

/// Object-safe loader trait. Implementations MUST be `Send + Sync`
/// so the scheduler can hold them behind an `Arc<dyn Loader>` and
/// drive concurrent refreshes if needed (the scheduler currently
/// drives one refresh at a time, but future revisions may add
/// per-track parallelism).
pub trait Loader: Send + Sync + std::fmt::Debug {
    fn load(&self, current_version: u64) -> LoadFuture<'_>;
}

/// In-memory test loader. Returns whichever manifest the test
/// configures via [`InMemoryLoader::set_next`]. Mirrors the
/// production "return Err if no fresh content" contract: if the
/// configured manifest's `content_version <= current_version`, the
/// loader returns [`LoaderError::NoNewContent`].
#[derive(Debug, Default)]
pub struct InMemoryLoader {
    next: Mutex<Option<Result<Manifest, LoaderError>>>,
}

impl InMemoryLoader {
    pub fn new() -> Self {
        Self::default()
    }

    /// Stage the next [`load`] outcome. Test scaffolding only.
    pub fn set_next(&self, outcome: Result<Manifest, LoaderError>) {
        *self.next.lock().expect("loader lock") = Some(outcome);
    }
}

impl Loader for InMemoryLoader {
    fn load(&self, current_version: u64) -> LoadFuture<'_> {
        Box::pin(async move {
            let staged = {
                let mut g = self.next.lock().expect("loader lock");
                g.take()
            };
            match staged {
                Some(Ok(m)) if m.content_version <= current_version => {
                    Err(LoaderError::NoNewContent)
                }
                Some(Ok(m)) => Ok(m),
                Some(Err(e)) => Err(e),
                None => Err(LoaderError::NoNewContent),
            }
        })
    }
}

/// Production loader stub. Always returns
/// [`LoaderError::ModuleNotReady`] in v1 — Module 67 wires the
/// signed-feed implementation in Phase 9.
#[derive(Debug, Default, Clone, Copy)]
pub struct SignedManifestLoader;

impl SignedManifestLoader {
    pub fn new() -> Self {
        Self
    }
}

impl Loader for SignedManifestLoader {
    fn load(&self, _current_version: u64) -> LoadFuture<'_> {
        Box::pin(async move { Err(LoaderError::ModuleNotReady) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blocklist::rule::{BlockKind, Rule};

    fn manifest(version: u64) -> Manifest {
        Manifest {
            format_version: 1,
            content_version: version,
            generated_at_unix: 0,
            host_rules: vec![Rule::host("ads.example", BlockKind::Ad)],
            url_param_rules: vec![],
            cookie_banner_rules: vec![],
        }
    }

    #[tokio::test]
    async fn signed_loader_returns_module_not_ready() {
        let l = SignedManifestLoader::new();
        match l.load(0).await {
            Err(LoaderError::ModuleNotReady) => {}
            other => panic!("expected ModuleNotReady, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn in_memory_loader_returns_staged_manifest() {
        let l = InMemoryLoader::new();
        l.set_next(Ok(manifest(5)));
        let out = l.load(0).await.expect("ok");
        assert_eq!(out.content_version, 5);
    }

    #[tokio::test]
    async fn in_memory_loader_returns_no_new_content_when_stale() {
        let l = InMemoryLoader::new();
        l.set_next(Ok(manifest(1)));
        match l.load(5).await {
            Err(LoaderError::NoNewContent) => {}
            other => panic!("expected NoNewContent, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn in_memory_loader_returns_staged_error() {
        let l = InMemoryLoader::new();
        l.set_next(Err(LoaderError::Signature));
        match l.load(0).await {
            Err(LoaderError::Signature) => {}
            other => panic!("expected Signature, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn in_memory_loader_returns_no_new_content_when_unstaged() {
        let l = InMemoryLoader::new();
        match l.load(0).await {
            Err(LoaderError::NoNewContent) => {}
            other => panic!("expected NoNewContent, got {other:?}"),
        }
    }

    #[test]
    fn loader_error_display_is_opaque() {
        assert_eq!(
            format!("{}", LoaderError::ModuleNotReady),
            "blocklist loader: module 67 not ready"
        );
        assert_eq!(
            format!("{}", LoaderError::Transport),
            "blocklist loader: transport failure"
        );
        assert_eq!(
            format!("{}", LoaderError::Signature),
            "blocklist loader: signature mismatch"
        );
        assert_eq!(
            format!("{}", LoaderError::InvalidManifest),
            "blocklist loader: invalid manifest"
        );
        assert_eq!(
            format!("{}", LoaderError::NoNewContent),
            "blocklist loader: no new content"
        );
    }
}
