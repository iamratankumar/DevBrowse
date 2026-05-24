//! Blocklist refresh scheduler, Module 21.
//!
//! Drives a periodic [`Loader`] call on a 1-hour randomized interval
//! per L25 (the same posture as cohort-watch dependency refreshes —
//! random within a +/- jitter window so the broker fleet does not
//! synchronously hammer the update channel at the top of every
//! hour).
//!
//! ## Failure semantics (per spec)
//!
//!   * `LoaderError::NoNewContent` / `ModuleNotReady`: benign no-op.
//!     Tree stays live, no warning.
//!   * `LoaderError::Transport` / `Signature` / `InvalidManifest`:
//!     tree stays live, scheduler emits a warning via the wired
//!     [`WarningSink`] (Module 11 surface). The scheduler keeps
//!     trying on the next tick.
//!
//! ## Cancellation
//!
//! The scheduler returns a [`SchedulerHandle`] whose drop signals
//! the periodic task to stop. `stop().await` blocks until the
//! task observes the signal and returns. Tests use the synchronous
//! `tick_once()` entrypoint to drive a single refresh deterministically.
//
// TODO(integration with Module 11 warning surface — Module 11 has
//   shipped `crates/pb-identity/src/warnings.rs`): replace the local
//   `WarningSink` placeholder with the pb-identity warning surface.
//   Integration is gated on pb-identity ↔ pb-network IPC wiring
//   which lands with the orchestrator at Phase 11 / Module 80.
// TODO(Module 67): with a real Loader the scheduler periodicity
//   should respect the manifest's signed `valid_through` field.

use crate::blocklist::blocklist::Blocklist;
use crate::blocklist::loader::{Loader, LoaderError};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;
use tokio::task::JoinHandle;

/// Mean refresh interval. 1 hour matches the L25 posture for the
/// blocklist track. Tests drive `tick_once` directly and never
/// observe this constant; production uses it as the centre of the
/// jitter window.
pub const REFRESH_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// Maximum +/- jitter applied to each tick. Keeps the cohort of
/// browsers from pinging the update channel synchronously.
pub const REFRESH_JITTER: Duration = Duration::from_secs(5 * 60);

/// Subscriber for scheduler warnings. Module 11 implements this in
/// production; tests inject a capturing sink.
pub trait WarningSink: Send + Sync + fmt::Debug {
    fn warn(&self, code: &'static str);
}

/// Default sink that drops every warning. Used in tests where the
/// caller does not care about warnings.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopWarningSink;

impl WarningSink for NoopWarningSink {
    fn warn(&self, _code: &'static str) {}
}

/// Capturing sink — for tests + integration harnesses.
#[derive(Debug, Default)]
pub struct CapturingWarningSink {
    codes: std::sync::Mutex<Vec<&'static str>>,
}

impl CapturingWarningSink {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn snapshot(&self) -> Vec<&'static str> {
        self.codes.lock().expect("warn lock").clone()
    }
}

impl WarningSink for CapturingWarningSink {
    fn warn(&self, code: &'static str) {
        self.codes.lock().expect("warn lock").push(code);
    }
}

/// Static stable warning code constants. The code strings are the
/// telemetry-safe identifiers; Display strings stay opaque elsewhere.
pub mod warning_codes {
    pub const TRANSPORT_FAILURE: &str = "blocklist.transport_failure";
    pub const SIGNATURE_FAILURE: &str = "blocklist.signature_failure";
    pub const INVALID_MANIFEST: &str = "blocklist.invalid_manifest";
}

/// One-shot result of a refresh attempt — returned by
/// [`tick_once`] for tests + diagnostic surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TickOutcome {
    /// Manifest swapped; new content version is the second arg.
    Updated { new_content_version: u64 },
    /// Loader said there was no new content.
    NoNewContent,
    /// Loader said its module is not yet ready (production stub).
    NotReady,
    /// Loader returned an error that produced a warning (transport,
    /// signature, invalid). Tree stays live.
    Warned,
}

/// Drive a single refresh against `loader`. Used by the scheduler's
/// internal tick and also by tests.
pub async fn tick_once(
    loader: &Arc<dyn Loader>,
    blocklist: &Arc<Blocklist>,
    warn: &Arc<dyn WarningSink>,
) -> TickOutcome {
    let current = blocklist.content_version();
    match loader.load(current).await {
        Ok(manifest) => {
            blocklist.swap(&manifest);
            TickOutcome::Updated {
                new_content_version: manifest.content_version,
            }
        }
        Err(LoaderError::NoNewContent) => TickOutcome::NoNewContent,
        Err(LoaderError::ModuleNotReady) => TickOutcome::NotReady,
        Err(LoaderError::Transport) => {
            warn.warn(warning_codes::TRANSPORT_FAILURE);
            TickOutcome::Warned
        }
        Err(LoaderError::Signature) => {
            warn.warn(warning_codes::SIGNATURE_FAILURE);
            TickOutcome::Warned
        }
        Err(LoaderError::InvalidManifest) => {
            warn.warn(warning_codes::INVALID_MANIFEST);
            TickOutcome::Warned
        }
    }
}

/// Background scheduler handle. Drop or call `stop().await` to
/// signal the task to exit.
pub struct SchedulerHandle {
    stop: Arc<Notify>,
    join: Option<JoinHandle<()>>,
}

impl SchedulerHandle {
    /// Signal the scheduler to stop and await its exit.
    pub async fn stop(mut self) {
        self.stop.notify_waiters();
        if let Some(j) = self.join.take() {
            let _ = j.await;
        }
    }
}

impl Drop for SchedulerHandle {
    fn drop(&mut self) {
        // Best-effort: notify the task; the runtime will reap it.
        self.stop.notify_waiters();
    }
}

impl fmt::Debug for SchedulerHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SchedulerHandle").finish()
    }
}

/// Spawn the periodic refresh loop. The loop runs on the current
/// tokio runtime; callers must hold the returned [`SchedulerHandle`]
/// for as long as they want refreshes to continue.
///
/// **NOT used by tests.** Tests prefer [`tick_once`] for
/// determinism. Production wiring uses this from
/// [`crate::NetworkCoordinator::start_blocklist_scheduler`] (TODO).
pub fn spawn(
    loader: Arc<dyn Loader>,
    blocklist: Arc<Blocklist>,
    warn: Arc<dyn WarningSink>,
) -> SchedulerHandle {
    let stop = Arc::new(Notify::new());
    let stop_for_task = stop.clone();
    let join = tokio::spawn(async move {
        let mut hasher_seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        loop {
            // Pseudorandom jitter (no `rand` dep). Quality is fine for
            // a fleet-spreading delay; this is not a crypto context.
            // xorshift64*
            hasher_seed ^= hasher_seed << 13;
            hasher_seed ^= hasher_seed >> 7;
            hasher_seed ^= hasher_seed << 17;
            let jitter_secs = (hasher_seed % (REFRESH_JITTER.as_secs() * 2)) as i64
                - REFRESH_JITTER.as_secs() as i64;
            let next = if jitter_secs >= 0 {
                REFRESH_INTERVAL + Duration::from_secs(jitter_secs as u64)
            } else {
                REFRESH_INTERVAL.saturating_sub(Duration::from_secs((-jitter_secs) as u64))
            };
            tokio::select! {
                _ = stop_for_task.notified() => break,
                _ = tokio::time::sleep(next) => {}
            }
            let _ = tick_once(&loader, &blocklist, &warn).await;
        }
    });
    SchedulerHandle {
        stop,
        join: Some(join),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blocklist::loader::InMemoryLoader;
    use crate::blocklist::rule::{BlockKind, Manifest, Rule};

    fn manifest(version: u64, host: &str) -> Manifest {
        Manifest {
            format_version: 1,
            content_version: version,
            generated_at_unix: 0,
            host_rules: vec![Rule::host(host, BlockKind::Ad)],
            url_param_rules: vec![],
            cookie_banner_rules: vec![],
        }
    }

    #[tokio::test]
    async fn tick_once_swaps_when_loader_returns_fresh_manifest() {
        let bl = Blocklist::empty();
        let loader = Arc::new(InMemoryLoader::new());
        loader.set_next(Ok(manifest(5, "ads.example.com")));
        let warn: Arc<dyn WarningSink> = Arc::new(NoopWarningSink);
        let loader_dyn: Arc<dyn Loader> = loader.clone();
        let outcome = tick_once(&loader_dyn, &bl, &warn).await;
        assert_eq!(
            outcome,
            TickOutcome::Updated {
                new_content_version: 5
            }
        );
        assert_eq!(bl.match_host("ads.example.com"), Some(BlockKind::Ad));
        assert_eq!(bl.content_version(), 5);
    }

    #[tokio::test]
    async fn tick_once_keeps_tree_on_no_new_content() {
        let bl = Blocklist::empty();
        bl.swap(&manifest(2, "first.example"));
        let loader = Arc::new(InMemoryLoader::new());
        loader.set_next(Ok(manifest(2, "first.example"))); // same version
        let warn: Arc<dyn WarningSink> = Arc::new(NoopWarningSink);
        let loader_dyn: Arc<dyn Loader> = loader.clone();
        let outcome = tick_once(&loader_dyn, &bl, &warn).await;
        assert_eq!(outcome, TickOutcome::NoNewContent);
        // Live tree intact.
        assert_eq!(bl.match_host("first.example"), Some(BlockKind::Ad));
    }

    #[tokio::test]
    async fn tick_once_warns_on_transport_failure() {
        let bl = Blocklist::from_manifest(&manifest(1, "live.example"));
        let loader = Arc::new(InMemoryLoader::new());
        loader.set_next(Err(LoaderError::Transport));
        let warn = Arc::new(CapturingWarningSink::new());
        let loader_dyn: Arc<dyn Loader> = loader.clone();
        let warn_dyn: Arc<dyn WarningSink> = warn.clone();
        let outcome = tick_once(&loader_dyn, &bl, &warn_dyn).await;
        assert_eq!(outcome, TickOutcome::Warned);
        assert_eq!(warn.snapshot(), vec![warning_codes::TRANSPORT_FAILURE]);
        // Tree stays live.
        assert_eq!(bl.match_host("live.example"), Some(BlockKind::Ad));
    }

    #[tokio::test]
    async fn tick_once_warns_on_signature_failure() {
        let bl = Blocklist::from_manifest(&manifest(1, "live.example"));
        let loader = Arc::new(InMemoryLoader::new());
        loader.set_next(Err(LoaderError::Signature));
        let warn = Arc::new(CapturingWarningSink::new());
        let loader_dyn: Arc<dyn Loader> = loader.clone();
        let warn_dyn: Arc<dyn WarningSink> = warn.clone();
        let outcome = tick_once(&loader_dyn, &bl, &warn_dyn).await;
        assert_eq!(outcome, TickOutcome::Warned);
        assert_eq!(warn.snapshot(), vec![warning_codes::SIGNATURE_FAILURE]);
        assert_eq!(bl.match_host("live.example"), Some(BlockKind::Ad));
    }

    #[tokio::test]
    async fn tick_once_warns_on_invalid_manifest() {
        let bl = Blocklist::from_manifest(&manifest(1, "live.example"));
        let loader = Arc::new(InMemoryLoader::new());
        loader.set_next(Err(LoaderError::InvalidManifest));
        let warn = Arc::new(CapturingWarningSink::new());
        let loader_dyn: Arc<dyn Loader> = loader.clone();
        let warn_dyn: Arc<dyn WarningSink> = warn.clone();
        let outcome = tick_once(&loader_dyn, &bl, &warn_dyn).await;
        assert_eq!(outcome, TickOutcome::Warned);
        assert_eq!(warn.snapshot(), vec![warning_codes::INVALID_MANIFEST]);
        // Tree stays live across a corrupt-manifest load — fail-open
        // for navigation, not fail-closed-on-empty (per spec edge
        // case "Empty / corrupt manifest after signature verify:
        // keep previous tree live").
        assert_eq!(bl.match_host("live.example"), Some(BlockKind::Ad));
        assert_eq!(bl.content_version(), 1);
    }

    #[tokio::test]
    async fn tick_once_silent_on_module_not_ready() {
        // Production loader stub returns ModuleNotReady — scheduler
        // treats it as benign no-op, no warning.
        let bl = Blocklist::empty();
        let loader = Arc::new(InMemoryLoader::new());
        loader.set_next(Err(LoaderError::ModuleNotReady));
        let warn = Arc::new(CapturingWarningSink::new());
        let loader_dyn: Arc<dyn Loader> = loader.clone();
        let warn_dyn: Arc<dyn WarningSink> = warn.clone();
        let outcome = tick_once(&loader_dyn, &bl, &warn_dyn).await;
        assert_eq!(outcome, TickOutcome::NotReady);
        assert!(warn.snapshot().is_empty());
    }
}
