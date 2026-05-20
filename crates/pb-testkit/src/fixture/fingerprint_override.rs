//! `fixture::fingerprint_override` — Module 26 harness.
//!
//! Drives `FingerprintOverride::install` across every `JsContext` for a
//! given (Mode, profile_id) pair and records every invocation so the
//! caller can assert the *context-inert* invariant (output cannot vary
//! by JsContext for fixed mode + profile_id).
//!
//! Pre-empts:
//!   * Phase 5.5 (Modules 35.1-35.4) Strict-mode hardening — the
//!     letterboxing / 100 ms timer quantum / disabled-by-default API
//!     overrides need to assert "Strict observed identical output
//!     across every JS scope"; this harness is the shared driver.
//!   * Phase 10 adversarial fingerprint suite — the CreepJS /
//!     FPStandard probes will iterate every per-surface override
//!     under both modes; this harness is the fixture they consume.
//!
//! The fixture is shaped around two pieces:
//!   * [`FingerprintOverrideHarness`] — builds an `OverrideContext`
//!     per `JsContext` and calls `install` on the supplied override.
//!     Returns the recorded invocations for assertion.
//!   * [`RecordingFingerprintOverride`] — reusable mock that records
//!     every install so a test can verify the bridge wired it into
//!     every context without writing the recording boilerplate.
//
// TODO(Phase 5.5 / Module 35.2): when the Strict timer-quantizer hook
//   lands, extend the harness with `install_strict_only` so the L41
//   "Strict cannot be loosened by user settings" enforcement test can
//   drive only the Strict surface.
// TODO(Phase 10 / Module 71+): the adversarial probes will want a
//   variant that takes a slice of overrides and installs each in
//   turn under a single OverrideContext — add when the first probe
//   module needs it.

use pb_fingerprint::{FingerprintOverride, JsContext, OverrideContext, WebIdlSurface};
use std::sync::Mutex;
use uuid::Uuid;

/// One recorded install: the override's declared surface plus the
/// (mode, profile_id, js_context) triple it was invoked under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedInstall {
    pub surface: WebIdlSurface,
    pub mode: pb_config::Mode,
    pub profile_id: Uuid,
    pub js_context: JsContext,
}

/// Harness that simulates the libxul FFI bridge: installs the
/// supplied override into every [`JsContext::ALL`] variant under a
/// fixed (mode, profile_id) pair. Cheap to construct; no I/O.
#[derive(Debug, Clone)]
pub struct FingerprintOverrideHarness {
    mode: pb_config::Mode,
    profile_id: Uuid,
}

impl FingerprintOverrideHarness {
    /// Build a harness with the given mode + profile id. The
    /// profile_id is intentionally a raw `Uuid` because
    /// `pb-fingerprint` is L12-leaf-bound and cannot import
    /// `pb-identity`; callers wanting a real `IdentityProfile` can
    /// pair this with [`super::profile`] / [`super::profile_strict`].
    pub fn new(mode: pb_config::Mode, profile_id: Uuid) -> Self {
        Self { mode, profile_id }
    }

    /// Convenience: Standard-mode harness with a stable test UUID.
    /// Use [`Self::new`] for tests that need a fresh CSPRNG id.
    pub fn standard() -> Self {
        Self::new(pb_config::Mode::Standard, fixed_test_uuid())
    }

    /// Convenience: Strict-mode harness with a stable test UUID.
    pub fn strict() -> Self {
        Self::new(pb_config::Mode::Strict, fixed_test_uuid())
    }

    /// Install `ovr` into every `JsContext::ALL` variant. Returns the
    /// list of OverrideContexts the override saw, in `JsContext::ALL`
    /// order — useful for asserting the bridge reached every scope.
    pub fn install_into_every_context(
        &self,
        ovr: &dyn FingerprintOverride,
    ) -> Vec<OverrideContext> {
        JsContext::ALL
            .iter()
            .map(|jsc| {
                let ctx = OverrideContext::new(self.mode, self.profile_id, *jsc);
                ovr.install(&ctx);
                ctx
            })
            .collect()
    }
}

/// Recording mock that captures every install. Implements
/// [`FingerprintOverride`] so the harness (or any other driver) can
/// invoke it the same way the production bridge would.
///
/// The recorded surface is configurable so a single test can exercise
/// every [`WebIdlSurface`] variant by spawning one `RecordingFingerprintOverride`
/// per surface.
#[derive(Debug)]
pub struct RecordingFingerprintOverride {
    surface: WebIdlSurface,
    installs: Mutex<Vec<RecordedInstall>>,
}

impl RecordingFingerprintOverride {
    pub fn new(surface: WebIdlSurface) -> Self {
        Self {
            surface,
            installs: Mutex::new(Vec::new()),
        }
    }

    /// Snapshot the recorded installs. Returns a clone; the internal
    /// buffer keeps growing if more installs land afterwards.
    pub fn installs(&self) -> Vec<RecordedInstall> {
        self.installs.lock().unwrap().clone()
    }

    /// Count without cloning — handy for "did the bridge reach every
    /// scope" style assertions.
    pub fn install_count(&self) -> usize {
        self.installs.lock().unwrap().len()
    }
}

impl FingerprintOverride for RecordingFingerprintOverride {
    fn surface(&self) -> WebIdlSurface {
        self.surface
    }

    fn install(&self, ctx: &OverrideContext) {
        self.installs.lock().unwrap().push(RecordedInstall {
            surface: self.surface,
            mode: ctx.mode(),
            profile_id: ctx.profile_id(),
            js_context: ctx.js_context(),
        });
    }
}

/// Free-function shortcut so call sites read
/// `fixture::fingerprint_override_harness(Mode::Strict)` instead of
/// `FingerprintOverrideHarness::new(...)`. Mirrors the `fixture::profile`
/// convention.
pub fn fingerprint_override_harness(mode: pb_config::Mode) -> FingerprintOverrideHarness {
    FingerprintOverrideHarness::new(mode, fixed_test_uuid())
}

/// Stable UUID for deterministic harness construction. Not real
/// CSPRNG output — tests that need a fresh id should pass their own
/// to `FingerprintOverrideHarness::new`.
fn fixed_test_uuid() -> Uuid {
    Uuid::parse_str("00000000-0000-4000-8000-00000000fb26").unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn harness_installs_into_every_js_context() {
        let harness = FingerprintOverrideHarness::standard();
        let ovr = RecordingFingerprintOverride::new(WebIdlSurface::Canvas);

        let contexts = harness.install_into_every_context(&ovr);

        assert_eq!(contexts.len(), JsContext::ALL.len());
        assert_eq!(ovr.install_count(), JsContext::ALL.len());

        let installs = ovr.installs();
        for (i, jsc) in JsContext::ALL.iter().enumerate() {
            assert_eq!(installs[i].js_context, *jsc);
            assert_eq!(installs[i].surface, WebIdlSurface::Canvas);
        }
    }

    #[test]
    fn harness_preserves_mode_and_profile_id_across_contexts() {
        // The context-inert invariant from outside: every install
        // saw the same (mode, profile_id). Only js_context varies.
        let pid = Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap();
        let harness = FingerprintOverrideHarness::new(pb_config::Mode::Strict, pid);
        let ovr = RecordingFingerprintOverride::new(WebIdlSurface::Timers);

        harness.install_into_every_context(&ovr);

        for rec in ovr.installs() {
            assert_eq!(rec.mode, pb_config::Mode::Strict);
            assert_eq!(rec.profile_id, pid);
        }
    }

    #[test]
    fn standard_and_strict_helpers_carry_the_right_mode() {
        let s_ovr = RecordingFingerprintOverride::new(WebIdlSurface::Navigator);
        let r_ovr = RecordingFingerprintOverride::new(WebIdlSurface::Navigator);

        FingerprintOverrideHarness::standard().install_into_every_context(&s_ovr);
        FingerprintOverrideHarness::strict().install_into_every_context(&r_ovr);

        assert!(s_ovr
            .installs()
            .iter()
            .all(|r| r.mode == pb_config::Mode::Standard));
        assert!(r_ovr
            .installs()
            .iter()
            .all(|r| r.mode == pb_config::Mode::Strict));
    }

    #[test]
    fn free_function_matches_struct_constructor() {
        let a = fingerprint_override_harness(pb_config::Mode::Standard);
        let b = FingerprintOverrideHarness::standard();
        // Same stable seed => same profile_id => harnesses produce
        // identical contexts.
        let ovr_a = RecordingFingerprintOverride::new(WebIdlSurface::Audio);
        let ovr_b = RecordingFingerprintOverride::new(WebIdlSurface::Audio);
        a.install_into_every_context(&ovr_a);
        b.install_into_every_context(&ovr_b);
        assert_eq!(ovr_a.installs(), ovr_b.installs());
    }

    #[test]
    fn recording_override_reports_its_declared_surface() {
        let ovr = RecordingFingerprintOverride::new(WebIdlSurface::Fonts);
        assert_eq!(ovr.surface(), WebIdlSurface::Fonts);
    }

    // ── Cross-phase contract test (Module 27) ─────────────────────────────
    //
    // Proves the harness drives a *real* `FingerprintOverride` impl —
    // not just the in-fixture `RecordingFingerprintOverride` mock —
    // so Phase 5.5 (Strict hardening) and Phase 10 (adversarial
    // fingerprint suite) can rely on this exact pattern. If the
    // harness ever drifts from the production trait shape, this
    // test breaks before downstream phases consume it.

    #[test]
    fn harness_drives_module_27_canvas_override_across_modes() {
        use pb_fingerprint::{CanvasOverride, CanvasReadbackPolicy};

        // Standard: CanvasOverride is registered structurally but
        // carries a NativePassThrough policy (Strict-only
        // normalization decision; see canvas.rs module doc).
        let standard_ovr = CanvasOverride::new(pb_config::Mode::Standard);
        let ctxs = FingerprintOverrideHarness::standard().install_into_every_context(&standard_ovr);
        assert_eq!(ctxs.len(), JsContext::ALL.len());
        assert_eq!(standard_ovr.surface(), WebIdlSurface::Canvas);
        assert!(matches!(
            standard_ovr.policy(),
            CanvasReadbackPolicy::NativePassThrough
        ));
        assert_eq!(standard_ovr.profile(), None);

        // Strict: same registration shape, but the policy now
        // carries the locked profile and `install` (when libxul is
        // wired) will activate the normalized rasterizer hook.
        let strict_ovr = CanvasOverride::new(pb_config::Mode::Strict);
        let ctxs = FingerprintOverrideHarness::strict().install_into_every_context(&strict_ovr);
        assert_eq!(ctxs.len(), JsContext::ALL.len());
        assert_eq!(strict_ovr.surface(), WebIdlSurface::Canvas);
        assert!(matches!(
            strict_ovr.policy(),
            CanvasReadbackPolicy::NormalizedRasterizer(_)
        ));
        assert!(strict_ovr.profile().is_some());
    }
}
