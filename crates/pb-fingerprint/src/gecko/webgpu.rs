//! Module 35.6 — WebGPU adapter normalization.
//!
//! Locks `navigator.gpu.requestAdapter()` adapter info (vendor /
//! architecture / driver / features / limits) under both modes.
//! WebGPU is the next-gen GPU API (Chrome 113+, Safari 18+,
//! Firefox 141 in progress); Tor and Mullvad disable it entirely.
//! DevBrowse goes structurally ahead: keep WebGPU USABLE in Strict
//! and lock the fingerprintable metadata.
//!
//! Architecture references:
//!   * **L8** — Gecko WebIDL override points only; the
//!     `requestAdapter` resolution + `GPUAdapter.info` getter +
//!     `features` / `limits` accessors are intercepted below the
//!     JS surface so workers (`navigator.gpu` is exposed in
//!     workers per spec) share a single policy.
//!   * **§3.3 / §3.2** — per-Mode normalization. Strict ships
//!     a Mozilla-cohort lock (matches Module 28 WebGL vendor);
//!     Standard ships a bucketed vendor class so compute-routing
//!     UX is preserved while the cohort identity envelope stays
//!     analyzable.
//!   * **§5.5** — central fingerprint surface bucketing.
//!   * **threat-model A1** — WebGPU adapter info is the next-gen
//!     equivalent of `WEBGL_debug_renderer_info` (one of the
//!     highest-entropy GPU-identity fingerprint surfaces); Module
//!     35.6 closes the channel before it ships at scale.
//!
//! ## Mode-applicability (locked v1.23)
//!
//!   * **Strict** — `WebGpuReadbackPolicy::CohortLocked(&LOCKED_WEBGPU_PROFILE)`.
//!     vendor = `"Mozilla"`, architecture / driver / features /
//!     limits all pinned to the cohort base. Every Strict
//!     DevBrowse user sees identical adapter info.
//!   * **Standard** — `WebGpuReadbackPolicy::Bucketed(&LOCKED_WEBGPU_PROFILE)`.
//!     The architecture / driver / features / limits fields stay
//!     pinned to the same cohort base (address-identical to
//!     Strict); only the vendor field is overridden by libxul-side
//!     bucketing of the host GPU's actual vendor into one of
//!     {Intel, NVIDIA, AMD, Apple, Other}. Compute-routing UX is
//!     preserved at the cost of a small cohort split on the
//!     vendor surface alone.
//!
//! ## Cross-module cohort unification with Module 28 (WebGL)
//!
//! `LOCKED_WEBGPU_PROFILE.vendor == "Mozilla" ==
//! LOCKED_WEBGL_PROFILE.vendor` is the load-bearing invariant for
//! Strict cohort identity: a renderer claiming "Mozilla GPU" via
//! WebGL and "Apple GPU" via WebGPU is a contradiction sites
//! detect. The cross-coupling regression test in this module pins
//! the agreement.
//
// TODO(libxul FFI bridge — pb-browser Phase 11 / Module 80;
//   verified by Module 69 in Phase 9): the WebGPU hook lands
//   alongside the libxul tag. On Strict-mode renderers,
//   `requestAdapter` resolves to a GPUAdapter whose info getter
//   returns `LOCKED_WEBGPU_PROFILE.vendor` ("Mozilla"); on
//   Standard, the bridge probes the host GPU vendor and returns
//   the bucketed `WebGpuVendor` mapping (Intel / NVIDIA / AMD /
//   Apple / Other). Features list + limits map are returned from
//   `LOCKED_WEBGPU_PROFILE` regardless of mode.
// Module 28 (WebGL) cross-coupling has shipped: the regression test
//   `vendor_matches_module_28_webgl_cohort` asserts the
//   `&'static str` "Mozilla" appears in both profile statics.
//   This is the structural anti-contradiction lock — a future
//   change to either module's vendor string fails the test and
//   forces the cohort migration to land in lockstep.
// Module 36 (pb-gpu coordinator) has shipped: pb-gpu owns its own
//   cohort-locked statics — `COHORT_VENDOR` ("Mozilla"),
//   `LOCKED_GPU_FEATURES` (empty), `LOCKED_GPU_LIMITS` (WebGPU
//   spec minima). The paired regression tests
//   `cohort_vendor_matches_module_35_6` /
//   `locked_gpu_features_matches_module_35_6` /
//   `locked_limits_match_module_35_6_webgpu_spec_minima` in
//   crates/pb-gpu/src/coordinator.rs assert byte equality with
//   `LOCKED_WEBGPU_PROFILE.vendor.as_str()` /
//   `.features.len()` / every `.limits` field on this side.
//   L12 forbids pb-gpu from importing pb-fingerprint, so the
//   alignment is enforced by paired literal-value assertions
//   on both sides (same pattern as
//   `DEVBROWSE_USER_AGENT` / `LOCKED_USER_AGENT` between
//   pb-network and Module 34). Drift in either direction fails
//   CI before merge.
// TODO(Phase 10 / Module 71+): adversarial-fingerprint probes
//   assert `navigator.gpu.requestAdapter().info.vendor == "Mozilla"`
//   in Strict and one-of-five in Standard, regardless of the
//   host's actual GPU.
// Module 35.4 (settings-lock audit) has shipped: the L41 invariant —
//   no user setting can flip Strict back to native WebGPU
//   metadata. The structural lock here is `for_mode(Mode::Strict)`
//   always returns `CohortLocked`; Module 35.4's audit pass
//   extends to this module's call sites.

use crate::interface::{FingerprintOverride, JsContext, OverrideContext, WebIdlSurface};
use pb_config::Mode;

// ── Vendor enumeration ───────────────────────────────────────────────────

/// JS-observable WebGPU vendor class.
///
/// Strict locks to `Mozilla` (matches Module 28 WebGL cohort
/// vendor). Standard buckets the host GPU's actual vendor into
/// one of the 5 hardware classes for compute-routing UX; the
/// host's specific GPU model / driver version is hidden behind
/// the bucket.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WebGpuVendor {
    /// Strict cohort lock. Address-identical to the Module 28
    /// WebGL vendor; anti-contradiction asserted by the
    /// cross-coupling test.
    Mozilla,
    /// Standard bucket: Intel-family integrated / discrete GPUs.
    Intel,
    /// Standard bucket: NVIDIA discrete GPUs.
    NVIDIA,
    /// Standard bucket: AMD integrated / discrete GPUs.
    AMD,
    /// Standard bucket: Apple Silicon GPUs.
    Apple,
    /// Standard bucket: every other vendor (Qualcomm Adreno, ARM
    /// Mali, Imagination PowerVR, Intel Arc, etc.) collapses to
    /// a single `Other` value.
    Other,
}

impl WebGpuVendor {
    /// The JS-observable string returned by `GPUAdapterInfo.vendor`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mozilla => "Mozilla",
            Self::Intel => "Intel",
            Self::NVIDIA => "NVIDIA",
            Self::AMD => "AMD",
            Self::Apple => "Apple",
            Self::Other => "Other",
        }
    }

    /// The 5 Standard-mode bucketed vendor classes (Mozilla is
    /// Strict-only). Iterated by the libxul bridge at adapter
    /// resolve time to look up which bucket the host GPU falls
    /// into.
    pub const STANDARD_BUCKETS: &'static [WebGpuVendor] = &[
        Self::Intel,
        Self::NVIDIA,
        Self::AMD,
        Self::Apple,
        Self::Other,
    ];
}

// ── Locked profile ───────────────────────────────────────────────────────

/// Cohort-locked WebGPU adapter parameters.
///
/// The fields that DO NOT vary by mode (architecture / driver /
/// features / limits) carry the cohort base used by BOTH modes.
/// The `vendor` field carries the Strict-mode lock; Standard
/// overrides it via libxul-side bucketing at adapter resolve time
/// (see [`WebGpuReadbackPolicy::Bucketed`]).
///
/// `Copy` is intentional — read on every adapter resolve.
///
/// Note: `Eq` / `Hash` derives are safe here (no `f32` fields,
/// unlike `AudioProfile`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WebGpuProfile {
    /// Strict cohort vendor (`"Mozilla"`). Standard overrides at
    /// resolve time per [`WebGpuReadbackPolicy::Bucketed`].
    pub vendor: WebGpuVendor,
    /// `GPUAdapterInfo.architecture`. Empty string `""` is
    /// web-compatible and matches the Tor / Mullvad posture
    /// (where they would expose this).
    pub architecture: &'static str,
    /// `GPUAdapterInfo.driver`. Empty string for cohort safety;
    /// driver-version leaks identify the host.
    pub driver: &'static str,
    /// `GPUAdapterInfo.description`. Empty string for cohort
    /// safety.
    pub description: &'static str,
    /// `GPUAdapter.features` (`Set<DOMString>`) — the cohort
    /// allowlist of WebGPU features the adapter advertises.
    /// Conservative v1 list: only the spec-mandated baseline; no
    /// optional features (which would split the cohort along
    /// hardware lines).
    pub features: &'static [&'static str],
    /// `GPUAdapter.limits` (`GPUSupportedLimits`). Spec-minimum
    /// values: every WebGPU-supporting adapter must support at
    /// least these, so the cohort is indistinguishable from a
    /// minimal-spec implementation.
    pub limits: WebGpuLimits,
}

/// Cohort-locked `GPUSupportedLimits`. Values pinned to the WebGPU
/// spec minima — every conformant adapter must support at least
/// these, so the cohort indistinguishability claim does not
/// depend on the host actually exceeding them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WebGpuLimits {
    pub max_texture_dimension_1d: u32,
    pub max_texture_dimension_2d: u32,
    pub max_texture_dimension_3d: u32,
    pub max_texture_array_layers: u32,
    pub max_bind_groups: u32,
    pub max_buffer_size: u64,
    pub max_compute_workgroup_size_x: u32,
    pub max_compute_workgroup_size_y: u32,
    pub max_compute_workgroup_size_z: u32,
    pub max_compute_invocations_per_workgroup: u32,
}

/// The single cohort-safe WebGPU profile.
///
/// `static` (not `const`): cohort consumers compare by address
/// (`std::ptr::eq`) to prove every renderer is reading the same
/// singleton. The same reasoning as Module 27 / Module 28's
/// locked-profile statics.
pub static LOCKED_WEBGPU_PROFILE: WebGpuProfile = WebGpuProfile {
    vendor: WebGpuVendor::Mozilla,
    architecture: "",
    driver: "",
    description: "",
    features: &[],
    limits: WebGpuLimits {
        // WebGPU spec minima — every WebGPU adapter MUST support
        // at least these (https://www.w3.org/TR/webgpu/#limits).
        max_texture_dimension_1d: 8192,
        max_texture_dimension_2d: 8192,
        max_texture_dimension_3d: 2048,
        max_texture_array_layers: 256,
        max_bind_groups: 4,
        max_buffer_size: 268_435_456, // 256 MiB
        max_compute_workgroup_size_x: 256,
        max_compute_workgroup_size_y: 256,
        max_compute_workgroup_size_z: 64,
        max_compute_invocations_per_workgroup: 256,
    },
};

// ── Per-Mode policy ──────────────────────────────────────────────────────

/// Per-Mode WebGPU readback policy.
///
/// Both variants reference the SAME `&LOCKED_WEBGPU_PROFILE`
/// static (the cohort-base architecture / driver / features /
/// limits are mode-invariant). The variant determines how the
/// vendor field is resolved at adapter request time:
///   * `CohortLocked` (Strict) — return `profile.vendor` as-is
///     (`"Mozilla"`).
///   * `Bucketed` (Standard) — libxul probes the host GPU vendor
///     and returns the matching `WebGpuVendor::STANDARD_BUCKETS`
///     entry; architecture / driver / features / limits still
///     come from the locked profile.
///
/// `Eq` / `Hash` derived (no `f32` fields — unlike Modules 27 /
/// 28 / 29 after the v1.23 farbling refactor).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WebGpuReadbackPolicy {
    /// Strict: every field (including vendor) comes from
    /// `profile`. Cohort identity is `"Mozilla"`.
    CohortLocked(&'static WebGpuProfile),
    /// Standard: every field EXCEPT vendor comes from `profile`;
    /// vendor is bucketed by the libxul bridge from the host
    /// GPU's actual vendor.
    Bucketed(&'static WebGpuProfile),
}

impl WebGpuReadbackPolicy {
    /// Locked snapshot for `mode`:
    ///   * `Mode::Standard` -> `Bucketed(&LOCKED_WEBGPU_PROFILE)`
    ///   * `Mode::Strict`   -> `CohortLocked(&LOCKED_WEBGPU_PROFILE)`
    pub fn for_mode(mode: Mode) -> Self {
        match mode {
            Mode::Standard => Self::Bucketed(&LOCKED_WEBGPU_PROFILE),
            Mode::Strict => Self::CohortLocked(&LOCKED_WEBGPU_PROFILE),
        }
    }

    /// The cohort-base profile this policy reads non-vendor fields
    /// from. Both variants reference the same `&LOCKED_WEBGPU_PROFILE`
    /// static — only the vendor-resolution semantics differ.
    pub fn profile(&self) -> &'static WebGpuProfile {
        match self {
            Self::CohortLocked(p) | Self::Bucketed(p) => p,
        }
    }
}

// ── WebGPU surface enumeration ───────────────────────────────────────────

/// Every JS pathway the libxul WebGPU bridge must wire.
///
/// The Strict hook overrides every variant's return value with
/// the cohort-locked profile data; Standard overrides every
/// variant except the vendor case, which routes through the
/// host-bucketed value. Missing a variant leaves a Strict
/// fingerprint leak.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WebGpuSurface {
    /// `navigator.gpu.requestAdapter(options?)` — the entry
    /// point. Returns a `GPUAdapter` whose info / features /
    /// limits accessors flow through the variants below.
    RequestAdapter,
    /// `GPUAdapter.info` (a `GPUAdapterInfo` dictionary with
    /// `vendor` / `architecture` / `device` / `description`).
    AdapterInfo,
    /// `GPUAdapter.features` (a `Set<DOMString>` of supported
    /// feature names).
    AdapterFeatures,
    /// `GPUAdapter.limits` (a `GPUSupportedLimits` map).
    AdapterLimits,
    /// `GPUDevice.lost` (a `Promise<GPUDeviceLostInfo>`). The
    /// resolution timing is a side channel; the libxul bridge
    /// resolves it deterministically per-cohort.
    DeviceLost,
}

impl WebGpuSurface {
    /// Every surface the FFI bridge must wire.
    pub const ALL: &'static [WebGpuSurface] = &[
        Self::RequestAdapter,
        Self::AdapterInfo,
        Self::AdapterFeatures,
        Self::AdapterLimits,
        Self::DeviceLost,
    ];
}

// ── FingerprintOverride impl ─────────────────────────────────────────────

/// Concrete `FingerprintOverride` for `WebIdlSurface::WebGpu`.
///
/// Construct with `WebGpuOverride::new(mode)` so the policy is
/// resolved once at construction; the override is then registered
/// by the libxul bridge into every `JsContext` for the renderer.
///
/// Context-inert per Module 26: the policy is a `Copy` value
/// referencing static data, so `install(&OverrideContext)`
/// produces observationally identical state regardless of
/// `ctx.js_context()`.
#[derive(Debug, Clone, Copy)]
pub struct WebGpuOverride {
    policy: WebGpuReadbackPolicy,
}

impl WebGpuOverride {
    pub fn new(mode: Mode) -> Self {
        Self {
            policy: WebGpuReadbackPolicy::for_mode(mode),
        }
    }

    pub fn policy(&self) -> WebGpuReadbackPolicy {
        self.policy
    }

    /// The cohort-base profile this override reads non-vendor
    /// fields from. Always `&LOCKED_WEBGPU_PROFILE`.
    pub fn profile(&self) -> &'static WebGpuProfile {
        self.policy.profile()
    }
}

impl FingerprintOverride for WebGpuOverride {
    fn surface(&self) -> WebIdlSurface {
        WebIdlSurface::WebGpu
    }

    fn install(&self, _ctx: &OverrideContext) {
        // v1: no side effect. The libxul WebGPU hook is not yet
        // wired (see crate-level TODO). When the FFI lands:
        //   * CohortLocked(p) -> register a per-renderer callback
        //     returning every field from `p` on demand, including
        //     `p.vendor.as_str() == "Mozilla"`.
        //   * Bucketed(p) -> register a callback returning every
        //     field from `p` EXCEPT vendor, which is overridden
        //     by the libxul-side host-GPU bucketing into
        //     `WebGpuVendor::STANDARD_BUCKETS`.
        let _ = (self.policy, JsContext::ALL, WebGpuSurface::ALL);
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gecko::webgl::LOCKED_WEBGL_PROFILE;

    #[test]
    fn locked_profile_pins_mozilla_vendor() {
        // v1 Strict-cohort definition. Changing any of these is a
        // cohort shift through the Adaptation protocol.
        assert_eq!(LOCKED_WEBGPU_PROFILE.vendor, WebGpuVendor::Mozilla);
        assert_eq!(LOCKED_WEBGPU_PROFILE.vendor.as_str(), "Mozilla");
        assert_eq!(LOCKED_WEBGPU_PROFILE.architecture, "");
        assert_eq!(LOCKED_WEBGPU_PROFILE.driver, "");
        assert_eq!(LOCKED_WEBGPU_PROFILE.description, "");
        assert_eq!(LOCKED_WEBGPU_PROFILE.features.len(), 0);
    }

    #[test]
    fn locked_limits_match_webgpu_spec_minima() {
        // Pinning the spec-minimum values keeps the cohort
        // indistinguishable from a minimal-spec adapter — every
        // WebGPU adapter MUST support at least these. Changing
        // any value is a cohort shift through the Adaptation
        // protocol.
        let l = LOCKED_WEBGPU_PROFILE.limits;
        assert_eq!(l.max_texture_dimension_1d, 8192);
        assert_eq!(l.max_texture_dimension_2d, 8192);
        assert_eq!(l.max_texture_dimension_3d, 2048);
        assert_eq!(l.max_texture_array_layers, 256);
        assert_eq!(l.max_bind_groups, 4);
        assert_eq!(l.max_buffer_size, 268_435_456);
        assert_eq!(l.max_compute_workgroup_size_x, 256);
        assert_eq!(l.max_compute_workgroup_size_y, 256);
        assert_eq!(l.max_compute_workgroup_size_z, 64);
        assert_eq!(l.max_compute_invocations_per_workgroup, 256);
    }

    #[test]
    fn vendor_matches_module_28_webgl_cohort() {
        // Cross-module cohort unification: a renderer claiming
        // "Mozilla GPU" via WebGL and "Apple GPU" via WebGPU is a
        // contradiction sites detect. The Strict vendor field
        // must match `LOCKED_WEBGL_PROFILE.vendor` BY VALUE.
        // (Address identity is not possible — these are different
        // statics in different modules — but value equality is
        // the load-bearing claim.)
        assert_eq!(
            LOCKED_WEBGPU_PROFILE.vendor.as_str(),
            LOCKED_WEBGL_PROFILE.vendor
        );
        assert_eq!(LOCKED_WEBGL_PROFILE.vendor, "Mozilla");
    }

    #[test]
    fn standard_buckets_cover_five_hardware_classes() {
        // Phase-file Standard buckets: Intel / NVIDIA / AMD /
        // Apple / Other. Mozilla is Strict-only and NOT in the
        // Standard bucket list.
        assert_eq!(WebGpuVendor::STANDARD_BUCKETS.len(), 5);
        for v in [
            WebGpuVendor::Intel,
            WebGpuVendor::NVIDIA,
            WebGpuVendor::AMD,
            WebGpuVendor::Apple,
            WebGpuVendor::Other,
        ] {
            assert!(
                WebGpuVendor::STANDARD_BUCKETS.contains(&v),
                "missing bucket: {:?}",
                v
            );
        }
        // Strict-only vendor must NOT leak into the Standard buckets.
        assert!(!WebGpuVendor::STANDARD_BUCKETS.contains(&WebGpuVendor::Mozilla));
    }

    #[test]
    fn vendor_as_str_round_trips_for_every_variant() {
        // Address-stable strings the libxul bridge returns
        // verbatim. Empty strings are forbidden.
        for v in [
            WebGpuVendor::Mozilla,
            WebGpuVendor::Intel,
            WebGpuVendor::NVIDIA,
            WebGpuVendor::AMD,
            WebGpuVendor::Apple,
            WebGpuVendor::Other,
        ] {
            assert!(!v.as_str().is_empty(), "{:?} has empty string", v);
        }
    }

    #[test]
    fn strict_resolves_to_cohort_locked_with_locked_profile() {
        let p = WebGpuReadbackPolicy::for_mode(Mode::Strict);
        assert!(matches!(p, WebGpuReadbackPolicy::CohortLocked(_)));
        // Address identity: every Strict renderer reads the same
        // singleton.
        assert!(std::ptr::eq(p.profile(), &LOCKED_WEBGPU_PROFILE));
        assert_eq!(p.profile().vendor, WebGpuVendor::Mozilla);
    }

    #[test]
    fn standard_resolves_to_bucketed_with_same_locked_profile() {
        let p = WebGpuReadbackPolicy::for_mode(Mode::Standard);
        assert!(matches!(p, WebGpuReadbackPolicy::Bucketed(_)));
        // Address identity: Standard reads the SAME static as
        // Strict — only the vendor-resolution semantics differ.
        assert!(std::ptr::eq(p.profile(), &LOCKED_WEBGPU_PROFILE));
    }

    #[test]
    fn standard_and_strict_share_webgpu_cohort_base() {
        // Cohort unification: both modes reference the same
        // profile static. Only the policy VARIANT differs.
        let s = WebGpuReadbackPolicy::for_mode(Mode::Standard);
        let r = WebGpuReadbackPolicy::for_mode(Mode::Strict);
        assert!(std::ptr::eq(s.profile(), r.profile()));
        // Modes diverge on the variant tag (Bucketed vs CohortLocked).
        assert!(matches!(s, WebGpuReadbackPolicy::Bucketed(_)));
        assert!(matches!(r, WebGpuReadbackPolicy::CohortLocked(_)));
    }

    #[test]
    fn strict_resolution_is_idempotent_and_non_loosenable() {
        // L41 lock — the API has no with_user_override
        // constructor. Two Strict resolutions are identical.
        let a = WebGpuReadbackPolicy::for_mode(Mode::Strict);
        let b = WebGpuReadbackPolicy::for_mode(Mode::Strict);
        assert_eq!(a, b);
    }

    #[test]
    fn webgpu_surface_all_covers_five_pathways() {
        // Phase-file subtask 5: RequestAdapter / AdapterInfo /
        // AdapterFeatures / AdapterLimits / DeviceLost. Adding a
        // new WebGPU surface that the bridge must hook needs a
        // variant here.
        assert_eq!(WebGpuSurface::ALL.len(), 5);
        for v in [
            WebGpuSurface::RequestAdapter,
            WebGpuSurface::AdapterInfo,
            WebGpuSurface::AdapterFeatures,
            WebGpuSurface::AdapterLimits,
            WebGpuSurface::DeviceLost,
        ] {
            assert!(WebGpuSurface::ALL.contains(&v), "missing pathway: {:?}", v);
        }
    }

    #[test]
    fn webgpu_override_reports_webgpu_surface_under_both_modes() {
        assert_eq!(
            WebGpuOverride::new(Mode::Standard).surface(),
            WebIdlSurface::WebGpu,
        );
        assert_eq!(
            WebGpuOverride::new(Mode::Strict).surface(),
            WebIdlSurface::WebGpu,
        );
    }

    #[test]
    fn webgpu_override_install_is_context_inert() {
        // Edge case: override must be inert across iframe / worker
        // / service-worker / dedicated-worker.
        let pid = uuid::Uuid::parse_str("00000000-0000-4000-8000-000000035006").unwrap();
        for mode in [Mode::Standard, Mode::Strict] {
            let ovr = WebGpuOverride::new(mode);
            let policy_before = ovr.policy();
            for jsc in JsContext::ALL {
                let ctx = OverrideContext::new(mode, pid, *jsc);
                ovr.install(&ctx);
            }
            assert_eq!(ovr.policy(), policy_before);
            assert_eq!(ovr.surface(), WebIdlSurface::WebGpu);
        }
    }

    #[test]
    fn vendor_dispatch_is_exhaustive_friendly() {
        fn route(v: WebGpuVendor) -> &'static str {
            match v {
                WebGpuVendor::Mozilla => "mozilla",
                WebGpuVendor::Intel => "intel",
                WebGpuVendor::NVIDIA => "nvidia",
                WebGpuVendor::AMD => "amd",
                WebGpuVendor::Apple => "apple",
                WebGpuVendor::Other => "other",
            }
        }
        for v in [
            WebGpuVendor::Mozilla,
            WebGpuVendor::Intel,
            WebGpuVendor::NVIDIA,
            WebGpuVendor::AMD,
            WebGpuVendor::Apple,
            WebGpuVendor::Other,
        ] {
            assert!(!route(v).is_empty());
        }
    }

    #[test]
    fn surface_dispatch_is_exhaustive_friendly() {
        fn route(s: WebGpuSurface) -> &'static str {
            match s {
                WebGpuSurface::RequestAdapter => "request-adapter",
                WebGpuSurface::AdapterInfo => "adapter-info",
                WebGpuSurface::AdapterFeatures => "adapter-features",
                WebGpuSurface::AdapterLimits => "adapter-limits",
                WebGpuSurface::DeviceLost => "device-lost",
            }
        }
        for s in WebGpuSurface::ALL {
            assert!(!route(*s).is_empty());
        }
    }

    #[test]
    fn policy_dispatch_is_exhaustive_friendly() {
        fn arm(p: WebGpuReadbackPolicy) -> &'static str {
            match p {
                WebGpuReadbackPolicy::CohortLocked(_) => "cohort-locked",
                WebGpuReadbackPolicy::Bucketed(_) => "bucketed",
            }
        }
        assert_eq!(
            arm(WebGpuReadbackPolicy::for_mode(Mode::Standard)),
            "bucketed"
        );
        assert_eq!(
            arm(WebGpuReadbackPolicy::for_mode(Mode::Strict)),
            "cohort-locked"
        );
    }

    #[test]
    fn webgpu_types_are_send_sync() {
        // Module 26 trait obligation: implementations MUST be
        // Send + Sync because libxul holds them in
        // Arc<dyn FingerprintOverride>.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<WebGpuOverride>();
        assert_send_sync::<WebGpuReadbackPolicy>();
        assert_send_sync::<WebGpuProfile>();
        assert_send_sync::<WebGpuVendor>();
        assert_send_sync::<WebGpuLimits>();
        assert_send_sync::<WebGpuSurface>();
    }
}
