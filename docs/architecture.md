# DevBrowse — Architecture

**Version:** 1.9  
**Status:** Locked — change requires explicit re-locking with rationale  
**Last revised:** 2026-04-30

---

## 0. How to read this document

This is the canonical specification for DevBrowse. Every module, every locked
decision, every security invariant in the codebase descends from this doc.

When code disagrees with this doc, **the doc wins** until the doc is explicitly
revised. To revise, add an entry to §10 (Revision log) with the date, what
changed, and why.

If a future maintainer is unsure about a design
choice, the rule is: **read this doc first, ask the user second, do not infer
from existing code third**. Existing code may be a stub or may pre-date a
revision.

---

## 1. Mission and non-goals

### 1.1 Mission

DevBrowse is a privacy-focused web browser written in Rust. The v1 desktop
builds (Linux / macOS) embed the Gecko engine via libxul FFI; Windows desktop
is deferred to **Phase 11.9** (its own hardening pass — Modules 93-96); mobile
builds (iOS, Android — Phase 12) use platform-conditional engines (WebKit on
iOS per App Store policy 2.5.6, GeckoView on Android). It is built to **change the
defaults** of the browser category: privacy is not a setting, it is the
architecture. UX is modern and trust-building, not a Chromium reskin.

### 1.2 Non-goals (v1)

- DevBrowse-operated sync server — sync is **cluster-local**, see L21. Users who want cross-network sync run their own relay (no DevBrowse-hosted service exists).
- Homemade cryptographic primitives — we compose audited primitives, never
  invent ciphers/hashes/PRFs (L22).
- OS-platform passkey sync — Apple/Google own the keychain on iOS/Android;
  only software-authenticator passkeys we generate are sync-eligible.
- Built-in password manager — deferred decision (§7).
- Built-in autofill — deferred decision (§7).
- Replacing the JS console — Gecko DevTools stays as-is in standard mode.
- Third-party SaaS cloud sync (Google Drive / iCloud / Dropbox / OneDrive) — anti-goal, will never be added (L21).

### 1.3 Anti-goals (never)

- Telemetry of any user-identifying data.
- Network calls outside the user's intent (no preconnect leaks, no suggestion
  pings without explicit opt-in to a search engine).
- Path-string filesystem APIs exposed to renderers or content JS.
- DevTools access in strict mode.

---

## 2. Locked architectural decisions

These are the load-bearing choices. Each is a **lock** — to change one is a
breaking re-architecture that requires explicit user discussion.

| Lock | Decision | Why |
|---|---|---|
| L1 | Engine: **Gecko** via libxul FFI | Mature, MPL-2.0, gives us WebIDL hooks for fingerprint normalization. |
| L2 | Language: **Rust 2021 edition**, stable channel | Memory safety mandatory for browser code. |
| L3 | UI: **Iced 0.14** (wgpu backend) for desktop chrome; native shells per mobile platform (SwiftUI on iOS, Jetpack Compose on Android) consuming shared renderer-agnostic design tokens; in-app glass via `pb-ui::glass` custom wgpu blur widget (Module 42); `window-vibrancy`-ready architecture for future OS-level vibrancy (NSVisualEffectView on macOS, DWM Mica on Windows) without engine swap. | Native rendering, no Electron, no Chromium UI deps. Iced wins on memory (60-120 MB lighter than Gecko chrome / WebKit-WebView at idle), CPU (3-5x lower during chrome animations), battery, attack surface (no second JS engine), and future vibrancy path. Rejected v1.24: (a) Gecko chrome document everywhere (libxul has no stable embedding API, GeckoView has no public chrome-document API on Android, breaks L40 isolation); (b) Tauri / WebKit-WebView (CSS `backdrop-filter` broken on WebView2 / WebKitGTK / Android WebView per upstream bugs); (c) Slint (Skia binary bloat + DSL overhead + per-element filter, not true backdrop sample); (d) Flutter (desktop PlatformView gap prevents Gecko content embedding, Impeller Linux desktop incomplete). |
| L4 | IPC: **Tokio + Unix sockets + Protobuf (prost)** | Async, well-typed, hermetic codegen. |
| L5 | Storage: **SQLite via rusqlite (bundled)**, WAL mode | One file format, audited C, no system-libsqlite version drift. |
| L6 | Networking: **hyper 1.x + rustls** (no OpenSSL) | Pure-Rust TLS, smaller attack surface, no OS trust-store dependency. |
| L7 | Identifier crypto: **uuid v4** (CSPRNG) for IDs, **sha2** for partition keys | Standard primitives only. |
| L8 | Fingerprint normalization: **Gecko WebIDL override points**, NOT JS prototype patching | Workers and iframes inherit automatically; zero internal Gecko patches. |
| L9 | Process model: **identity-grouped** with **Standard** and **Strict** modes | See §3. |
| L10 | Filesystem access: **capability-based** via opaque `FileHandle`, OS-picker-gated | Path strings never cross the trait surface. See §5.3. |
| L11 | Clipboard / sensitive input: **gesture-token-gated** at the type system level | Move-only `GestureToken`, single-use. See §5.4. |
| L12 | Crate dependency rule: any crate may import **`pb-ipc`, `pb-config`, and `pb-sandbox`**; no other cross-crate imports | Enforced at Cargo.toml level. See §4. |
| L13 | Unsafe code policy: **`#![forbid(unsafe_code)]`** on every crate; downgrade to `deny` only on FFI modules with `#[allow(unsafe_code)]` annotation | See §5.6. |
| L14 | Release profile: `panic=abort`, `overflow-checks=true`, `lto=fat`, `codegen-units=1`, `strip=symbols` | Browser parses hostile input — overflow must panic, not wrap. `panic=abort` prevents unwinding through libxul FFI. |
| L15 | Supply chain: **`cargo-deny` gate in CI** (advisories, licenses, bans, sources) | Every transitive dependency reviewed. |
| L16 | DevTools: **Gecko built-in only** (zero custom impl in v1); **blocked entirely in strict mode** | Customization deferred. |
| L17 | PDF: **inline pdf.js sandboxed renderer** + download option | No external PDF helper; consistent privacy boundary. |
| L18 | Default search engine: **DuckDuckGo**, with user choice from a curated privacy-respecting set (DDG, Startpage, Brave Search, Mojeek) | Suggestions ON by default, but only via the user's chosen engine. |
| L19 | File picker UX: **modern drag-and-drop entry surface** that calls the OS picker for capability minting | "Reading B" — drop zone + recent-picks chips + Browse button. Never traverses filesystem ourselves. See §5.3. |
| L20 | Translation / spellcheck: **OFF by default**; when enabled, **local-only** (no remote service calls) | Both are content-leaking by default in mainstream browsers. |
| L21 | Sync model: **cluster-local, LAN-first, end-to-end encrypted, no DevBrowse server, no third-party cloud**. Initial pair on same WiFi via SPAKE2 6-digit code + mandatory 4-emoji fingerprint compare. **Pair-once persistent identity:** paired devices reconnect across any network or restart without re-pairing; mDNS announcements carry a rotating-nonce HMAC under the cluster key so paired peers identify each other while outsiders observing the LAN see only random bytes. Three transport tiers: direct LAN (mDNS + QUIC + Ed25519 mTLS), hub-peer forwarding (per-device opt-in, encrypted blobs only), optional self-hosted WebDAV relay (last resort, off by default). **Convergence guarantee:** all paired devices reach the same vault version via signed append-only sync log + per-peer high-water marks (Module 84); on reconnection each side ships missing entries until both sides match. **Vault auto-locks** on OS suspend, lid-close, and inactivity timeout. No SaaS cloud backend will ever be added (architectural anti-goal). | User data never touches a server we don't control; nothing to subpoena; pair-once persistent identity gives seamless multi-device UX without compromising LAN unlinkability for outsiders; cross-network sync requires user action (run own relay) — the honest tradeoff. |
| L22 | Cryptographic primitives: **audited and standardized only** (Argon2id, XChaCha20-Poly1305, HKDF, Ed25519/X25519). Protocol composition is ours; primitive set is upgradable (PQC migration tracked). No homemade ciphers/hashes/PRFs. | Schneier's law: anyone can design a cipher they themselves can't break. We compose vetted primitives; we don't invent them. |
| L23 | First-launch setup wizard: **per-feature opt-in** (sync, telemetry, search engine, privacy mode, fingerprint level, translation/spellcheck, etc.). Declined features are **disabled at code-path level**, not just UI-hidden. | "Defaults are architecture" — the wizard makes the defaults a conscious user choice, not a buried setting. |
| L24 | Local encrypted backup/import: **same vault format as sync**, exported to a user-controlled file. Works fully offline. Cross-platform import (desktop ↔ mobile). | Users who decline cloud entirely still get device portability. Vault format reuse keeps the surface area minimal. |
| L25 | DoH provider whitelist: **Quad9 (default)**, NextDNS (wizard-personalized), Cloudflare, or user-supplied custom HTTPS URL (covers self-hosted DNS). **System DNS allowed only in Standard mode** (§3.2); forbidden in Strict (§3.3, DoH-only). NextDNS in the wizard requires a per-account config ID and is persisted as `Custom { url }`; declining the ID falls back to Quad9. | Privacy-respecting curated set, no Google DNS. Quad9 is no-log + malware blocklist out of the box. NextDNS without a config ID adds no privacy value over Quad9, so we refuse to ship that as the silent default. Config rejects malformed URLs at load so a tampered config cannot silently downgrade resolution. |
| L26 | Tracker / ad blocking counters: per-tab badge in the address bar shows total blocked items; full breakdown (ads vs trackers vs fingerprint attempts) in the **Network Viewer** (Module 60). Counters are pure-local, in-process, never persisted, never network-shipped. Module 21 (blocklist) emits classified events; Module 60 surfaces them. Ad/tracker blocking itself remains always-on per the original lock (privacy-browser-context). | Visibility builds trust without leaking data. Counters are ephemeral so even a forensic disk read shows nothing. |
| L27 | Logging policy: **ephemeral session-only debug logs by default** (RAM ring buffer, dropped at exit, never written to disk). User can opt-in to disk logs for bug reporting; opt-in logs auto-redact URLs, form bodies, identity profile names, and partition keys before any write. **No log line ever crosses the network without explicit per-session user consent** (e.g. attaching to a bug report). | Logs are the easiest accidental data leak in any browser. Default-ephemeral + redact-on-write keeps the floor high. |
| L28 | UI design intent: **modern translucent / Apple-glass aesthetic** (vibrancy/blur on platforms that support it: macOS NSVisualEffectView, Windows 11 Mica/Acrylic, Linux compositor-dependent). Default chrome layout = **left-vertical sidebar that opens on hover from a hamburger affordance**, with tab search at sidebar top, tab list in the middle, bookmarks as a right-edge icon column with hover popovers, and a 3-dot overflow menu at the sidebar top for settings / passwords / less-frequent items. Address bar is prominent on focus and fades when idle (always reveals on any keyboard activity, never on mouse-only). Top-horizontal and full-vertical tab layouts are **opt-in alternatives** in settings; sidebar-hover is the v1 default. **Accessibility floor (mandatory):** respect OS "reduce transparency"; WCAG AA contrast on all text-on-glass surfaces (apply a subtle solid backdrop behind text where needed); every chrome surface fully keyboard-navigable. | "Defaults are architecture" extends to UX. The sidebar-hover layout is the most distinctive choice and matches the bookmark-column idea. Locking the accessibility floor up front prevents the glass aesthetic from boxing out users who need contrast or reduced motion. |
| L29 | History retention (Standard mode only): user-selectable in `[history] retention = "forever" \| "session" \| "week" \| "month"`. **Default: `"forever"`** (matches user expectation; wizard surfaces the choice). Strict mode never writes history (already locked at §3.3 / privacy-browser-context). The history process auto-purges entries older than the retention window on a daily sweep. | Users who want a clean trail get it; users who want history get it. Either way, no surprise. The wizard prompt makes the choice conscious, not buried. |
| L30 | **HTTPS-Only mode is the default.** All outbound navigations are upgraded to `https://`; an `http://` request is only issued after the user clicks an explicit per-host downgrade in a confirmation modal (no silent fallback, no auto-retry on TLS error). Strict mode disallows the downgrade entirely. Validated in pb-network (Module 22 headers + Module 23 TLS). | Every modern browser ships HTTPS-Only behind a setting. Locking it on by default closes the largest passive-network leak users have. |
| L31 | **Referer policy:** `strict-origin-when-cross-origin` in Standard mode; `no-referrer` in Strict mode. Header is rewritten by pb-network before the request hits the wire. No site-level override path in v1. | Default browser policy still leaks origin paths cross-site. Locking the header at the broker keeps it consistent regardless of what content JS sets. |
| L32 | **URL parameter stripping:** outbound navigations and bookmark writes have known tracking parameters removed (`utm_*`, `gclid`, `fbclid`, `mc_eid`, `_ga`, `igshid`, `vero_id`, `wickedid`, plus the curated list maintained in the Module 21 blocklist track). Bookmarks store the stripped URL; the navigation that the user typed proceeds with the stripped URL. | Re-shareable links shouldn't carry attribution beacons. Stripping at the broker keeps the policy out of every renderer's hands. |
| L33 | **Network-state partitioning:** HTTP cache, DNS cache, connection pool, ALT-SVC cache, and HSTS cache are all keyed by `partition_key` (§3.5). No cross-partition reuse, no cross-site connection coalescing. | Same partition-key discipline that storage uses — extended to the entire network state. Closes the connection-pool side channel and the cache-timing oracle. |
| L34 | **Encrypted Client Hello (ECH):** preferred when the server advertises HTTPS RR records with an ECH config; falls back to standard SNI without a handshake-failure leak. Disabled in Standard only by an explicit settings toggle; in Strict mode, ECH is mandatory when available and standard SNI is permitted only when the server has no ECH config (logged as a warning surfaced via Module 11). | Plaintext SNI is the last passive identifier on the wire. ECH adoption is mid-rollout; default-on with graceful fallback gets us the privacy when it's available without breaking compat. |
| L35 | **WebRTC constraints:** peer connections require an explicit per-site permission grant (Module 59 permission center). ICE candidates use mDNS hostnames; private IPv4/IPv6 / link-local addresses are filtered out of candidate strings before they reach JS. **In Strict mode, WebRTC is fully disabled** (the API surface returns "not supported"). Module 25 owns enforcement. | WebRTC's IP-leak surface is the most-cited fingerprint vector. Default-deny in Strict, default-mDNS-only in Standard, never raw private IPs to content. |
| L36 | **Bounce tracker mitigation (navigational tracking protection):** storage created by an "intermediate" site — one the user visited only via cross-site redirect, never as a top-level navigation — is auto-purged after a short window (default: 45 days, matching Mozilla's tuning). Module 18 (strict-wipe) is the per-tab variant; this is the cross-session variant. | Bounce trackers convert each referral into persistent state. Time-boxed purge of intermediate-only storage neutralizes the vector without breaking sites users actually visit. |
| L37 | **Cookie banner auto-decline:** opt-in at the first-launch wizard (default: ON for new users, easily disabled). Injects "decline / reject all" responses to common consent banners using a curated rule set (Consent-O-Matic and "I Don't Care About Cookies" style). Rule list is versioned and shipped via the Module 21 blocklist track (signed updates). | Most users would decline if asked properly. Automating the decline both saves clicks and prevents banner-fatigue "accept all" mistakes. Wizard-gated so the user knows it's happening. |
| L38 | **Reproducible builds:** every release artifact is built reproducibly under a locked Rust toolchain version and locked dependency tree (Cargo.lock + cargo-vet pin). The CI publishes the artifact's `sha256` alongside the binary; an independent rebuild from the same source must produce a byte-identical artifact. Reproducibility checks are part of the release-promotion gate. | Reproducibility is what makes signed builds *meaningful* — without it, a compromised CI can ship malware under a valid signature. |
| L39 | **Release signing (dual scheme):** every release artifact carries **(a)** a GPG detached signature from an offline release key (rotated annually, fingerprint published in the repo) **and (b)** a Sigstore signature recorded in the Rekor public transparency log. Update-channel signing (`pb-update`, §5.7) reuses the offline key; binary distribution outside the auto-updater (e.g. distro packagers) verifies via the GPG signature alone. | GPG covers offline / air-gapped verification (distro maintainers); Sigstore gives a public transparency log that catches a compromised release-key event. Both together close more of the supply-chain threat model than either alone. |
| L40 | **Renderer-network isolation (libxul build + sandbox):** every Gecko renderer process is configured so its only outbound network path is the pb-ipc bridge to the `pb-network` broker. **(a)** libxul is built with Necko / NSPR / NSS network egress paths disabled (or replaced with pb-ipc shims registered via `nsIIOService` protocol-handler injection) so the renderer's in-process network stack cannot syscall directly. **(b)** the renderer's kernel sandbox (Modules 12 / 12.1 / 80.5) denies `socket()` / `connect()` / `bind()` as defense-in-depth — even a Necko bypass fails at the syscall boundary. **(c)** Module 69 (wrapper-compatibility checker) verifies on every libxul tag bump that the build retains the Necko-disabled configuration; a libxul that re-enables internal egress fails the update gate. | Without this, the L33 partition-key gate is a polite suggestion: a renderer running unmodified Necko can dial out directly and bypass every broker-side privacy lock. Three independent layers (libxul build, sandbox, wrapper checker) keep the broker as the sole egress authority even if any single layer regresses. |
| L41 | **Strict-mode settings lock:** Strict mode is **non-loosenable** by user settings. Any wizard opt-in or settings toggle that would weaken an L9 / L16 / L25 / L29 / L30 / L31 / L34 / L35 / L42 / L43 / L44 invariant is **ignored** for tabs whose `mode == Strict`; the loosening only affects Standard tabs. Settings can still further-tighten Strict (e.g. enabling Strict-by-default, disabling DoH fallback in Standard) but never loosen it. Enforced at code-path level: every settings-consuming site reads `(setting, mode)` and short-circuits to the locked value when mode is Strict. The orchestrator (Module 80) wires the per-mode settings consultation at boot. | "Strict means strict" must be an architectural property, not a UX promise. Without this lock, a hostile site that tricks the user into a settings change could weaken every Strict tab silently. Enumerating which locks Strict pins makes the contract auditable and the test surface complete (Phase 10 module 71 asserts it). |
| L42 | **Window dimension letterboxing (Strict):** in Strict tabs, `window.innerWidth` / `window.innerHeight` / `window.outerWidth` / `window.outerHeight` / `screen.width` / `screen.height` / `screen.availWidth` / `screen.availHeight` are quantized to a **200 × 100 grid** (matching Tor Browser / Mullvad Browser). The actual window may be any pixel size; only the JS-visible dimensions are bucketed. Standard tabs use the coarser §5.5 buckets. Multi-monitor layout is never exposed to content JS regardless of mode (already locked by §5.5). | Window dimensions are one of the largest passive-fingerprinting surfaces. Letterboxing collapses ~10⁵ distinct screen-size values into ~10² buckets, giving Strict users the same cohort signal as every other Strict user on the same release. Tor Browser ships this as `privacy.resistFingerprinting.letterboxing = true`; DevBrowse pins the dimensions and the bucket size by lock so they cannot drift. |
| L43 | **Timer quantization (Strict):** `performance.now()`, `Date.now()`, `Performance.timeOrigin`, and every other JS-observable timer surface are quantized to **100 ms** in Strict (matching Tor Browser RFP). Standard tabs use **1 ms** (the existing §5.5 floor); GPU timestamps remain **2 ms** in both modes (L8 / pb-gpu). Async event jitter (e.g. `requestAnimationFrame`, `setTimeout`) is bounded to the same granularity in Strict. | Sub-millisecond timer resolution is the foundation of timing-side-channel attacks (Spectre, cache-occupancy probes) and a high-entropy passive fingerprint (CPU clock skew, JIT warm-up cost). 100 ms is Tor Browser's locked floor; matching it gives Strict the same defense-class without re-deriving the threshold. Standard accepts the 1 ms / 100 ms gap as a Strict-only opt-in tradeoff. |
| L44 | **Disabled-by-default API surface (Strict):** in Strict tabs the following JS APIs return `"not supported"` (constructor throws or undefined property) **without ever consulting Module 59**: Geolocation, `MediaDevices.enumerateDevices` (and `getUserMedia` audio/video capture), Web Bluetooth, WebUSB, WebHID, Web Serial, Web NFC, Sensors (`Accelerometer` / `Gyroscope` / `Magnetometer` / `AmbientLightSensor` / `LinearAccelerationSensor` / `OrientationSensor` / `GravitySensor` / `RelativeOrientationSensor` / `AbsoluteOrientationSensor`), Gamepad, `navigator.sendBeacon`, `Battery`, `Notification`, `WakeLock`, `IdleDetector`, `PresentationRequest`, `PaymentRequest`. Standard tabs route the same APIs through Module 59's per-site permission flow. WebRTC is separately locked (L35) — Strict-disabled, Standard mDNS-only with permission. | Each surface above is a fingerprint vector and a privacy-impacting capability. In Strict the user has expressed "I want maximum normalization", so blanket-deny is the right default; any per-site permission flow is itself a fingerprint signal (does the user grant? does the site receive a deny vs ignore?). Mullvad / Tor Browser disable nearly all of these globally; DevBrowse splits at the mode boundary so Standard remains web-compatible. |

---

## 3. Identity-grouped process model

### 3.1 IdentityProfile

Every tab is bound to an `IdentityProfile` at spawn. The profile is **immutable
for the tab's lifetime**. To "switch" identities, the lifecycle layer tears
down the tab's renderer and creates a new tab with a new profile.

A profile carries:

- `profile_id: Uuid` — stable identifier, used as input to the partition key.
- `name: String` — user-visible label (e.g. "Personal", "Work").
- `mode: Mode` — Standard or Strict. Locked at creation.

### 3.2 Standard mode

- Renderers may be **shared across tabs of the same `profile_id`**.
- **Browser extensions: curated allowlist only.** Users may install
  only extensions on the signed allowlist shipped via the Module 65
  update channel. Free side-load from AMO is forbidden; there is no
  link to addons.mozilla.org in the chrome and no manual `.xpi`
  install path. Allowlisted extensions do **not** receive
  outbound-traffic inspection capabilities (no `webRequest`-style
  hook into `pb-network`); the network broker is intentionally
  non-extensible to honor L30 / L33.
- DevTools allowed.
- DNS: DoH preferred, system DNS permitted as fallback.
- Storage: standard partition-key isolation (per-site within identity).

### 3.3 Strict mode

- **Per-tab renderer.** Never shared, even across tabs with the same `profile_id`.
- Extensions blocked at the identity context level.
- DevTools blocked entirely.
- DNS: **DoH-only**, no system DNS.
- Storage: full partition-key isolation + strict-wipe on tab close.
- Increased fingerprint normalization (max bucketing).

### 3.4 Renderer-sharing rule (security invariant)

Two tabs may share a renderer process **iff**:

1. Both profiles are in `Mode::Standard`, **and**
2. Both profiles have the same `profile_id`.

Strict tabs never share. This rule is enforced in pb-identity (Module 8) and
asserted by the renderer scheduler.

### 3.5 Partition key derivation

```
partition_key = sha256( site_origin || identity_profile_id || context_id )
```

Computed by pb-storage (Module 14). Every storage read/write checks this key
via the gatekeeper (Module 15) — no exceptions, no bypass paths.

`context_id` is **fresh per Strict tab** so two Strict tabs of the same
`identity_profile_id` cannot read each other's storage (defense-in-depth on
top of the per-tab renderer rule §3.3). Standard tabs of the same
`identity_profile_id` use a stable `context_id` per profile so they share
storage as users expect.

### 3.6 Mode-toggle UX (one-way Standard → Strict)

The mode toggle is the flagship UX element that makes "private window" go
away as a separate concept. Rules:

1. **New tab opens in Standard** by default (matches `privacy.default_mode`,
   user-configurable in the wizard / settings).
2. **One-time prominent "Convert to Privacy tab" affordance** sits inside
   every freshly-opened Standard tab, with a short inline explanation of
   what changes (per-tab renderer, no extensions, no DevTools, no history,
   strict-wipe on close, separate cookies / session, max fingerprint
   normalization). The affordance is dismissible per-tab and per-session;
   suppressing it permanently is a settings opt-out (Module 52).
3. **Once a tab is Strict, it is Strict for life.** There is no Strict →
   Standard path. The only way out is to close ("kill") the tab. This is a
   security invariant, not a UX choice — re-using a Strict-mode renderer
   for Standard work would leak the very isolation the user just asked for.
   Enforced by the absence of any retarget API on `LifecycleManager`
   (architecture §3.1) and by the per-tab renderer rule (§3.3).
4. **Standard-mode link clicks open new tabs in Standard.** When the user
   clicks a link inside a Standard tab, the new tab inherits Standard mode
   by default. A non-modal popover at the top of the new tab offers
   "Open this in a Privacy tab instead" for a few seconds, then fades. The
   user can disable the popover in settings.
5. **Cookies / session firewall (Standard ↔ Strict).** A Strict tab spawned
   from the same URL as an authenticated Standard tab MUST NOT see the
   Standard tab's cookies, sessionStorage, IndexedDB, cache, or any other
   per-origin state. Enforcement: Strict tabs run under a separate
   `identity_profile_id` (the user's "Strict mode" profile, distinct from
   their everyday Standard profile) **and** a fresh `context_id` per tab,
   so the partition key (§3.5) differs from the Standard partition key for
   the same origin. The storage gatekeeper (§5.2) rejects any cross-key
   read; the network state partition (L33) rejects any cached connection
   reuse.
6. **No "Strict by default" silent escalation.** If the user prefers
   Strict-by-default, they set it explicitly in settings (`privacy.default_mode = "strict"`).
   This makes the user's choice conscious and visible, in line with L23.

---

## 4. Crate topology and dependency rule

DevBrowse is a 13-crate workspace today (Phase 1, expanded in v1.5 to add
`pb-sandbox`). Phase 11.5 introduces a single `pb-sync` crate (vault crypto +
sync log + LAN discovery / pairing / transport + hub-peer forwarding +
optional WebDAV relay). Password manager UI is a separate future phase, not
part of `pb-sync`. Phase 12 introduces mobile crates (engine adapter for
WebKit/GeckoView, mobile UI shells, mobile build glue).

```
pb-browser              (orchestrator binary)
   ├── pb-ipc           (shared message types — anyone may import)
   ├── pb-config        (shared config types — anyone may import)
   └── pb-sandbox       (OS sandbox profiles — anyone may import; Module 12)

pb-platform             (OS adapter trait surface — leaf crate, zero pb-* deps)

pb-identity             (identity profiles, lifecycle)
pb-storage              (partition-keyed storage gatekeeper)
pb-network              (DoH, blocklist, TLS, WebRTC constraints)
pb-fingerprint          (Gecko WebIDL overrides)
pb-gpu                  (timing-quantized GPU coordination)
pb-extensions           (extension policy enforcement)
pb-update               (signed update pipeline)
pb-ui                   (Iced chrome)
```

### 4.1 Dependency rule (locked)

A crate may import **`pb-ipc`, `pb-config`, and `pb-sandbox` only**. No
`pb-X → pb-Y` imports beyond those three. Violations are caught at
Cargo.toml review.

`pb-platform` is a strict leaf — it imports neither `pb-ipc` nor `pb-config`
nor `pb-sandbox`. This guarantees OS adapter traits are usable in any
context, including future backend test harnesses.

`pb-sandbox` is also a leaf — it has zero pb-* imports. It is in the
"anyone may import" tier so that every spawn site (renderer, network broker,
storage broker) can construct or receive a `SandboxProfile` and call
`apply()` at startup without taking a dep on pb-identity.

### 4.2 Why this rule

- Compilation graph is a DAG, never a near-cycle.
- Every crate is independently testable.
- Refactoring one feature can't accidentally pull in the rest of the world.
- Trust boundaries align with crate boundaries — pb-storage cannot accidentally
  call pb-network functions.

---

## 5. Security invariants (consolidated)

This section gathers every SECURITY INVARIANT into one place. Code-level
comments must remain in the source files for local context, but any new
invariant added in code must also be reflected here.

### 5.1 Process trust boundaries

- Renderers are **untrusted**. They handle hostile content.
- Brokers (the orchestrator, identity, storage, network processes) are
  **trusted**. They run code from this codebase only.
- The IPC boundary between renderer and broker is the trust boundary.
  Every message crossing it must be validated.

### 5.2 Partition key gatekeeping

Every storage operation in pb-storage passes through the gatekeeper. The
gatekeeper computes the expected partition key from the request context and
rejects any read/write whose declared key differs. There is no fast path,
no admin override, no test bypass.

### 5.3 Filesystem access — capability model

- The trait surface (`FileSystemAdapter` in pb-platform) **never** accepts a
  `&Path` from a caller. Callers receive an opaque `FileHandle`.
- Three legitimate sources of `FileHandle`:
  1. `open_picker()` → user selected via OS open dialog.
  2. `save_picker()` → user selected destination via OS save dialog.
  3. `register_dropped_path()` → user dragged a file onto a window (the OS
     witnessed the gesture; only the chrome's drop handler may call this).
- Backends store the canonicalized path in a private map keyed by handle.
- Renderers receive `FileHandle` over IPC, never path strings.
- "Modern file picker UX" (drop zone + recent picks + Browse button) is a
  chrome-side presentation layer. The capability boundary is unchanged.

### 5.4 Clipboard / gesture gating

- `InputAdapter::clipboard_read` / `clipboard_write` require a move-only
  `GestureToken`. Tokens are consumed on use (no `Clone`, no `Copy`).
- Tokens are minted **only by pb-ipc's input event handler** after observing
  a real OS-level keypress or mouse click.
- Programmatic JS clipboard access never produces a token, therefore never
  reaches the trait.

### 5.5 Fingerprint surface — central bucketing

- pb-platform exposes **raw** OS values (DPR, screen size, window position,
  etc.).
- pb-fingerprint is the **single bucketing point** before content exposure.
  No other crate filters fingerprint values.
- Bucketing rules (per-mode):
  - Standard: coarse grid for screen, DPR snapped to {1.0, 1.5, 2.0, 3.0}.
    Timer quantization 1 ms (`performance.now`, `Date.now`).
  - Strict: tighter buckets, hardware identifiers fully normalized.
    Window dimensions letterboxed to a 200×100 grid (L42). Timer
    quantization 100 ms (L43). Disabled-by-default API surface (L44).
    Settings cannot loosen these (L41).
- **Per-Phase-5 surface Mode-applicability matrix** (locked alongside
  each module as it ships; "Standard" column is the pass-through /
  bucketed behavior, "Strict" column is the max-normalization
  behavior). A Phase 5 module without an explicit row here MUST add
  one in its phase-file entry before it can land — see the
  "Mode-applicability discipline" note in
  `project-plan/phase-5-fingerprint.md`.

  | # | Surface | Standard | Strict |
  |---|---|---|---|
  | 27 | Canvas readback | **`LOCKED_CANVAS_PROFILE` cohort base + per-(origin, IdentityProfile) farbling** (cohort base = same rasterizer / font set / AA / hinting / pixel snap as Strict, so amiunique sees a generic DevBrowse Standard cohort; farbling = ±1 LSB deterministic noise on the readback derived from `PartitionKey::farbling_seed()` so cross-site tracking is defeated; **superseded v1.12 Native pass-through, locked v1.23 / Module 35.5**) | Normalized rasterizer via `LOCKED_CANVAS_PROFILE` (grayscale AA, no hinting, CPU, sRGB, snap-to-int, bundled font set); **no farbling** (pure cohort lock) |
  | 28 | WebGL parameters | **`LOCKED_WEBGL_PROFILE` cohort base + per-origin farbling on numeric MAX_*** (vendor / renderer locked to `"Mozilla"`; 5-extension cohort allowlist; numeric MAX_* farbled within cohort-locked bounds; **superseded v1.13 Native pass-through, locked v1.23 / Module 35.5**) | `LOCKED_WEBGL_PROFILE` cohort lock for `getParameter` + `getSupportedExtensions`; `WEBGL_debug_renderer_info` + `EXT_disjoint_timer_query{,_webgl2}` absent from the allowlist; `readPixels` reuses `LOCKED_CANVAS_PROFILE` (Module 27) so the Strict cohort is not split by readback-API choice; **no farbling** |
  | 29 | Web Audio | **`LOCKED_AUDIO_PROFILE` cohort base + per-origin farbling on readback** (cohort base activates `CompressorImpl::CohortLocked` + `DspPath::ScalarReference`; farbling = ±1e-5 noise on `getChannelData` / `AnalyserNode` reads derived from `PartitionKey::farbling_seed()`; **superseded v1.14 Native pass-through, locked v1.23 / Module 35.5**) | `LOCKED_AUDIO_PROFILE` cohort lock for `OfflineAudioContext` rendering + `AudioBuffer.getChannelData` + all four `AnalyserNode` readbacks + `AudioContext.baseLatency` / `outputLatency` / `sampleRate` (44.1 kHz Tor-parity, stereo, 5 ms / 20 ms cohort-locked latencies, 1e-7 `Float32Array` post-render quantization grid, `CompressorImpl::CohortLocked` deterministic scalar reference compressor, `DspPath::ScalarReference` SIMD-off DSP path); **no farbling** |
  | 30 | Fonts enumeration | `STANDARD_BUCKETED_TABLE_V1` — 9 script-coverage buckets (`FontBucket::ALL`); per-site full access via Module 59 (consulted at enumeration time via the `FontsGrants` trait; `DenyAllFontsGrants` is the v1 default) | `BUNDLED_FONT_SET_V1` — 15-font Tor-style allowlist (Arimo / Tinos / Cousine metric-compatible Latin + Noto coverage of CJK / Arabic / Urdu Nastaliq / Devanagari (also serves Hindi) / Thai / Bengali / Tamil + STIX Two Math + Noto Emoji); no per-site opt-in; L41 forbids loosening even with a hostile `FontsGrants` impl (L44 / Phase 5.5 Module 35.3) |
  | 31 | Battery API | **Removed** (`'getBattery' in navigator === false`); no permission-gate path | **Removed** (L44; same accessor patch as Standard); no permission-gate path |
  | 32 | Timers | 1 ms quantum (`Date.now` / `performance.now`) | 100 ms quantum (L43; Phase 5.5 Module 35.2 enforces L41) |
  | 33 | Timezone | Host timezone | UTC |
  | 34 | Navigator | `STANDARD_NAVIGATOR_PROFILE` — UA = `pb_network::DEVBROWSE_USER_AGENT`; language `"en-US"` / languages `["en-US", "en"]`; `hardwareConcurrency = 4` (most common real-world laptop); `device_memory_gib = 8`; `plugins.length = 0`; `mimeTypes.length = 0`; `webdriver = false`; `doNotTrack = "1"`; `globalPrivacyControl = true` | `STRICT_NAVIGATOR_PROFILE` — identical to Standard except `hardwareConcurrency = 2` (Tor Browser / Mullvad Browser / Firefox RFP cohort). Every other field byte-identical with Standard; JS-vs-HTTP UA alignment preserved by mode-invariant UA |
  | 35.6 | WebGPU adapter | Bucketed vendor class (Intel / NVIDIA / AMD / Apple / Other) + cohort-locked limits matching Module 28 WebGL bounds | `LOCKED_WEBGPU_PROFILE` cohort lock — vendor / architecture / driver pinned to Mozilla-cohort; cohort-safe limits; cross-coupling with Module 28 asserts vendor agreement so a renderer claiming `"Mozilla GPU"` via WebGL cannot claim `"Apple GPU"` via WebGPU |
  | 35.7a | Speech Synthesis voices | Locale-bucketed (Spanish-locale Standard users see Spanish-cohort voices, etc.; no specific voice enumeration) | Curated 4-voice cohort (`en-US`, `en-GB`, `ja-JP`, `ar-SA`) covering Latin / CJK / Arabic — accessibility preserved (Tor breaks screen readers) |
  | 35.7b | Media Capabilities | **Mode-invariant baseline lock** — H.264 / VP9 / AAC / Opus / MP3 supported; HEVC / AV1 unsupported regardless of hardware; EME / DRM unaffected | Same as Standard |
  | 35.8 | Network Information | Cohort-locked values (`effectiveType = "4g"`, `downlink = 10`, `rtt = 50`, `saveData = false`, `type = "wifi"`) — every Standard user reports same broadband cohort | **`navigator.connection` is `undefined`** (API removed entirely; L44 list) |
  | 35.9a | Permissions enumeration | Per-API query via Module 59; no bulk-enum surface | Returns `"denied"` for every L44 surface (Module 35.3) + every non-granted API; no bulk enumeration |
  | 35.9b | Storage estimate | `{quota: 1_073_741_824 (1 GiB), usage: 0}` cohort-locked; partition-key boundary hides per-origin usage | `{quota: 0, usage: 0}` (matches Tor) |
  | 35.10a | Display (DPR / colorDepth / pixelDepth / orientation) | Bucketed DPR `1.0 / 1.5 / 2.0 / 3.0` (closest-bucket preserves Retina UX); `colorDepth = 24` fixed; orientation native (mobile-responsive site compat) | `devicePixelRatio = 1.0`, `colorDepth = 24`, `pixelDepth = 24`, `orientation = landscape-primary / 0°` — locked desktop cohort (Retina UX accepted as Strict tradeoff) |
  | 35.10b | Touch surface (`maxTouchPoints` / `ontouchstart` / pointer / hover) | **Desktop:** `maxTouchPoints = 0`; pointer `fine` / hover `hover` (joins Strict desktop cohort per v1.23 amiunique-generic). **Phase 12 mobile:** native carve-out (preserves mobile UX) | **Desktop:** same as Standard desktop (`maxTouchPoints = 0`; pointer `fine` / hover `hover`). **Phase 12 mobile:** native carve-out (preserves mobile UX; Tor's universal `maxTouchPoints = 0` breaks responsive layouts) |
- Window position is **never exposed to content JS**, bucketed or otherwise
  (multi-monitor layout is itself a fingerprint).
- `InputEvent` carries no timestamp by design; future timestamps must be
  quantized to ≥1ms granularity in pb-fingerprint (Strict tightens to
  100 ms per L43).
- GPU timestamps are quantized to **2ms** in pb-gpu.
- The Mullvad-class hardening modules (35.1 letterboxer, 35.2 timer
  quantizer, 35.3 disabled-API surface, 35.4 settings-lock enforcement)
  ship as Phase 5.5, after Phase 5's WebIDL surface lands. See
  `project-plan/phase-5_5-strict-hardening.md`.

### 5.6 Unsafe code policy

- `#![forbid(unsafe_code)]` on every crate root by default.
- Crates needing FFI (currently planned: pb-fingerprint for Gecko WebIDL,
  pb-gpu for low-level bridges) downgrade to `#![deny(unsafe_code)]` and
  isolate unsafe to a single FFI module with `#[allow(unsafe_code)]` on it.
- Unsafe blocks remain visible in code review forever.

### 5.7 Update integrity

- All updates (binary, blocklist, HSTS preload, wrapper-compatibility manifest)
  are signed with **two-key HSM scheme** — one online key for normal release,
  one offline key for emergency revocation.
- Blocklist track has a 1-hour randomized fetch delay to prevent timing
  correlation across users.

### 5.8 OS sandbox

- Every renderer runs under an OS-level sandbox profile (seccomp on Linux,
  AppArmor profile, mac sandbox.plist, Windows job objects).
- Sandbox profiles live in the **`pb-sandbox` crate** (Module 12) and are
  applied before any renderer begins parsing untrusted content. v1.5 moved
  the typed profile out of `pb-identity` and into its own crate so that
  every spawn site (renderer, network broker, storage broker) can use it
  without taking a dep on `pb-identity`. The real syscall enforcement
  (Module 12.1, deferred) lands in the same `pb-sandbox` crate, with
  unsafe confined to a future `enforce` submodule per L13.
- The sandbox is the **kernel-level** boundary; the IPC trust boundary
  (§5.1) is the **process-level** boundary. Both hold simultaneously.

### 5.9 Memory zeroization

- Credentials (passwords, OAuth tokens, cookies marked Secure+HttpOnly)
  in memory must use the `zeroize` crate or equivalent at drop.
- Cross-cutting policy: any new struct holding a secret field uses
  `#[derive(Zeroize, ZeroizeOnDrop)]`.

### 5.10 Crash containment

- Renderer crashes **must not** propagate user-identifying data to crash
  reports (URLs, form contents, request bodies, identity profile names).
- Crash reports are scrubbed in-process before any disk write or network
  send. See Module 82.

### 5.11 Site-isolation tradeoff (Standard mode)

- Under §3.4, two **Standard** tabs of the same `identity_profile_id` may
  share a single renderer process even when they navigate to different
  top-level sites. This is intentional — it keeps the process count down
  for users who run dozens of tabs under one identity.
- Tradeoff: a malicious page co-resident with another site in the same
  renderer can attempt cross-site Spectre / Meltdown reads against
  in-process memory. The kernel sandbox (§5.8) does not mitigate
  same-process side channels.
- Mitigation in v1:
  - **Strict mode is per-tab renderer (§3.3)** — never co-resident with
    anything else. Users who need site-isolation guarantees use Strict.
  - **Cross-origin headers are honored.** Pages that send
    `Cross-Origin-Opener-Policy: same-origin` and
    `Cross-Origin-Embedder-Policy: require-corp` are placed in their own
    renderer regardless of `identity_profile_id` (Module 8 scheduler hook,
    deferred to Phase 5 alongside the WebIDL surface).
  - **Spectre mitigations stay enabled** at the Gecko level (process
    isolation primitives, JIT mitigations) for every renderer.
- Future: an opt-in "per-site renderer in Standard mode" toggle is reserved
  for Phase 8 (Module 52 settings) when we have benchmarks to show the
  process-count cost is acceptable. Lock it as deferred — do not ship
  without measurement.

---

## 6. Module plan

13 phases (Phase 1 through Phase 12, with Phase 11.5 between Orchestrator
and Mobile and Phase 11.9 between Sync and Mobile). 96 modules through
Phase 11.9; Phase 12 module count is reserved
and locked when that phase begins. Sub-files within a module are not
separately numbered. Phase numbering reflects dependency order.

### Phase 1 — Foundation (Modules 1–5)

| # | Module | Status |
|---|---|---|
| 1 | Workspace + Cargo setup | ✅ done |
| 2 | Platform adapter trait surface (5 adapters + capability `FileHandle` + `GestureToken` + `register_dropped_path`) | ✅ done |
| 3 | `pb-config` schema (Config struct, Mode enum, defaults, validation, atomic save, owner-only file mode) | ✅ done |
| 4 | `pb-ipc` transport (Tokio + Unix sockets, framing, max-message-size) | ✅ done |
| 5 | `pb-ipc` messages (protobuf types via prost-build) | ✅ done |

### Phase 2 — Identity (Modules 6–12)

| # | Module | Status |
|---|---|---|
| 6 | `IdentityProfile` struct + builder + validation | ✅ done |
| 7 | Profile registry + persistence wiring | ✅ done |
| 8 | Renderer scheduler (renderer-sharing rule §3.4) | ✅ done |
| 9 | Lifecycle (spawn → suspend → kill, immutable for tab) | ✅ done |
| 10 | Suspension semantics (tab freeze) | ✅ done |
| 11 | Identity warnings (signals to UI layer) | ✅ done |
| 12 | **OS sandbox profile** (seccomp / AppArmor / mac / Win) — `pb-sandbox` crate | ✅ done |

### Phase 3 — Storage (Modules 13–18)

| # | Module |
|---|---|
| 13 | Storage process bootstrap | ✅ done |
| 14 | Partition key derivation (sha256) | ✅ done |
| 15 | Gatekeeper (every read/write enforces partition key) | ✅ done |
| 16 | Storage primitives (cookies, cache, localStorage, sessionStorage; IndexedDB deferred) | ✅ done |
| 17 | Service worker isolation | ✅ done |
| 18 | Strict-wipe (per-identity wipe on tab close) | ✅ done |

### Phase 4 — Network (Modules 19–25)

| # | Module |
|---|---|
| 19 | `pb-network` coordinator (process bootstrap, request routing) |
| 20 | DNS — DoH client + whitelist |
| 21 | Blocklist (radix tree, loader, scheduler) |
| 22 | Headers (request scrubbing, identity-aware) |
| 23 | **TLS / cert policy** (root choice, CT enforcement, revocation) |
| 24 | **JA3 reduction / client-hello control** |
| 25 | **WebRTC constraint** (peer connection, mDNS hostnames, ICE candidate filtering) |

### Phase 5 — Fingerprint (Modules 26–35)

| # | Module |
|---|---|
| 26 | WebIDL override interface |
| 27 | Canvas readback normalization |
| 28 | WebGL parameter normalization |
| 29 | Audio context / Web Audio normalization |
| 30 | Fonts enumeration normalization |
| 31 | Battery API |
| 32 | Timers (`Date.now`, `performance.now`, `performance.timing`) |
| 33 | Timezone |
| 34 | Navigator (UA, plugins, languages, hardwareConcurrency, deviceMemory) |
| 35 | WebKit stub (Safari-style identification for compat) |

### Phase 6 — GPU (Modules 36–39)

| # | Module |
|---|---|
| 36 | GPU coordinator |
| 37 | Memory budget (per-identity caps) |
| 38 | Queue (per-identity isolation) |
| 39 | Timing quantization (2ms) |

### Phase 7 — Extensions (Modules 40–41)

| # | Module |
|---|---|
| 40 | Extension blocker (strict mode enforcement) |
| 41 | Extension controller (standard mode passthrough) |

### Phase 8 — UI (Modules 42–64)

| # | Module |
|---|---|
| 42 | UI shell (Iced backbone) |
| 43 | Address bar (with suggestion privacy posture, default DDG) |
| 44 | Tab bar |
| 45 | Tab search |
| 46 | New tab page |
| 47 | Find in page |
| 48 | History |
| 49 | Bookmarks |
| 50 | Downloads |
| 51 | Notifications (chrome-side, calls `NotificationAdapter`) |
| 52 | Settings |
| 53 | Strict mode popup (mode switcher) |
| 54 | Reader mode |
| 55 | Print (with print-to-PDF) |
| 56 | Picture-in-picture |
| 57 | Zoom |
| 58 | **Modern file picker UI** (drop zone + recent picks chrome) |
| 59 | **Permission center** (visible permission lifecycle UI) |
| 60 | **Network viewer** (privacy trust panel — "mini Wireshark") |
| 61 | **Site customizer** (visual element zapper, emits cosmetic filter rules) |
| 62 | **PDF viewer** (pdf.js sandboxed renderer) |
| 63 | DevTools (Gecko built-in, blocked in strict — see L16) |
| 64 | **First-launch setup wizard** (`pb-wizard` UI module) — per-feature opt-in (L23) |

### Phase 9 — Update pipeline (Modules 65–70)

| # | Module |
|---|---|
| 65 | Update manifest (TOML, signed) |
| 66 | Update signing (two-key HSM) |
| 67 | Blocklist track fetcher (1-hour randomized delay) |
| 68 | **HSTS preload track fetcher** |
| 69 | Wrapper compatibility checker |
| 70 | Canary (staged rollout) |

### Phase 10 — Adversarial fingerprint surface tests (Modules 71–79)

Nine modules of adversarial test suites, one per major fingerprint surface.
Each test exercises the surface from JS in worker, iframe, top-frame, and
service-worker contexts to catch normalization gaps.

### Phase 11 — Orchestrator (Modules 80–82)

| # | Module |
|---|---|
| 80 | Startup sequence |
| 80.5 | **OS sandbox enforcement (Module 12.1)** — real seccomp-bpf (Linux) / AppArmor profile (Linux) / `sandbox_init` plist (macOS) / Windows Job Object + Restricted Token. Lands in `pb-sandbox` with `unsafe` confined to a private `enforce` submodule (`#![deny(unsafe_code)]` + `#[allow(unsafe_code)]` on that one module per L13). **v1.0 ship blocker** — Module 12 v1 ships only the typed profile + `apply()` no-op; without 80.5 the kernel boundary in §5.8 is documentation, not enforcement. |
| 81 | Graceful shutdown |
| 82 | **Crash containment + report scrubbing** |

### Phase 11.5 — Sync (Modules 83–92)

End-to-end encrypted, LAN-first cluster sync. No DevBrowse server, no SaaS
cloud backends. Three transport tiers in priority order:

  1. **Direct LAN** (T1) — mDNS discovery + QUIC + Ed25519 mTLS. Default.
  2. **Hub-peer forwarding** (T2) — any paired device can opt in as a hub
     to store-and-forward encrypted blobs for offline cluster members.
  3. **Self-hosted relay** (T3) — optional WebDAV; off by default. Only
     transport tier that crosses networks; user must run the server.

Initial pairing requires both devices on the same WiFi (LAN-only by design).
Sync is foreground-only; mobile background sync is explicitly out of scope.
Crate is single `pb-sync`. Password manager UI is its own future phase.

| # | Module |
|---|---|
| 83 | **Vault crypto** — Argon2id (passphrase → master key), HKDF key ladder, XChaCha20-Poly1305 AEAD per blob, `zeroize` for in-memory secrets. Versioned vault format (L24). |
| 84 | **Sync log** — per-record append-only op log, vector clocks, periodic compaction. LWW for tabs / history / bookmarks; per-record conflict surfacing for credentials (no silent overwrite). Each entry signed by originating device's Ed25519 key (tamper evidence even at hub-peer). |
| 85 | **Local backup / import** — export vault to a single user-controlled file; import on another device. Same format as cluster sync. |
| 86 | **LAN discovery** — mDNS service announce + browse for cluster devices on the local network. |
| 87 | **LAN pairing** — SPAKE2 PAKE bootstrapped from a 6-digit code, mandatory 4-emoji fingerprint compare, Ed25519 identity key exchange. Both mDNS-list and QR-scan flows. Code expires in 90 seconds; max 5 wrong attempts then code burns (rate limit defeats online brute force of the 1M code space). Identity keys persisted via OS keystore (macOS Keychain / iOS Keychain / Win DPAPI / Android Keystore / libsecret). |
| 88 | **LAN transport** — QUIC over UDP, mTLS via pinned Ed25519 keys (no CA), per-pair monotonic sequence numbers, 5-minute replay window. Forward secrecy via QUIC handshake. |
| 89 | **Hub-peer forwarding** — per-device opt-in. Encrypted blobs queued for offline cluster members; recipient pulls; hub deletes after delivery. Per-recipient X25519 envelopes for direct-message blobs ensure hub cannot read them. |
| 90 | **Send tab to device** — URL + title + scroll position, encrypted to recipient device's X25519 key. Auto-open with toast (`Open / Dismiss / Undo`) when recipient browser is foreground; queued banner on next launch otherwise. Source device + URL preview always shown; never silent. |
| 91 | **Cluster key rotation** — on unpair, on schedule (90 days), on user request. Re-encrypt vault, re-sign sync log, broadcast new key to remaining cluster members. Removed device's stored data becomes useless. |
| 92 | **Self-hosted relay (WebDAV)** — last-resort cross-network transport. Same encrypted-blob protocol as hub-peer; relay sees ciphertext only. Off by default. Hosted DevBrowse relay explicitly not in scope. |

### Phase 11.9 — Windows hardening (Modules 93–96)

Windows support is deferred to its own phase. Pre-existing Windows code paths
(named-pipe IPC backend, ACL stubs, default `%APPDATA%` resolution) have been
stripped in v1.9 and replaced with `compile_error!` markers so a Windows build
fails fast rather than ships half-implemented. CI continues to target
Linux + macOS only until this phase is executed.

Rationale: Windows requires its own threat-model pass (DACLs, AppContainer,
Job Objects, named-pipe security descriptors, DPAPI for keystore, Mark of the
Web propagation, SmartScreen bypass risk on update) that cannot be safely
bolted on alongside the cross-platform foundation. Treating it as a discrete
phase forces the same security review depth Linux/macOS already received.

Phase entry criteria: Phase 11.5 complete, ship-blockers in Phase 11 closed,
test infrastructure capable of Windows CI (Azure / GitHub Windows runners).

| # | Module |
|---|---|
| 93 | **Windows IPC** — Named-pipe backend with two-pipe duplex (one per direction) so reads and writes never serialize through a shared lock. Per-pipe security descriptor restricts the ACL to the current user SID. Same 4-byte BE length-prefix framing as Unix; identical public API on `IpcListener` / `IpcConnection` / `IpcReadHalf` / `IpcWriteHalf`. |
| 94 | **Windows file ACLs** — `pb-config` + `pb-storage` config/db/data-dir DACL enforcement: explicit ACL granting only the current user SID, inheritance disabled. Applied at first write and re-verified on every load (mirrors the Unix 0700/0600 pass). DPAPI-protected secret blobs for any pre-keystore credential cache. |
| 95 | **Windows kernel sandbox** — `pb-sandbox::SandboxProfile::apply` Windows path: AppContainer per renderer, restricted SID tokens, Job Object with `JOB_OBJECT_LIMIT_BREAKAWAY_OK = false`, mitigation policies (`PROCESS_MITIGATION_*`: ACG, CIG, BlockNonSystem fonts, image-load restrictions). Mark-of-the-Web honored on download writes. |
| 96 | **Windows update + signing** — Signed MSI / MSIX build path with timestamped Authenticode signature plus the dual-signing posture from L39 (offline GPG + Sigstore Rekor). SmartScreen reputation bootstrap plan documented. Update channel uses the same blocklist-fetcher contract as desktop (Module 65) — no Windows-specific update protocol. |

### Phase 12 — Mobile (iOS / Android) (Modules 97+, scope reserved)

Mobile is **in scope, design-disciplined throughout Phases 1–11.5**: no path
strings on trait surfaces, no Iced types in core crates, no Tokio assumptions
in shared logic. Mobile implementation is additive, not a rewrite.

iOS engine: **WebKit (`WKWebView`)** — App Store policy 2.5.6 forbids
non-WebKit engines outside the EU. EU/Gecko-on-iOS is a stretch goal pending
Mozilla's own iOS Gecko build.

Android engine: **GeckoView** (Mozilla's Java/Kotlin libxul wrapper).

Module list locks when the phase begins. Reserved areas:

| Area | Notes |
|---|---|
| `EngineAdapter` trait | `GeckoEngine` (desktop + Android), `WebKitEngine` (iOS). Lands ahead of any mobile-specific module so the abstraction is in place. |
| Build pipelines | `cargo-lipo` + `xcframework` for iOS; cargo + JNI + Gradle for Android. |
| iOS UI shell | SwiftUI; chrome design from §8 ported to native idioms. |
| Android UI shell | Jetpack Compose; chrome design from §8 ported to Material. |
| Capability adapters | `UIDocumentPicker` (iOS), Storage Access Framework (Android) — both already capability-shaped, fit `FileHandle` model directly. |
| Sandbox | Delegates to OS app sandbox (iOS/Android handle this themselves). Module 12 (`pb-sandbox` kernel sandbox) is desktop-only; `apply()` is a no-op on iOS/Android. |
| Sync transport | Same `pb-sync` crate as desktop. Mobile uses LAN discovery + QUIC + Ed25519 mTLS identically. SAF (Android) and `UIDocumentPicker` (iOS) only matter for the local-backup file (Module 85), not for cluster sync. |

---

## 7. Deferred / open decisions

| Decision | Status | Notes |
|---|---|---|
| Password manager | Deferred | Decide between: ship one, integrate via Secret Service / KeePassXC, or punt. |
| Form autofill | Deferred | Tied to password manager decision. |
| `hyper-rustls` trust store: webpki-roots vs system | Deferred | Decision lands in Module 23. |
| `tokio` per-crate feature trimming | Deferred | Trim when each crate has real code. |
| Pin GitHub Actions to commit SHAs | Deferred | Acceptable risk to leave on tag refs. |
| Terminal in place of JS console (Idea 1) | **Rejected (locked)** | DevTools console stays standard. Replacing it with a shell creates an arbitrary-code-execution surface inside the browser process, breaks DevTools muscle memory for every web developer, and adds maintenance burden with no privacy benefit. Wizard occupies Module 64. |
| Visual editor (Idea 2) | Reframed | Site Customizer (Module 61) is the privacy-aligned version; full visual editor not pursued. |
| Tab discard under memory pressure | Deferred | UX, not security. |
| Passkey sync across devices | Deferred (post-v1) | Native passkeys are hardware-bound (Secure Enclave / StrongBox / TPM). Syncing them requires shipping our own software FIDO2 authenticator inside the vault. Out of scope for v1; revisit when password manager UI lands. |
| Plugin / extension model beyond passthrough | **Closed (locked v1.10)** | Curated allowlist only; no generic plugin SDK in v1. Future "Plugin / extension SDK" entry remains in Future Improvements §11. |
| Extension distribution surface (link to addons.mozilla.org / bundled store / manual `.xpi` only) | **Closed (locked v1.10): curated signed allowlist via Module 65 update channel.** No AMO link in chrome, no bundled in-app store, no manual `.xpi` side-load. Allowlist updates ship through the same signed-manifest pipeline as the blocklist track (Module 67). | Removes the AMO ToS / Mozilla-branding / trademark exposure entirely; trades extensibility for a much smaller security review surface. |
| Extensions inspecting or modifying outbound traffic (webRequest-style hook) | **Closed (locked v1.10): no.** Allowlisted extensions do not receive outbound-traffic inspection. pb-network has no extension hook surface. | Honors L30 / L33; keeps the partition-key gatekeeper as the sole authority over network state. If a genuinely needed allowlisted extension ever requires this, reopen via architecture revision. |

---

## 8. UX flagship features

These are the user-visible elements that **change the defaults** of the
browser category. They must ship with v1 to differentiate.

1. **Identity selector in tab bar** — switching identity is one click, not
   buried in profiles. The tab strip shows current identity label.
2. **Strict mode toggle** with clear visual treatment — strict tabs are
   visibly distinct so users always know their state.
3. **Network viewer** (Module 60) — real-time privacy trust panel showing
   blocked trackers, DoH paths, partition decisions per request.
4. **Site customizer** (Module 61) — right-click → kill this overlay /
   hide this tracker / dim this section, persisted as cosmetic rules.
5. **Modern file picker** (Module 58) — drag-drop first, OS picker behind
   "Browse...", recent picks as quick chips.
6. **Permission center** (Module 59) — every grant visible, every grant
   revocable, history of what asked for what.
7. **Inline PDF viewer** (Module 62) — sandboxed pdf.js, with explicit
   download fallback.

---

## 9. Versioning and lock policy

- Semver for the binary: `0.x` until Module 82 ships and an end-to-end
  privacy review passes; `1.0` thereafter.
- "Lock" in this doc means: **no silent change**. Breaking a lock requires:
  1. A revision-log entry (§10) with date, what changed, why.
  2. Explicit user acknowledgment in conversation.
  3. Updates to all affected SECURITY INVARIANT comments in code.

---

## 10. Revision log

| Date | Revision | Notes |
|---|---|---|
| 2026-04-27 | v1.0 — initial lock | All decisions through Module 2.1 hardening. Locks L1–L20. |
| 2026-04-27 | v1.1 — mobile + sync + wizard | Mobile (iOS/Android) moved from non-goal to Phase 12 (design-disciplined now, implemented later). Sync added as Phase 11.5 (BYO-cloud, E2E client-side). Locks L21–L24. Wizard takes Module 64 slot; Terminal moved to Future Improvements (§11). |
| 2026-04-27 | v1.2 — DoH whitelist | L25 added: curated DoH provider set (NextDNS default, Cloudflare, Quad9, custom HTTPS), System DNS gated to Standard mode only. Reflected in `pb-config` schema (`DohProvider` enum) and validated at load/save time. Aligns config with the pre-existing pb-network whitelist stub. |
| 2026-04-28 | v1.3 — DoH default + counters / logging / UI / history locks | L25 default flipped from NextDNS to **Quad9** (NextDNS without an account config ID adds no privacy value as a silent default; wizard now enforces config-ID entry and persists as `Custom { url }`, falling back to Quad9 if declined). L26 added: tracker/ad block counters surfaced in address-bar badge + Network Viewer (always local, never persisted). L27 added: ephemeral RAM-only debug logs by default, opt-in disk logs are redaction-gated, no network egress without per-session user consent. L28 added: modern translucent UI design intent — sidebar-hover default with bookmark icon column, top/vertical layouts opt-in; accessibility floor locked alongside (reduce-transparency honored, WCAG AA, full keyboard nav). L29 added: standard-mode history retention selector (`forever \| session \| week \| month`, default `forever`); strict still never writes history. Schema reflects L25 default; UI/history config keys land with their respective modules to avoid orphaned fields. |
| 2026-04-28 | v1.4 — Cross-platform principle locked; schema gaps closed; UI module stubs added | **Cross-platform rule locked:** every crate in the workspace must compile on Linux, macOS, and Windows at all times. Platform-specific code is gated by `#[cfg(unix)]` / `#[cfg(windows)]` within a single module; the public API surface is identical on all platforms. **IPC transport (L4):** Unix backend uses AF_UNIX domain sockets (`tokio::net::UnixStream`). Windows backend uses named pipes (`tokio::net::windows::named_pipe`) with the same 4-byte BE length-prefix framing. `split()` on Windows serializes through a `Mutex` (single handle, not two-pipe duplex); upgrade to two-pipe if benchmarks show contention. A `compile_error!` guards all other platforms. **Schema gaps closed:** `HistoryConfig { retention }` (L29), `LoggingConfig { disk_logging_enabled }` (L27), and `UiConfig { tab_layout, reduce_transparency }` (L28) added to `pb-config` schema with correct locked defaults. **UI module stubs added:** Modules 58–62, 64 (file picker UI, permission center, network viewer, site customizer, PDF viewer, first-launch wizard) stubbed in `pb-ui` with full invariant comments. |
| 2026-04-28 | v1.5 — Sandbox split into its own crate | Module 12 (OS sandbox profile) moved out of `pb-identity` and into a new top-level `pb-sandbox` crate. Workspace expanded from 12 to 13 crates. L12 amended: any crate may import `pb-ipc`, `pb-config`, **and `pb-sandbox`**; previously only the first two. Rationale: (1) `SandboxClass::Network` / `SandboxClass::Storage` are not identity concepts — putting them in `pb-identity` was a category error that scaled poorly; (2) `pb-storage` and `pb-network` need a sandbox profile but should not depend on `pb-identity` to get one; (3) Module 12.1 (real syscall enforcement) needs `unsafe`, and consolidating types + enforcement in one dedicated crate is more auditable than splitting policy across `pb-identity` + impl across `pb-platform`. Behavioral surface unchanged (same types, same `apply()` no-op contract). §4 topology, §5.8, and §6 Phase 2 module table updated to match. |
| 2026-04-30 | v1.8 — Terminal-in-place-of-console rejected (locked) | Idea 1 (replace JS console with a real shell) moved from "deferred indefinitely" to **rejected**. Reasons: arbitrary-code-execution surface inside the browser process, breaks DevTools muscle memory, maintenance burden with no privacy payoff. Removed from §11; §7 row updated to "Rejected (locked)". |
| 2026-05-27 | v1.24, Phase 8 UI stack lock + design-token codegen + in-app glass | **L3 refined (no breaking change):** UI stack locked at Iced 0.14 (upgrade from 0.13) for desktop, native SwiftUI / Jetpack Compose shells for mobile (Phase 12), all consuming a shared renderer-agnostic design-token JSON via build-time codegen. The Phase 7.5 design glass is **in-app**, not OS-vibrancy: chrome capsules sample the app's own wallpaper layer with a Gaussian blur, the app window itself stays opaque. **Module 42 foundation: `pb-ui::glass` custom wgpu blur widget** (single WGSL Gaussian / Kawase blur shader + saturate color matrix + Iced custom-widget wrapper, ~200-300 LOC total). One shader, identical pixel output on Vulkan (Linux / Android) + Metal (macOS / iOS) + DX12 (Windows) to within float-LSB tolerance. Every other Phase 8 module (URL bar, sidebar, identity capsule, settings sheet, permission capsule, network viewer) composes glass surfaces from this single primitive. **Design-token codegen:** `design/tokens.json` is the source of truth for renderer-agnostic numeric primitives (blur_sigma_px, tint_rgba, corner_radius_px, spring_stiffness, animation_duration_ms, palette colors); build-time transforms emit `tokens.rs` (Rust constants consumed by `pb-ui`), `tokens.swift` (iOS Phase 12 shell), and `tokens.kt` (Android Phase 12 shell). Brand consistency is preserved across platforms without forcing a single rendering engine. Adopting a new platform later (visionOS, embedded Linux) means writing a new token consumer, not porting the chrome. **Future OS vibrancy path:** Phase 8 ships opaque windows + in-app glass; OS-level vibrancy (NSVisualEffectView on macOS, DWM Mica / Acrylic on Windows, KWin blur on Linux when supported) added later via the `window-vibrancy` crate (MIT, Tauri team) behind a Settings toggle. Zero refactoring of the chrome code, one feature-flag addition. **Rejected alternatives (decisive evidence):** (a) **Gecko chrome document everywhere** (the Firefox model): Mozilla publishes no stable embedding API, every libxul tag bump would double Module 69 audit scope, GeckoView has no public chrome-document API (Mozilla's own Fenix uses Kotlin / Compose, not HTML / CSS), iOS forces WebKit so chrome would be two CSS engines anyway, and placing the chrome JS in libxul's parent process collides with the broker-isolation model that gives L40 its bite. (b) **Tauri 2.x + system WebView (HTML / CSS chrome):** `backdrop-filter` is broken on WebView2 (Windows transparent windows, [tauri/12804](https://github.com/tauri-apps/tauri/issues/12804)), severely limited on WebKitGTK 4.1 / 6.0 Linux ([tauri/8808](https://github.com/tauri-apps/tauri/discussions/8808)), and renders black boxes on Android System WebView ([react-native-webview/3469](https://github.com/react-native-webview/react-native-webview/issues/3469)). Three of five target platforms fail the core glass requirement. Also adds a second browser engine on top of libxul for content, worst memory shape. (c) **Slint 1.x + Skia:** per-element `ImageFilter::Blur`, not a backdrop sample of the chrome scene behind a panel; `.slint` DSL build step and ~15 MB Skia binary bloat for marginal benefit. (d) **Flutter desktop + flutter_rust_bridge:** desktop has no public PlatformView API for embedding Gecko's content surface, Impeller is not yet default on Linux desktop (BackdropFilter regressions in 3.32, [flutter/169508](https://github.com/flutter/flutter/issues/169508)). **Memory / CPU / battery numbers (estimated, idle, 1 window 5 tabs, desktop):** Iced + wgpu ~40-60 MB chrome layer (~440 MB total RSS including libxul + 5 content procs); Gecko chrome ~100-180 MB chrome layer (+60-120 MB vs Iced); WebKit-WebView chrome ~120-180 MB chrome layer (+80-120 MB vs Iced, second engine loaded). Iced chrome animation at 60fps ~2-4% CPU vs ~8-15% for Gecko chrome vs ~10-18% for WebKit-WebView (no JS event loop in Iced). Battery on MacBook Pro M3 8h: Iced-class baseline ~1-2%, HTML / CSS chrome ~5-10%. **Industry-pattern validation:** 1Password, Signal, Firefox-on-mobile (Fenix Kotlin + Firefox-iOS Swift), Brave-on-mobile all use shared Rust / C++ core + per-platform native UI. No production browser uses one UI framework across all five platforms. Arc Browser (The Browser Company) explicitly migrated away from SwiftUI to lower-level Swift / AppKit for performance, then built Swift-WinRT for the Windows port. The current architecture's L3 + §6 mobile plan is industry-validated. **No L-invariants added or changed.** This is a refinement of L3's "Why" column plus a lock on the implementation strategy. Phase 8 Module 42 now starts on the locked stack in a fresh chat per CLAUDE.md phase-boundary discipline. |
| 2026-05-19 | v1.23 — Phase 5.5 scope expansion + Standard cohort-base + farbling for Modules 27 / 28 / 29 | **Phase 5.5 grows from 4 to 10 sub-modules. Standard posture target locked at Brave+ / Firefox 119+ ETP parity with amiunique-generic; Strict posture target locked at Tor / Mullvad+ parity.** Triggered by the Phase 5 exit audit which identified two gaps: (a) Standard mode native-passes-through canvas / WebGL / audio (worse than Brave's per-session farbling), and (b) modern fingerprint surfaces — WebGPU, Speech Synthesis voices, Media Capabilities, Network Information, Permissions enumeration, Storage estimate, Display capabilities, Touch surface — are not covered by Phase 5's 8-module §5.5 matrix. **Posture targets:** Standard mode shows every DevBrowse Standard user the same static cohort identity (UA, fonts, WebGL vendor / extensions, codec list, voices, network info, storage, display, touch — amiunique reports a generic DevBrowse Standard cohort) while the dynamic readback surfaces (canvas, audio, WebGL numeric MAX_*) carry per-(origin, IdentityProfile) deterministic farbling layered on top so cross-site tracking is defeated AND same-site identity is stable across browser restarts (UX preserved; structurally better than Brave's per-session reshuffle). Strict mode = pure cohort lock on every surface (no farbling); structurally better than Tor / Mullvad on WebGPU (kept usable; Tor disables entirely), Speech Synthesis (accessibility preserved; Tor breaks screen readers), and Phase 12 mobile (preserves mobile UX; Tor breaks responsive layouts). **Module 27 / 28 / 29 refactor (lands in Module 35.5):** Standard's `*ReadbackPolicy::NativePassThrough` variant is **deleted**; each policy collapses to one parameterized variant `Normalized { profile, farbling: Option<&'static FarblingProfile> }`. `for_mode(Strict)` resolves to `farbling: None`; `for_mode(Standard)` resolves to `farbling: Some(&STANDARD_FARBLING_PROFILE)`. Standard now activates the libxul rasterizer / DSP / WebGL hooks (currently no-op for Standard) with farbling on the readback — supersedes the v1.12 / v1.13 / v1.14 cohort-by-choice posture decisions for these three modules. Module 28 Standard now reports `"Mozilla"` vendor / renderer + the 5-extension cohort allowlist (was: native). Module 29 Standard now activates `CompressorImpl::CohortLocked` + `DspPath::ScalarReference` (was: native). **Farbling seed source (cross-crate change):** Module 14 (pb-storage) gains a `PartitionKey::farbling_seed()` accessor returning a 16-byte HKDF-derived seed from `(partition_key.bytes, "devbrowse-fp-farbling-v1")`. Deterministic per-(origin, profile_id) since `partition_key` already keys on those (L7 / §3.5); reuses workspace `hkdf` per L22. **New §5.5 surfaces (lands in Modules 35.6-35.10):** WebGPU adapter normalization (cohort-locked vendor matching Module 28 WebGL; WebGPU stays functional — ahead of Tor); Speech Synthesis + Media Capabilities (4-voice cohort preserving accessibility — ahead of Tor; codec baseline lock both modes); Network Information API (Strict removes the API entirely, joining L44; Standard cohort-locks to broadband values); Permissions enumeration + Storage estimate (Strict denies L44 surfaces + locks storage to `{0, 0}`; Standard queries Module 59 per-API + locks storage to 1 GiB cohort); Display + Touch (DPR bucket 1.0 / 1.5 / 2.0 / 3.0 preserving Retina UX; Standard desktop joins Strict's `maxTouchPoints = 0` desktop cohort; Phase 12 mobile carve-out preserves mobile UX — ahead of Tor). **Module 26 `WebIdlSurface::ALL` grows from 8 to 16 variants** across the new sub-modules. The libxul bridge exhaustive-match contract enforces lockstep updates. **Phase 5 / Phase 5.5 boundary clarification:** Phase 5 (now complete) shipped the WebIDL trait surface + 10 Phase-5 modules with per-Module Mode-applicability locks. Phase 5.5 ships (i) the Mullvad-class hardening locks L41-L44 (35.1-35.4, already planned), (ii) the v1.23 Standard cohort-base + farbling refactor (35.5), and (iii) the modern fingerprint surface coverage (35.6-35.10). No new L-invariants; the posture targets are codified in the Phase 5.5 plan-file header. |
| 2026-05-19 | v1.22 — Module 35 WebKit stub + Phase 5 complete | **Module 35 (WebKit backend stub) shipped — Phase 5 is now complete.** Module 35 is **not a Gecko WebIDL plumb-in** (per the Module 26 interface comment); it is the Phase 12 iOS scaffolding for the WebKit-backed mobile build. WebKit on iOS does not expose Gecko-style WebIDL override points (the L8 mechanism used by Modules 27-34), so Phase-5 normalization on iOS is best-effort UA-level only. The stub ships the surface today so Phase 12 can implement against a stable contract. `WEBKIT_STUB_PROFILE` documents the iOS Safari 17 + iPhone cohort identity DevBrowse-on-iOS naturally inherits (UA = iOS Safari 17 string, vendor = "Apple Computer, Inc.", platform = "iPhone"). `WebKitNormalizationSurface::ALL` enumerates the 8 Gecko-side Phase-5 modules (Canvas, WebGl, Audio, Fonts, Battery, Timers, Timezone, Navigator); `capability_v1()` returns `Unsupported` for all 8 in v1 (Phase 12 may promote specific rows — most likely Timers → BestEffort via `setTimeout` shimming). `WebKitStub::new(mode)` accepts a Mode argument for cross-platform API symmetry but behavior is mode-invariant (Strict on iOS cannot reach Tor-grade normalization because the engine does not expose the hooks; UX path is to redirect Strict-on-iOS users to desktop builds or Tor Browser's iOS variant). Edge case enforced: the stub UA does NOT advertise DevBrowse / Firefox / Gecko branding (the historical `"(KHTML, like Gecko)"` Safari compatibility token IS preserved — required for cohort overlap with real Safari). Apple Pay etc. work naturally on iOS because the underlying engine IS WebKit; Module 35 is NOT a Safari-impersonation layer for desktop Gecko (Module 34 keeps the desktop UA locked to Firefox). **Phase 5 module count: 10 modules (26-35) all done.** Phase 5 exit gate (cumulative cargo + Phase 10 adversarial suite + pb-testkit cross-phase contract tests) is the next checkpoint before Phase 5.5. No L-invariants added or changed; this is the per-Module Mode-applicability lock the v1.12 matrix demanded for Module 35, completing the Phase-5 ratification cycle. |
| 2026-05-19 | v1.21 — Module 34 Navigator `hardware_concurrency` per-Mode split | **Refines v1.20.** `hardware_concurrency` is now per-Mode: **Standard = 4** (kept; most common real-world laptop value; the cohort sites already optimize Web Workers against); **Strict = 2** (matches Tor Browser, Mullvad Browser, and Firefox `privacy.resistFingerprinting`). The cohort-overlap rationale: Tor / Mullvad / Firefox-RFP all lock to 2, so Strict users gain direct fingerprint overlap with the largest privacy-aware browser population on the public web. v1.20's mode-invariant `LOCKED_NAVIGATOR_PROFILE` is replaced by two profile statics: `STANDARD_NAVIGATOR_PROFILE` (hardware_concurrency = 4) and `STRICT_NAVIGATOR_PROFILE` (hardware_concurrency = 2). **Every other field is byte-identical across both profiles** — UA, app_name / app_version / vendor / platform / product / product_sub, language / languages, device_memory_gib = 8 (Tor/Mullvad parity, no change), do_not_track, global_privacy_control, webdriver, plugins_count, mime_types_count — asserted by `standard_and_strict_share_every_field_except_hardware_concurrency`. Why split only `hardware_concurrency` and nothing else: it has no HTTP analog (unlike UA / Accept-Language) so the per-Mode split does not create a JS-vs-HTTP fingerprint mismatch; the cohort gain is the highest-value privacy lock available on this field. `device_memory_gib` stays mode-invariant at 8 because Tor / Mullvad / Firefox-RFP all use 8 (the largest common Web spec bucket) — no cohort-overlap incentive to split. The §5.5 matrix row 34 is updated to name the per-Mode `hardware_concurrency` divergence; the Module 34 phase-file entry is refined accordingly. Posture name in §3.3 / §3.2 framing: "mostly mode-invariant with one cohort-divergent field" — a new variant of the Phase-5 posture taxonomy that future modules may also adopt. No L-invariants added or changed. |
| 2026-05-19 | v1.20 — Module 34 Navigator mode-invariant lock + last §5.5 row closed | **Module 34 (Navigator) shipped:** **mode-invariant locked** (fourth Phase-5 posture instance after Modules 22 / 31; the last Phase-5 module with the §5.5 row 34 flipped from "Mode TBD" to a concrete lock). Both `Mode::Standard` and `Mode::Strict` resolve to `NavigatorPolicy::Locked(&LOCKED_NAVIGATOR_PROFILE)`. Rationale: a JS-vs-HTTP UA mismatch is itself a fingerprint signal, and Module 22 already locked the network-side UA / Accept-Language for both modes — the JS-side Navigator must stay aligned per mode. The locked profile pins UA = `pb_network::DEVBROWSE_USER_AGENT` (`"Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"`), `appName = "Netscape"`, `appVersion = "5.0 (X11)"`, `vendor = ""`, `platform = "Linux x86_64"`, `product = "Gecko"`, `productSub = "20100101"`, `language = "en-US"`, `languages = ["en-US", "en"]`, `hardwareConcurrency = 4` (Tor RFP parity), `device_memory_gib = 8` (common Web spec bucket), `doNotTrack = "1"` + `globalPrivacyControl = true` (matches Module 22 `send_dnt` + `send_sec_gpc`), `webdriver = false`, `plugins_count = mime_types_count = 0` (industry consensus; Firefox 52+). `NavigatorSurface::ALL` covers 17 accessors: UA / AppName / AppVersion / Vendor / Platform / Product / ProductSub / Language / Languages / HardwareConcurrency / DeviceMemory / Plugins / MimeTypes / UserAgentData (Client Hints object) / Webdriver / DoNotTrack / GlobalPrivacyControl. Dynamic-state accessors (`onLine`, `cookieEnabled`) intentionally excluded — they reflect runtime state from pb-network / pb-storage, not the cohort surface. **Cross-module alignment via paired literal-string regression tests:** pb-fingerprint and pb-network are L12 sibling leaves (neither imports the other), so the UA / Accept-Language alignment is enforced by hardcoded expected literals in both crates' test modules (3 alignment tests in `pb-fingerprint::gecko::navigator::tests` + 2 in `pb-network::headers::tests`). Phase 10 adversarial suite is the third defense (live JS-vs-HTTP equality check on a spawned renderer). The Module 22 TODO at `pb-network/src/headers.rs:54-55` ("Module 34 owns the canonical value once it lands") is now resolved in spirit — direct ownership-transfer to pb-fingerprint blocked by L12, so the v1 approach is duplicated constants + paired tests + Phase 10 live check. **Phase 5's §5.5 matrix is now fully populated** — no remaining "Mode TBD" rows; only Module 35 (WebKit stub) remains pending in Phase 5. No L-invariants added or changed. |
| 2026-05-19 | v1.19 — Module 33 Timezone configurability refinement | **Strict stays UTC-non-configurable (Tor / Mullvad-style); Standard gains explicit user-configurable timezone selection (Firefox-style).** Refines v1.18's two-variant policy to a three-variant `TimezonePolicy { NativePassThrough, UserConfigured(&'static TimezoneProfile), NormalizedUtc(&'static TimezoneProfile) }`. New constructor `for_mode_with_user_selection(mode, Option<&'static TimezoneProfile>)` bakes L41 enforcement directly into the API: for `Mode::Strict` it returns `NormalizedUtc(&LOCKED_TIMEZONE_PROFILE)` **regardless of any supplied user selection** (asserted by `strict_ignores_user_timezone_selection` against `Asia/Tokyo`, `America/New_York`, `Europe/Berlin`, and `None`). For `Mode::Standard`, `Some(tz)` resolves to `UserConfigured(tz)` and `None` falls back to `NativePassThrough` (host TZ default). The `COMMON_TIMEZONES` curated list ships 10 `&'static TimezoneProfile` singletons: UTC (aliased to `LOCKED_TIMEZONE_PROFILE` as the first entry so Standard users picking UTC share the exact same static as every Strict renderer — cohort unification), `America/Los_Angeles` (PST -480, DST), `America/Chicago` (CST -360, DST), `America/New_York` (EST -300, DST), `Europe/London` (GMT 0, DST), `Europe/Berlin` (CET +60, DST), `Asia/Kolkata` (IST +330, no DST), `Asia/Singapore` (SGT +480, no DST), `Asia/Tokyo` (JST +540, no DST), `Australia/Sydney` (AEST +600, DST). The curated rather than free-form approach keeps every user-selected TZ on a known static so the cohort surface is analyzable; per-IANA-name `offset_minutes` is the standard-time baseline, with the libxul-side IANA database resolving DST at request time when `dst_observed = true`. Per-identity storage of the user's selection deferred to pb-identity (Module 6); Module 33 ships the policy surface today. §5.5 matrix row 33 unchanged in shape; v1.19 documents the configurability path explicitly. No L-invariants added or changed; this refines v1.18's Mode-applicability lock to encode Tor/Mullvad-vs-Firefox configurability semantics directly into the API. |
| 2026-05-19 | v1.18 — Module 33 Timezone Strict-UTC lock | **Module 33 (Timezone normalization) shipped:** cohort-by-choice with Standard pass-through (same shape as Modules 25 / 27 / 28 / 29; second instance of the Strict-only-normalization posture in Phase 5). `TimezonePolicy { NativePassThrough, NormalizedUtc(&'static TimezoneProfile) }` with `for_mode`. `LOCKED_TIMEZONE_PROFILE` pins `iana_name = "UTC"`, `offset_minutes = 0`, `dst_observed = false`, `abbreviation = "UTC"` — every Strict DevBrowse renderer reports identical timezone metadata regardless of host TZ, matching Tor Browser's `privacy.resistFingerprinting` floor. Standard renderers leave the native Gecko timezone resolver in place per §3.2's "permission-center, not blanket-normalization" tradeoff. Future per-identity custom timezone (phase-file Goal "Configurable per-identity") is a Standard-only feature stored in `IdentityProfile` (pb-identity); when it ships, `for_profile(&IdentityProfile)` will wrap `for_mode` and Strict will remain locked to `LOCKED_TIMEZONE_PROFILE` regardless (L41 forbids loosening). `TimezoneSurface::ALL` covers 5 variants: `IntlDateTimeFormatResolvedTimeZone` (the most direct leak), `DateGetTimezoneOffset`, `DateToString` (default string embeds offset + abbreviation), `DateToLocaleString` (locale-aware formatting embeds the TZ), `IntlLocaleDefaults` (`LC_TIME` / Windows region settings carry timezone hints into the resolved locale). The `Intl.Locale` defaults variant is the phase-file edge case lifted to a typed pathway. §5.5 matrix row 33 already carried the "Host timezone / UTC" values from v1.0; v1.18 names the concrete `LOCKED_TIMEZONE_PROFILE` static + the surface set. No L-invariants added or changed; this is the per-Module Mode-applicability lock the v1.12 matrix demanded for Module 33 (the lock was already explicit in v1.0, so no Mode-applicability TBD existed for this row). |
| 2026-05-19 | v1.17 — Module 32 Timer quantization per-Mode lock | **Module 32 (Timer quantization) shipped:** both modes quantize through a single `TimerQuantizationPolicy::Quantized(&'static TimerProfile)` variant, with the per-Mode profile carrying the divergence — Standard `STANDARD_TIMER_PROFILE.js_quantum_ns = 1_000_000` (1 ms; the §5.5 floor since v1.0); Strict `STRICT_TIMER_PROFILE.js_quantum_ns = 100_000_000` (100 ms; L43 / Tor Browser RFP parity). GPU quantum stays mode-invariant at 2 ms (`GPU_QUANTUM_NS`; pb-gpu authoritative per L8; the field on `TimerProfile.gpu_quantum_ns` is documentation only). **Floor rounding** (`(now / Q) * Q`) is the chosen mechanism: it preserves both same-microtask correlation (two reads within a Q-ns window return the same value, eliminating the canonical timing-side-channel) AND the spec's monotonic-non-decreasing contract on `performance.now()`. Round-to-nearest leaks the sub-quantum delta on the boundary; round-up violates monotonicity. `TimerSurface::ALL` covers 7 variants (`DateNow`, `PerformanceNow`, `PerformanceTimeOrigin`, `PerformanceTiming`, `PerformanceObserverEntry` — consolidates Resource / Navigation / Paint / User / LongTask / Event Timing under one libxul dispatch path, `RequestAnimationFrameTimestamp`, `EventTimeStamp`). The worker-context performance object is closed by Module 26's context-inert obligation, not a separate variant. Cross-module coupling note: Module 29 (Audio) `performance.now()` reads during `OfflineAudioContext` rendering route through Module 32 (audio.rs pins only buffer values); Module 30 (Fonts) `FontFaceSet.ready` callback latency depends on Module 32's quantization (Strict 100 ms floor absorbs sub-100ms enumeration deltas; Standard 1 ms is insufficient for the enumeration-count delta and would require a per-callback quantizer from a future module). §5.5 matrix row 32 already carried the 1 ms / 100 ms values from v1.11; v1.17 names the concrete statics + `quantize_js_ns` helper. No L-invariants added or changed; this is the per-Module Mode-applicability lock the v1.12 matrix demanded for Module 32 (the lock was already explicit in v1.11 via L43, so no Mode-applicability TBD existed for this row). |
| 2026-05-19 | v1.16 — Module 31 Battery API mode-invariant removal | **Module 31 (Battery Status API) shipped:** first Phase-5 module where the per-Mode decision is **mode-invariant removal** (third Phase-5 posture, joining Strict-only / both-modes-normalize). `BatteryApiPolicy::Removed` is the single variant; `for_mode` returns it for both `Mode::Standard` and `Mode::Strict`. Strict per L44 mandate (Battery is in the L44 disabled-by-default set); Standard per industry consensus (Firefox 52+ removed `navigator.getBattery`; the W3C spec itself flags the API as a cross-site identification surface per Olejnik / Englehardt 2016 research). No `BatteryGrants` permission hook — unlike Module 30 fonts (per-site `FontsGrants` opt-in for Standard), Battery has no re-enable path under any settings. `BatterySurface::ALL` covers 6 variants (entry point `NavigatorGetBattery` + 4 BatteryManager properties `Level` / `Charging` / `ChargingTime` / `DischargingTime` + the consolidated event-handler table) — the BatteryManager properties are listed even though they are unreachable once `getBattery` is removed, as defense-in-depth against a libxul build that re-enables the entry point but forgets to patch the manager. Libxul-side removal lands via `dom.battery.enabled = false` + `Navigator.webidl` patch so `'getBattery' in navigator === false` (not just a rejected Promise). §5.5 matrix row 31 was already populated v1.11 ("Permission-gated via Module 59" Standard / "Returns 'not supported' (L44)" Strict); v1.16 supersedes that with the mode-invariant removal — both columns now read "Removed; no permission-gate path." No L-invariants added or changed; this is the per-Module Mode-applicability lock the v1.12 matrix demanded for Module 31. |
| 2026-05-19 | v1.15 — Module 30 Fonts both-modes-normalize lock + Module 27 cross-coupling | **Module 30 (Fonts enumeration normalization) shipped:** first Phase-5 module where **both modes normalize**, breaking the cohort-by-choice pattern of Modules 25 / 27 / 28 / 29 because the unfiltered system font list is too high-entropy even for the Standard cohort. **Strict** pins `BUNDLED_FONT_SET_V1` (15 family names: Tor-style metric-compatible Latin substitutes `Arimo` / `Tinos` / `Cousine` + Noto coverage of CJK SC/JP/KR / Arabic Naskh / **Urdu Nastaliq** (`Noto Nastaliq Urdu`, distinct from the Arabic Naskh face — Nastaliq is the elegant Urdu calligraphic style) / Devanagari (also serves **Hindi**) / Thai / Bengali / Tamil + `STIX Two Math` + `Noto Emoji`); no host-OS enumeration; no per-site opt-in (L41 forbids loosening). **Roman Urdu** (Urdu transliterated to Latin) uses the existing Latin faces and needs no additional font. **Standard** ships `STANDARD_BUCKETED_TABLE_V1` (9 script-coverage buckets via `FontBucket::ALL`); per-site full enumeration opt-in routes through the `FontsGrants` trait (Module 59 wiring point; `DenyAllFontsGrants` is the v1 default). `FontsSurface::ALL` covers 5 readback pathways including the phase-file edge case (`FontLoadCallback` — callback latency leaks installed-font count; needs latency quantization cross-coupled to Module 32 / L43). **Module 27 cross-coupling:** `CanvasRenderProfile::font_set` migrated from `&'static str` (v1 label-only) to `&'static BundledFontSet` pointing at `BUNDLED_FONT_SET_V1`; Strict canvas-rasterizer cohort and Strict font-enumeration cohort are now unified by address identity. §5.5 matrix row 30 updated to name the concrete statics + the `FontsGrants` hook. No L-invariants added or changed; this is the per-Module Mode-applicability lock the v1.12 matrix demanded for Module 30 plus the planned Module 27 font_set type swap. |
| 2026-05-19 | v1.14 — Module 29 Web Audio Strict-only lock | **Module 29 (Audio context / Web Audio normalization) locked Strict-only:** Strict-mode renderers route every audio readback pathway through `LOCKED_AUDIO_PROFILE`: `OfflineAudioContext.startRendering`, `AudioBuffer.getChannelData`, all four `AnalyserNode` getter pairs (`getByte/Float Frequency/TimeDomainData`), and the `AudioContext` metadata trio (`baseLatency`, `outputLatency`, `sampleRate`) — covered by the `AudioSurface::ALL` 9-variant typed list. The locked profile pins `sample_rate_hz = 44100` (Tor Browser parity for maximum cohort overlap with Tor / Mullvad / Firefox-RFP users), `channel_count = 2`, `base_latency_seconds = 0.005`, `output_latency_seconds = 0.020`, `f32_quantization_step = 1.0e-7` (Tor / Brave parity post-render rounding), `CompressorImpl::CohortLocked` (deterministic scalar reference `DynamicsCompressorNode` implementation; W3C-default parameters are cohort-uniform but the FP path is what fingerprints, so the *implementation* is locked rather than the parameters), and `DspPath::ScalarReference` (no SIMD auto-vectorization; SSE / AVX / NEON deltas in mixing + FFT magnitudes split the cohort by micro-arch). Two-layer cohort determinism: even if a future SIMD path produced sub-grid deltas, the 1e-7 post-render quantization would collapse them. Standard-mode renderers preserve the native Gecko audio path — cohort-by-choice, same shape as Modules 25 / 27 / 28 / 30 / 32 / 33. Cross-module cohort coupling note: timer quantization (L43, 100 ms Strict floor) lives in Module 32, not here; Module 29 pins only the audio buffer values. §5.5 matrix row 29 updated from "Mode TBD / Mode TBD" to the explicit per-Mode behavior. No L-invariants added or changed; this is the per-Module Mode-applicability lock the v1.12 matrix demanded for Module 29. |
| 2026-05-19 | v1.13 — Module 28 WebGL Strict-only lock | **Module 28 (WebGL parameter normalization) locked Strict-only:** Strict-mode renderers route every WebGL parameter readout (`VENDOR`, `RENDERER`, `VERSION`, `SHADING_LANGUAGE_VERSION`, `getSupportedExtensions`, the eight `MAX_*` numeric parameters) through `LOCKED_WEBGL_PROFILE` (vendor / renderer pinned to `"Mozilla"` for maximum cohort overlap with Firefox / Tor Browser; cohort-safe numeric ceilings; curated allowlist of 5 WebGL 1 extensions). `WEBGL_debug_renderer_info`, `EXT_disjoint_timer_query`, and `EXT_disjoint_timer_query_webgl2` are absent from the allowlist (the first leaks unmasked GPU + driver identity; the latter two bypass L43's 100 ms timer floor with a high-resolution GPU clock). `WebGLRenderingContext.readPixels` reuses `LOCKED_CANVAS_PROFILE` (Module 27) so the Strict cohort is not split by readback-API choice — cross-module cohort unification asserted by address-identity test. Standard-mode renderers preserve the native Gecko WebGL surface; Firefox's default `webgl.enable-debug-renderer-info = false` floor is inherited without DevBrowse adding a separate carve-out. Same cohort-by-choice shape as Modules 25 / 27 / 30 / 32 / 33. §5.5 matrix row 28 updated from "Mode TBD / Mode TBD" to the explicit per-Mode behavior. No L-invariants added or changed; this is the per-Module Mode-applicability lock the v1.12 matrix demanded for Module 28. |
| 2026-05-18 | v1.12 — Module 27 canvas Strict-only lock + Phase-5 Mode-applicability matrix | **Module 27 (Canvas readback normalization) locked Strict-only:** Strict-mode renderers route every canvas readback pathway (`getImageData`, `toDataURL`, `toBlob`, `OffscreenCanvas` variants, `createImageBitmap`, `WebGLRenderingContext.readPixels`) through `LOCKED_CANVAS_PROFILE` (grayscale AA, no hinting, CPU rasterizer, sRGB, snap-to-int, `devbrowse-bundled-v1` font set). Standard-mode renderers preserve the native Gecko rasterizer — cohort-by-choice, same shape as Module 25 WebRTC Disabled-vs-PerSitePermission, Module 30 Tor-allowlist-vs-bucketed, Module 32 100ms-vs-1ms, Module 33 UTC-vs-host. Rationale: §3.3 "max fingerprint normalization" is a Strict-only feature; forcing Standard through a normalized rasterizer would over-reach §3.2's tradeoff and shift the Standard cohort against its consumers' expectations. §5.5 gains the **Per-Phase-5 surface Mode-applicability matrix** so future modules cannot ship without a per-Mode lock; Modules 28 / 29 / 34 marked "Mode TBD" in the matrix until their phase-file entries lock them. `phase-5-fingerprint.md` gains a "Mode-applicability discipline" header rule mandating the per-Mode lock be documented before code lands. `CLAUDE.md` gains a one-line reminder for Phase-5 implementers. No L-invariants added or changed; this is a clarification of §3.3 / §5.5 / L9. |
| 2026-05-07 | v1.11 — Renderer-network isolation lock + Mullvad-class Strict hardening | **L40 added (renderer-network isolation):** Gecko renderer's only egress is the pb-ipc bridge to pb-network; libxul is built with Necko / NSPR / NSS direct-egress disabled (or replaced via `nsIIOService` protocol-handler injection); kernel sandbox denies `socket()` / `connect()` / `bind()` as defense-in-depth; Module 69 wrapper-checker verifies on every libxul tag bump. Closes the previously implicit gap that "the renderer is forced to use pb-network" — without this lock the L33 partition-key gate is a polite suggestion if a libxul build re-enables Necko. **L41 added (Strict-mode settings lock):** Strict is non-loosenable by user settings; any wizard opt-in or settings toggle that would weaken L9 / L16 / L25 / L29 / L30 / L31 / L34 / L35 / L42 / L43 / L44 is ignored for `mode == Strict`. Settings can still further-tighten Strict, never loosen. Phase 10 Module 71 asserts. **L42 added (letterboxing):** Strict tabs report `window.innerWidth/innerHeight/outerWidth/outerHeight/screen.width/height/availWidth/availHeight` quantized to a 200×100 grid (matches Tor Browser / Mullvad). Standard uses §5.5 coarse buckets. **L43 added (timer quantization):** `performance.now()`, `Date.now()`, `Performance.timeOrigin` quantized to **100 ms** in Strict (matches Tor Browser RFP), 1 ms in Standard, GPU timestamps stay 2 ms (L8). **L44 added (disabled-by-default API surface):** in Strict, Geolocation, MediaDevices.enumerateDevices, getUserMedia, Bluetooth, USB, HID, Serial, NFC, all 9 sensor APIs, Gamepad, sendBeacon, Battery, Notification, WakeLock, IdleDetector, PresentationRequest, PaymentRequest return "not supported" without consulting Module 59; Standard routes these through the permission center. WebRTC stays separately locked (L35). **§5.5 updated** to inline references to L41-L44 and point at Phase 5.5. **plan.md companion changes:** new **Phase 5.5 — Strict-mode hardening** (Modules 35.1 letterboxer / 35.2 timer quantizer / 35.3 disabled-API surface / 35.4 settings-lock enforcement) lands between Phase 5 (WebIDL surface) and Phase 6 (GPU). Phase 5.5 is required because the new modules layer on Phase 5's WebIDL bridge but introduce locks not previously planned. Module 69 (wrapper-compatibility checker) extended to verify L40 on every libxul tag bump. Module 32 (timers) spec extended with the 100 ms Strict floor (L43). Module 30 (fonts) spec pinned to a Tor Browser-style allowlist in Strict (~15 fonts) plus bucketed enumeration in Standard. **threat-model.md updated:** A1 defenses now list Phase 5.5 alongside Phase 4 / Phase 5 / Phase 10. **Architecture phase count:** 13 → 14 (adds 5.5, mirrors the existing 1.5 / 7.5 sub-phase precedent). Module count: 96 → 100 (adds 35.1, 35.2, 35.3, 35.4). |
| 2026-04-30 | v1.10 — Extension allowlist locked + plan.md adaptation/perf/UI-design upgrades | **Extensions: curated allowlist only.** §3.2 rewritten: free side-load from AMO is forbidden, no AMO link in chrome, no bundled store, no manual `.xpi`. Allowlist ships through Module 65 update channel (same signed-manifest pipeline as Module 67 blocklist track). Allowlisted extensions do **not** receive `webRequest`-style outbound-traffic inspection; pb-network has no extension hook surface (honors L30/L33). All three "extension" rows in §7 Open Decisions closed: distribution-surface (allowlist), webRequest-hook (no), plugin-model (allowlist only). Extension SDK remains a Future Improvements §11 entry. **plan.md v1.10 companion changes:** Adaptation protocol + cohort-watch list (rustls/quinn/webpki-roots/argon2/chacha20poly1305/prost/Gecko); Module 0.5 test-harness foundation as new Phase 1.5 (replaces Module 19 as `(next)`); Module 23 split 23.1-23.4 (chain, CT, ECH, HSTS); Module 24 split 24.1-24.2 (ClientHello pin + cohort-drift CI); Module 83 split 83.1-83.5 (KDF/AEAD, ladder, format, lock, OS hooks); Module 87 split 87.1-87.3 (PAKE, UI, keystore); Phase 7.5 + Module 41.5 UI design lock as ship-blocker before any Phase 8 implementation; Module 80.6 local self-check page (no-telemetry privacy diagnostic); Performance contract cross-cutting concern with per-module budgets and Strict-mode invariant. New `docs/threat-model.md` codifies attacker profiles A1-A6 (in scope), N1-N7 (out of scope), and the seven defense-in-depth layers. |
| 2026-04-30 | v1.9 — Windows isolated to its own phase + cloud purge + mDNS pair-once locked | **Windows pulled out of cross-platform foundation:** all pre-existing Windows code paths (pb-ipc named-pipe backend, pb-config/pb-storage ACL no-ops, `%APPDATA%` data-dir arm) replaced with `#[cfg(windows)] compile_error!` markers pointing at the new **Phase 11.9 — Windows hardening** (Modules 93-96: Windows IPC two-pipe duplex, file ACLs / DPAPI, AppContainer + Job Object sandbox, MSI/MSIX signed update). CI Linux/macOS only until Phase 11.9 ships. **Cloud sync purged from architecture entirely:** no Google Drive / iCloud / Dropbox / OneDrive references survive in L21 or anywhere; `SyncBackend` enum reduced to `{ Disabled, LanCluster, HubPeer, WebDav }`; cloud SaaS is now an architectural anti-goal, not a deferred option. **L21 mDNS pair-once persistent identity locked:** TXT record carries `(rotating_nonce, HMAC(cluster_key, nonce \|\| device_id_short))` so paired peers identify each other across networks/restarts without re-pairing while LAN outsiders see only random bytes. **Convergence guarantee** (signed append-only sync log + per-peer high-water marks, Module 84) explicitly written into L21. **Vault auto-lock** on suspend/lid-close/inactivity added to L21. **Forensic-redaction Mi2:** `pb-storage::StoreError::Sqlite` and `StorageError::Sqlite` Display made opaque (rusqlite text reachable only via `Error::source()` for internal tracing) per L27. **Cross-platform notification icon** (`pb-platform::IconRef`) replaces `Option<PathBuf>` to support iOS bundle ids / Android drawables. **Schema migration scaffold** stubbed in pb-storage (`migrate(conn, from, to)` with explicit `unimplemented!()` arms invoked from `bootstrap` on version mismatch). Module count 92 → 96. Architecture phase count 12 → 13 (added 11.9). |
| 2026-04-30 | v1.7 — Sync model redesigned (LAN-cluster, no SaaS clouds) | Phase 11.5 expanded from 5 modules (83-87) to 10 modules (83-92). Dropped Google Drive / iCloud / Dropbox / OneDrive backends entirely. New transport stack: SPAKE2 6-digit pairing + 4-emoji fingerprint compare + Ed25519 identity keys (in OS keystore) + mDNS discovery + QUIC mTLS + per-recipient X25519 envelopes for direct messages. Hub-peer forwarding mode replaces SaaS sync as the primary cross-device path. Self-hosted WebDAV becomes opt-in last-resort relay. Sync is foreground-only; mobile background sync explicitly out of scope. Crate split locked to single `pb-sync`. L21 rewritten. §7 "Sync crate split" decision row replaced with "Passkey sync deferred" row. Phase 12 mobile sync row updated to reuse the same stack (SAF / UIDocumentPicker only matter for the local-backup file in Module 85). |
| 2026-04-28 | v1.6 — Privacy-standard locks + mode-toggle UX + ship-gate scheduling | **Mode-toggle UX (§3.6)** locked: new tabs open Standard with a one-time prominent "Convert to Privacy tab" affordance; Strict is one-way (kill-tab-to-exit); Standard link-clicks open Standard with an offer-to-Strict popover; Strict tabs run under a separate `identity_profile_id` plus fresh `context_id` so cookies / session / cache from a Standard tab on the same URL never apply. **Partition-key context (§3.5)** clarified: `context_id` is fresh per Strict tab, stable per Standard profile. **Locks L30–L37** added: HTTPS-Only default, Referer policy (`strict-origin-when-cross-origin` / `no-referrer`), URL parameter stripping (UTM/gclid/fbclid + Module 21 list), network-state partitioning (cache / DNS / conn-pool / ALT-SVC / HSTS keyed by partition_key), Encrypted Client Hello (preferred when available, mandatory in Strict where supported), WebRTC constraints (per-site permission, mDNS-only ICE, fully off in Strict), bounce-tracker mitigation (45-day intermediate-only purge), cookie-banner auto-decline (wizard-gated, blocklist-track shipped). **Locks L38–L39** added: reproducible builds (locked toolchain + cargo-vet + sha256 publish + rebuild gate) and dual release signing (offline GPG key + Sigstore Rekor transparency log). **§5.11** added: Standard-mode site-isolation tradeoff documented — co-residence acknowledged, COOP/COEP isolation honored, Spectre mitigations on, opt-in per-site Standard renderers reserved for Phase 8. **§6 Phase 11** scheduled **Module 80.5** as the real OS sandbox enforcement work in `pb-sandbox/src/enforce.rs` and called it a v1.0 ship-blocker (Module 12 v1 is types-only). |

---

## 11. Future improvements

Items locked **out of v1.x scope** but explicitly tracked. The architecture
must remain compatible with these — i.e. don't paint into a corner.

| Item | Notes |
|---|---|
| **Custom protocol stack** built on audited primitives | Our own vault format spec, device-pairing handshake, recovery scheme. Primitives stay standardized (L22). |
| **Post-quantum primitive migration** (ML-KEM-768 / ML-DSA-65) | Track NIST PQC standardization. Vault format is versioned (Module 83) so migration is a format bump, not a rewrite. |
| **Hardware-backed key storage** | Secure Enclave (macOS/iOS), TPM (Linux/Windows), Android Keystore, YubiKey. Vault master-key derivation grows a hardware-attested branch. |
| **Push-based sync over WAN** | A user-runnable WireGuard-style relay (still E2E encrypted) for cross-network sync without WebDAV. v1 ships LAN + hub-peer + optional WebDAV; this would be a smoother T3 alternative if/when there's appetite to ship it. |
| **Visual theme / CSS authoring tool** | Built atop Site Customizer (Module 61). Lets users author and share visual customizations. |
| **Plugin / extension SDK** | Beyond Phase 7 blocking, a privacy-respecting extension model with capability-scoped APIs. |
| **Identity-scoped device sync** | Each `IdentityProfile` syncs to its own vault — work and personal data never share a backup file. |

---

## Appendix A — Stub module headers vs this doc

The pre-existing module numbers in source-file comments (e.g. `// Module 6.`)
correspond to the **pre-revision** plan (71 modules). After v1.0 (83 modules)
and v1.1 (87 through Phase 11.5; Phase 12 reserved), some numbers shift. As
we touch each module to write real code, its file header is updated to match
this doc. Until then, expect mild drift between stubs and §6.

If you encounter a discrepancy, **§6 of this doc is authoritative**.
