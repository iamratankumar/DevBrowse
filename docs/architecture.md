# DevBrowse — Architecture

**Version:** 1.3  
**Status:** Locked — change requires explicit re-locking with rationale  
**Last revised:** 2026-04-28

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

DevBrowse is a privacy-focused web browser written in Rust. The desktop builds
(Linux / macOS / Windows) embed the Gecko engine via libxul FFI; mobile builds
(iOS, Android — Phase 12) use platform-conditional engines (WebKit on iOS per
App Store policy 2.5.6, GeckoView on Android). It is built to **change the
defaults** of the browser category: privacy is not a setting, it is the
architecture. UX is modern and trust-building, not a Chromium reskin.

### 1.2 Non-goals (v1)

- Self-hosted sync infrastructure — sync is **bring-your-own-cloud**, see L21.
- Homemade cryptographic primitives — we compose audited primitives, never
  invent ciphers/hashes/PRFs (L22).
- OS-platform passkey sync — Apple/Google own the keychain on iOS/Android;
  only software-authenticator passkeys we generate are sync-eligible.
- Built-in password manager — deferred decision (§7).
- Built-in autofill — deferred decision (§7).
- Replacing the JS console — Gecko DevTools stays as-is in standard mode.

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
| L3 | UI: **Iced** (wgpu backend), Linux MVP | Native rendering, no Electron, no Chromium UI deps. |
| L4 | IPC: **Tokio + Unix sockets + Protobuf (prost)** | Async, well-typed, hermetic codegen. |
| L5 | Storage: **SQLite via rusqlite (bundled)**, WAL mode | One file format, audited C, no system-libsqlite version drift. |
| L6 | Networking: **hyper 1.x + rustls** (no OpenSSL) | Pure-Rust TLS, smaller attack surface, no OS trust-store dependency. |
| L7 | Identifier crypto: **uuid v4** (CSPRNG) for IDs, **sha2** for partition keys | Standard primitives only. |
| L8 | Fingerprint normalization: **Gecko WebIDL override points**, NOT JS prototype patching | Workers and iframes inherit automatically; zero internal Gecko patches. |
| L9 | Process model: **identity-grouped** with **Standard** and **Strict** modes | See §3. |
| L10 | Filesystem access: **capability-based** via opaque `FileHandle`, OS-picker-gated | Path strings never cross the trait surface. See §5.3. |
| L11 | Clipboard / sensitive input: **gesture-token-gated** at the type system level | Move-only `GestureToken`, single-use. See §5.4. |
| L12 | Crate dependency rule: any crate may import **`pb-ipc` and `pb-config`**; no other cross-crate imports | Enforced at Cargo.toml level. See §4. |
| L13 | Unsafe code policy: **`#![forbid(unsafe_code)]`** on every crate; downgrade to `deny` only on FFI modules with `#[allow(unsafe_code)]` annotation | See §5.6. |
| L14 | Release profile: `panic=abort`, `overflow-checks=true`, `lto=fat`, `codegen-units=1`, `strip=symbols` | Browser parses hostile input — overflow must panic, not wrap. `panic=abort` prevents unwinding through libxul FFI. |
| L15 | Supply chain: **`cargo-deny` gate in CI** (advisories, licenses, bans, sources) | Every transitive dependency reviewed. |
| L16 | DevTools: **Gecko built-in only** (zero custom impl in v1); **blocked entirely in strict mode** | Customization deferred. |
| L17 | PDF: **inline pdf.js sandboxed renderer** + download option | No external PDF helper; consistent privacy boundary. |
| L18 | Default search engine: **DuckDuckGo**, with user choice from a curated privacy-respecting set (DDG, Startpage, Brave Search, Mojeek) | Suggestions ON by default, but only via the user's chosen engine. |
| L19 | File picker UX: **modern drag-and-drop entry surface** that calls the OS picker for capability minting | "Reading B" — drop zone + recent-picks chips + Browse button. Never traverses filesystem ourselves. See §5.3. |
| L20 | Translation / spellcheck: **OFF by default**; when enabled, **local-only** (no remote service calls) | Both are content-leaking by default in mainstream browsers. |
| L21 | Sync model: **bring-your-own-cloud, end-to-end encrypted client-side**. WebDAV baseline + Google Drive / iCloud / Dropbox / OneDrive. DevBrowse never operates sync infrastructure. | Zero server cost (no funding model needed); user owns the data; we hold nothing to subpoena. |
| L22 | Cryptographic primitives: **audited and standardized only** (Argon2id, XChaCha20-Poly1305, HKDF, Ed25519/X25519). Protocol composition is ours; primitive set is upgradable (PQC migration tracked). No homemade ciphers/hashes/PRFs. | Schneier's law: anyone can design a cipher they themselves can't break. We compose vetted primitives; we don't invent them. |
| L23 | First-launch setup wizard: **per-feature opt-in** (sync, telemetry, search engine, privacy mode, fingerprint level, translation/spellcheck, etc.). Declined features are **disabled at code-path level**, not just UI-hidden. | "Defaults are architecture" — the wizard makes the defaults a conscious user choice, not a buried setting. |
| L24 | Local encrypted backup/import: **same vault format as sync**, exported to a user-controlled file. Works fully offline. Cross-platform import (desktop ↔ mobile). | Users who decline cloud entirely still get device portability. Vault format reuse keeps the surface area minimal. |
| L25 | DoH provider whitelist: **Quad9 (default)**, NextDNS (wizard-personalized), Cloudflare, or user-supplied custom HTTPS URL (covers self-hosted DNS). **System DNS allowed only in Standard mode** (§3.2); forbidden in Strict (§3.3, DoH-only). NextDNS in the wizard requires a per-account config ID and is persisted as `Custom { url }`; declining the ID falls back to Quad9. | Privacy-respecting curated set, no Google DNS. Quad9 is no-log + malware blocklist out of the box. NextDNS without a config ID adds no privacy value over Quad9, so we refuse to ship that as the silent default. Config rejects malformed URLs at load so a tampered config cannot silently downgrade resolution. |
| L26 | Tracker / ad blocking counters: per-tab badge in the address bar shows total blocked items; full breakdown (ads vs trackers vs fingerprint attempts) in the **Network Viewer** (Module 60). Counters are pure-local, in-process, never persisted, never network-shipped. Module 21 (blocklist) emits classified events; Module 60 surfaces them. Ad/tracker blocking itself remains always-on per the original lock (privacy-browser-context). | Visibility builds trust without leaking data. Counters are ephemeral so even a forensic disk read shows nothing. |
| L27 | Logging policy: **ephemeral session-only debug logs by default** (RAM ring buffer, dropped at exit, never written to disk). User can opt-in to disk logs for bug reporting; opt-in logs auto-redact URLs, form bodies, identity profile names, and partition keys before any write. **No log line ever crosses the network without explicit per-session user consent** (e.g. attaching to a bug report). | Logs are the easiest accidental data leak in any browser. Default-ephemeral + redact-on-write keeps the floor high. |
| L28 | UI design intent: **modern translucent / Apple-glass aesthetic** (vibrancy/blur on platforms that support it: macOS NSVisualEffectView, Windows 11 Mica/Acrylic, Linux compositor-dependent). Default chrome layout = **left-vertical sidebar that opens on hover from a hamburger affordance**, with tab search at sidebar top, tab list in the middle, bookmarks as a right-edge icon column with hover popovers, and a 3-dot overflow menu at the sidebar top for settings / passwords / less-frequent items. Address bar is prominent on focus and fades when idle (always reveals on any keyboard activity, never on mouse-only). Top-horizontal and full-vertical tab layouts are **opt-in alternatives** in settings; sidebar-hover is the v1 default. **Accessibility floor (mandatory):** respect OS "reduce transparency"; WCAG AA contrast on all text-on-glass surfaces (apply a subtle solid backdrop behind text where needed); every chrome surface fully keyboard-navigable. | "Defaults are architecture" extends to UX. The sidebar-hover layout is the most distinctive choice and matches the bookmark-column idea. Locking the accessibility floor up front prevents the glass aesthetic from boxing out users who need contrast or reduced motion. |
| L29 | History retention (Standard mode only): user-selectable in `[history] retention = "forever" \| "session" \| "week" \| "month"`. **Default: `"forever"`** (matches user expectation; wizard surfaces the choice). Strict mode never writes history (already locked at §3.3 / privacy-browser-context). The history process auto-purges entries older than the retention window on a daily sweep. | Users who want a clean trail get it; users who want history get it. Either way, no surprise. The wizard prompt makes the choice conscious, not buried. |

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
- Browser extensions allowed.
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

---

## 4. Crate topology and dependency rule

DevBrowse is a 12-crate workspace today (Phase 1). Phase 11.5 will introduce
sync crates (`pb-vault`, `pb-sync`, `pb-cloud` — exact split locked when the
phase begins). Phase 12 introduces mobile crates (engine adapter for
WebKit/GeckoView, mobile UI shells, mobile build glue).

```
pb-browser              (orchestrator binary)
   ├── pb-ipc           (shared message types — anyone may import)
   └── pb-config        (shared config types — anyone may import)

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

A crate may import **`pb-ipc` and `pb-config` only**. No `pb-X → pb-Y` imports
beyond those two. Violations are caught at Cargo.toml review.

`pb-platform` is a strict leaf — it imports neither `pb-ipc` nor `pb-config`.
This guarantees OS adapter traits are usable in any context, including future
backend test harnesses.

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
  - Strict: tighter buckets, hardware identifiers fully normalized.
- Window position is **never exposed to content JS**, bucketed or otherwise
  (multi-monitor layout is itself a fingerprint).
- `InputEvent` carries no timestamp by design; future timestamps must be
  quantized to ≥1ms granularity in pb-fingerprint.
- GPU timestamps are quantized to **2ms** in pb-gpu.

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
- Sandbox profiles are owned by Module 12 (pb-identity area) and applied
  before any renderer begins parsing untrusted content.
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

---

## 6. Module plan

12 phases (Phase 1 through Phase 12, with Phase 11.5 between Orchestrator
and Mobile). 87 modules through Phase 11.5; Phase 12 module count is reserved
and locked when that phase begins. Sub-files within a module are not
separately numbered. Phase numbering reflects dependency order.

### Phase 1 — Foundation (Modules 1–5)

| # | Module | Status |
|---|---|---|
| 1 | Workspace + Cargo setup | ✅ done |
| 2 | Platform adapter trait surface (5 adapters + capability `FileHandle` + `GestureToken` + `register_dropped_path`) | ✅ done |
| 3 | `pb-config` schema (Config struct, Mode enum, defaults, validation, atomic save, owner-only file mode) | ✅ done |
| 4 | `pb-ipc` transport (Tokio + Unix sockets, framing, max-message-size) | next |
| 5 | `pb-ipc` messages (protobuf types via prost-build) | |

### Phase 2 — Identity (Modules 6–12)

| # | Module |
|---|---|
| 6 | `IdentityProfile` struct + builder + validation |
| 7 | Profile registry + persistence wiring |
| 8 | Renderer scheduler (renderer-sharing rule §3.4) |
| 9 | Lifecycle (spawn → suspend → kill, immutable for tab) |
| 10 | Suspension semantics (tab freeze) |
| 11 | Identity warnings (signals to UI layer) |
| 12 | **OS sandbox profile** (seccomp / AppArmor / mac / Win) |

### Phase 3 — Storage (Modules 13–18)

| # | Module |
|---|---|
| 13 | Storage process bootstrap |
| 14 | Partition key derivation (sha256) |
| 15 | Gatekeeper (every read/write enforces partition key) |
| 16 | Storage primitives (cookies, cache, IndexedDB, localStorage, sessionStorage) |
| 17 | Service worker isolation |
| 18 | Strict-wipe (per-identity wipe on tab close) |

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
| 81 | Graceful shutdown |
| 82 | **Crash containment + report scrubbing** |

### Phase 11.5 — Sync (BYO-Cloud) (Modules 83–87)

End-to-end encrypted, bring-your-own-cloud sync. No DevBrowse server.
Crate organization (single `pb-sync` vs split `pb-vault` / `pb-sync` /
`pb-cloud`) is decided at phase start; locks below describe modules, not
crate boundaries.

| # | Module |
|---|---|
| 83 | **Vault crypto** — Argon2id (passphrase → master key), HKDF key ladder, XChaCha20-Poly1305 AEAD per blob, `zeroize` for in-memory secrets. Vault format spec (versioned). |
| 84 | **Sync log** — append-only operation log per data type, vector clocks, periodic compaction. Per-record conflict surfacing for credentials (no silent overwrite). |
| 85 | **Local backup / import** — export vault to a single user-controlled file; import on another device. Same format as sync (L24). |
| 86 | **`CloudStorageAdapter` trait + WebDAV impl** — universal baseline; covers Nextcloud, Fastmail Files, self-host. |
| 87 | **Cloud backends** — Google Drive, iCloud Drive, Dropbox, OneDrive. On Android route through SAF; on iOS use the app's iCloud container. |

### Phase 12 — Mobile (iOS / Android) (Modules 88+, scope reserved)

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
| Sandbox | Delegates to OS app sandbox (iOS/Android handle this themselves). Module 12 (kernel sandbox) is desktop-only. |
| Sync transport | iCloud container on iOS, SAF-routed Drive on Android — adapters reuse Phase 11.5 vault. |

---

## 7. Deferred / open decisions

| Decision | Status | Notes |
|---|---|---|
| Password manager | Deferred | Decide between: ship one, integrate via Secret Service / KeePassXC, or punt. |
| Form autofill | Deferred | Tied to password manager decision. |
| `hyper-rustls` trust store: webpki-roots vs system | Deferred | Decision lands in Module 23. |
| `tokio` per-crate feature trimming | Deferred | Trim when each crate has real code. |
| Pin GitHub Actions to commit SHAs | Deferred | Acceptable risk to leave on tag refs. |
| Terminal (Idea 1) | Moved to Future Improvements (§11) | Wizard now occupies Module 64. |
| Visual editor (Idea 2) | Reframed | Site Customizer (Module 61) is the privacy-aligned version; full visual editor not pursued. |
| Tab discard under memory pressure | Deferred | UX, not security. |
| Sync crate split (`pb-sync` vs `pb-vault` + `pb-cloud`) | Decided at Phase 11.5 start | Affects dependency rule L12 — may require pb-vault to be added to the "freely importable" allowlist. |
| Plugin / extension model beyond passthrough | Deferred | Phase 7 only enforces blocking; richer extensions deferred indefinitely. |

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

---

## 11. Future improvements

Items locked **out of v1.x scope** but explicitly tracked. The architecture
must remain compatible with these — i.e. don't paint into a corner.

| Item | Notes |
|---|---|
| **Custom protocol stack** built on audited primitives | Our own vault format spec, device-pairing handshake, recovery scheme. Primitives stay standardized (L22). |
| **Post-quantum primitive migration** (ML-KEM-768 / ML-DSA-65) | Track NIST PQC standardization. Vault format is versioned (Module 83) so migration is a format bump, not a rewrite. |
| **Hardware-backed key storage** | Secure Enclave (macOS/iOS), TPM (Linux/Windows), Android Keystore, YubiKey. Vault master-key derivation grows a hardware-attested branch. |
| **Push-based sync** | If/when funding allows: CRDT log + thin WebSocket relay (still E2E encrypted). Polling is the v1 mode. |
| **Linux terminal in place of JS console** | Original "Idea 1" — replace dev console with a real shell where the page is callable from the terminal. Long-term, deferred indefinitely. |
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
