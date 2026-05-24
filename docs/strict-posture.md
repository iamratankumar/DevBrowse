# DevBrowse Strict-mode posture

This document enumerates the fingerprint surfaces DevBrowse Strict mode locks, with one paragraph per surface explaining the lock and how DevBrowse compares to Tor Browser RFP, Mullvad Browser, and Brave's (sunset) Strict mode. It is the user-facing equivalent of mullvad.net/en/browser's posture page.

**Last revised:** 2026-05-22 (post-Phase-5.5 + post-audit additions Modules 35.11 – 35.13).

## Identity posture

DevBrowse Strict targets **Tor / Mullvad+ parity** with three structural advantages: WebGPU stays usable, speech-synthesis voices preserve accessibility, and Standard desktop joins the Strict cohort on touch / display metadata (v1.23 amiunique-generic).

## Surface-by-surface lock

### Navigator + UA (Module 34)

- **User-Agent**: `Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0`. Firefox 128 cohort on the Linux desktop token (Tor uses Win64; DevBrowse uses Linux because v1 ships Linux + macOS desktop). Same UA across both modes — joins the Firefox ESR cohort regardless of host OS.
- **`navigator.vendor`**: `""` (Firefox convention). Empty string IS the Mozilla / Firefox family identifier.
- **`navigator.platform`**: `"Linux x86_64"` regardless of host (matches the UA token).
- **`navigator.userAgentData`**: **not exposed**. Firefox does not implement the Chromium Client Hints API; DevBrowse blends in by matching the absence — never spoofs a Chrome-style brand list.
- **`navigator.hardwareConcurrency`**: 2 in Strict (Tor RFP parity), 4 in Standard.
- **`navigator.deviceMemory`**: locked to 8 (Web-spec bucket; most-common value).
- **`navigator.webdriver`**: `false`. DevBrowse is not a WebDriver-driven browser.
- **`navigator.doNotTrack` + `navigator.globalPrivacyControl`**: `"1"` and `true` (mode-invariant — both modes consent-signal).

### Canvas + WebGL + Audio (Modules 27, 28, 29 + 35.5 farbling)

Strict: cohort-locked `LOCKED_CANVAS_PROFILE` (CPU rasterizer, grayscale AA, no hinting, bundled font set), `LOCKED_WEBGL_PROFILE` (`vendor = "Mozilla"`, 5-extension allowlist), `LOCKED_AUDIO_PROFILE` (cohort compressor + scalar reference DSP). No farbling — pure cohort identity. Standard: same cohort base + per-(origin, IdentityProfile) deterministic `±1 LSB` farble on dynamic readbacks (canvas / WebGL numeric / audio).

### WebGPU (Module 35.6) **— DevBrowse advantage**

Strict locks `navigator.gpu.requestAdapter()` adapter info (`vendor = "Mozilla"`, spec-minimum limits, empty architecture / driver strings) while keeping WebGPU functional. **Tor and Mullvad disable WebGPU entirely**; DevBrowse keeps the API usable for shader / compute applications under the cohort lock. Cross-coupled with WebGL vendor via address-identity test.

### Speech Synthesis voices (Module 35.7) **— DevBrowse advantage**

Strict ships a 4-voice cohort (`en-US`, `en-GB`, `ja-JP`, `ar-SA` — Latin + CJK + Arabic script directions) so screen readers continue to function. **Tor and Mullvad return the empty voice list**, breaking accessibility tools. DevBrowse's accessibility-preserving cohort is structurally ahead.

### Media Capabilities (Module 35.7)

Mode-invariant codec table: H.264 baseline / VP9 / AAC / Opus / MP3 supported; HEVC and AV1 unsupported regardless of host hardware. Sites that need HEVC / AV1 fall back to VP9. EME / DRM playback unaffected.

### Network Information API (Module 35.8) **— DevBrowse advantage**

Strict removes `navigator.connection` entirely (`'connection' in navigator === false`). **Tor still exposes the API surface** with a `"4g"` stub — the existence of the property is itself a 1-bit signal. DevBrowse removes the surface to match Brave's posture but with the Firefox-equivalent property-deletion mechanism.

### Permissions enumeration (Module 35.9) **— DevBrowse advantage**

Strict resolves every recognized W3C permission name to `"denied"` and every unrecognized name to `"prompt"` — **polluted-oracle protection**. A site cannot enumerate the L44 disabled-API list by probing because `"prompt"` (no decision) is structurally indistinguishable between "not gated" and "gated but oracle-polluted". No competitor implements this.

### Storage estimate (Module 35.9)

Strict returns `{quota: 0, usage: 0}` (Tor parity). Per-origin actual usage is hidden behind the partition-key boundary so sites cannot probe their own storage state.

### Letterboxing + Display + Touch (Modules 35.1, 35.10)

- **Window dimensions** (Module 35.1): quantized to a 200×100 grid (matches Tor 9.0+).
- **`devicePixelRatio`** (Module 35.10): Strict locks to 1.0; Standard buckets into `{1.0, 1.5, 2.0, 3.0}` so Retina UX is preserved while every Standard user reports one of four cohorts. **Tor forces a hard 1.0**, breaking non-fractional Retina scaling — DevBrowse Standard is structurally ahead on UX.
- **`screen.colorDepth` / `pixelDepth`**: locked to 24 in both modes (universal on modern displays).
- **`screen.orientation`**: locked to `landscape-primary` / 0° on desktop v1. Phase 12 mobile carve-out for actual rotation.
- **Touch** (Module 35.10): both desktop modes lock `maxTouchPoints = 0` + `pointer = fine` + `hover = hover` (v1.23 amiunique-generic — Standard desktop joins Strict desktop). `ontouchstart` is deleted from `window` and `Element.prototype`. Mobile carve-out (Phase 12) preserves real touch values for responsive sites.

### DOMRect + TextMetrics (Module 35.11, audit addition)

Strict snaps every `Element.getClientRects()` / `getBoundingClientRect()` / `Range.getClientRects()` / `CanvasRenderingContext2D.measureText()` / `SVGGraphicsElement.getBBox()` coordinate to **integer pixels** — closes the per-font-rendering + per-DPI sub-pixel signal (Tor bug 1507879). Standard adds `±1 px` farble on top of integer snap via the disjoint `FarblingSurface::DomRect` / `::TextMetrics` streams.

### Intl.* defaults (Module 35.12, audit addition)

Both modes lock `Intl.NumberFormat` / `Intl.Collator` / `Intl.RelativeTimeFormat` / `Intl.PluralRules` resolved options to the **en-US cohort** (`numbering_system = "latn"`, `collator_sensitivity = "variant"`, `default_currency = "USD"`, `plural_rules_default_type = "cardinal"`). Module 33 owns the `DateTimeFormat` `timeZone` field separately (UTC in Strict).

### Keyboard Layout Map (Module 35.13, audit addition)

Both modes return the **US-QWERTY layout** from `navigator.keyboard.getLayoutMap()` (matches `LOCKED_LANGUAGE = "en-US"`). 48 entries covering alphabet + digits + common punctuation. `navigator.keyboard.lock()` returns a rejected Promise.

### Timer quantization (Modules 32, 35.2)

Strict: 100 ms `performance.now()` / `Date.now()` / `Performance.timeOrigin` quantum (Tor Browser RFP parity). GPU: 2 ms (separate Phase 6 path). Standard: 1 ms quantum. **Floor-rounded + per-bucket deterministic jitter** (`quantize_js_ns_with_jitter`, P1-3 audit addition) so statistical de-jittering attacks averaging many reads yield no information beyond the quantized value.

### Disabled APIs (Module 35.3)

Strict denies 16 L44-listed API families: Geolocation, MediaDevices, Web Bluetooth, WebUSB, WebHID, Web Serial, Web NFC, all 9 sensor APIs, Gamepad, Beacon, Notification, WakeLock, IdleDetector, PresentationRequest, PaymentRequest, `SharedArrayBuffer + Atomics.wait`. Battery, NetworkInformation, and WebRTC are delegated to their owning modules (no duplication; typed `DelegatedSurface` registry pins the boundary).

### Settings lock (L41)

Module 35.4 ships the audit framework: every Strict-locked surface has a structural `for_mode(Mode::Strict)` resolver with no `with_user_override`-style escape hatch. Conformance tests assert idempotence. `TimezoneOverride::for_standard_selection` (renamed 2026-05-22) makes the Standard-only configurability explicit.

## What DevBrowse does NOT do (anti-spoof)

- **No `navigator.userAgentData`** — Firefox doesn't have it; we don't pretend to be Chrome.
- **No Chrome-style brand list** spoofing — would create JS-vs-UA inconsistency.
- **No fake `Google Inc.` vendor** — empty string is the Firefox cohort identifier.
- **No `Sec-CH-UA-*` HTTP headers** — Module 22 strips them on the wire.

## How DevBrowse compares

| Surface | DevBrowse Strict | Tor RFP | Mullvad | Brave (sunset) | Firefox RFP |
|---|---|---|---|---|---|
| Canvas | Cohort + integer snap | Permission prompt | Tor parity | Farbled | Prompt |
| WebGL | Vendor = "Mozilla" | `webgl.disabled` | Tor parity | Farbled MAX_* | Vendor hidden |
| **WebGPU** | **Usable, vendor cohort** | Disabled | Disabled | Disabled | Disabled |
| Audio | Cohort DSP | RFP timer | Tor parity | Farbled | Prompt |
| Fonts | 15-font bundle | Bundled | Tor parity | Bucketed | Standard list |
| **Speech voices** | **4-voice a11y cohort** | Empty list | Empty list | Farbled name | n/a |
| Timers | 100 ms + jitter | 100 ms + jitter | Tor parity | Variable | 100 ms |
| **Permissions** | **Polluted oracle** | Consistent answers | Tor parity | Per-API | Native |
| Storage | `{0, 0}` | Some leak | Tor parity | Partitioned | Per-partition |
| Network Info | Removed | Stub `"4g"` | Removed | Removed | Disabled |
| **DPR bucket** | Locked 1.0 | Hard 1.0 | Tor parity | Native | 1.0 |
| Letterbox | 200×100 | 200×100 | Tor parity | None | Enabled |
| Touch | `0` + fine | `0` desktop | Tor parity | Native | `0` |
| **DOMRect** | **Integer snap** | Integer snap (bug 1507879) | Tor parity | Integer | Snap |

Bold rows are surfaces where DevBrowse goes structurally beyond the comparison set.

## Threat-model coverage

Strict targets attacker class **A1** (passive tracking / fingerprinting) and partial **A2** (compromised renderer — settings-lock is non-loosenable structurally). See `docs/threat-model.md` for full attacker enumeration.
