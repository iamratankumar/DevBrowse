# DevBrowse Standard-mode posture

This document describes DevBrowse Standard mode's privacy posture and how it differs from both DevBrowse Strict (above) and competitor Standard modes (Brave, Firefox 119+ ETP, LibreWolf).

**Last revised:** 2026-05-22 (post-Phase-5.5 + post-audit additions Modules 35.11 – 35.13).

## Identity posture

DevBrowse Standard targets **Brave+ / Firefox 119+ ETP parity with amiunique-generic cohort identity**:

1. **Every Standard DevBrowse user appears in the SAME cohort on static-identity probes** (UA, fonts, hardware, WebGL vendor / extensions, codec list, voices, network info, storage, display, touch). On amiunique-class probes, a DevBrowse Standard user is indistinguishable from any other DevBrowse Standard user.
2. **Dynamic readback surfaces (canvas, audio, WebGL numeric, DOMRect, TextMetrics) carry per-(origin, IdentityProfile) deterministic farbling** layered on top of the cohort base. Cross-site tracking is defeated AND same-site identity is stable across browser restarts.

**This is structurally better than:**
- **Brave** — Brave reshuffles farbling per session; DevBrowse keeps same-site identity stable across restarts (canvas-rendered avatars in IndexedDB don't break).
- **Firefox 119+ ETP** — Firefox has the cohort base but no farbling; cross-site tracking via canvas / audio is still reachable.

## What Standard shares with Strict (amiunique-generic)

Every static-identity surface uses the same cohort lock as Strict:

- **User-Agent**: `Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0` (Firefox 128 cohort).
- **`navigator.vendor`**: `""` (Firefox).
- **`navigator.userAgentData`**: not exposed (matches Firefox).
- **`navigator.deviceMemory`**: 8 (cohort value).
- **WebGL vendor + extension allowlist**: `"Mozilla"` + 5-extension cohort.
- **WebGPU vendor / architecture / features / limits**: cohort-locked metadata (vendor `"Mozilla"`).
- **Speech voices**: per-locale bucket (Standard threads the user's `navigator.language` into a cohort bucket rather than the per-OS voice list).
- **Media Capabilities**: same codec table (mode-invariant).
- **Network Information**: cohort-locked broadband (`effectiveType = "4g"`, `downlink = 10`, `rtt = 50`, `saveData = false`, `type = "wifi"`).
- **Storage estimate**: `{quota: 1 GiB, usage: 0}` cohort.
- **Touch desktop cohort**: `maxTouchPoints = 0` + `pointer = fine` + `hover = hover` (v1.23 — same as Strict desktop).
- **`screen.colorDepth` / `pixelDepth`**: 24 in both modes.
- **`Intl.*` defaults**: en-US cohort.
- **Keyboard layout**: US-QWERTY.

## Where Standard differs from Strict

These surfaces are per-Mode by design:

| Surface | Standard | Strict |
|---|---|---|
| `navigator.hardwareConcurrency` | 4 | 2 |
| `devicePixelRatio` | Bucketed {1.0, 1.5, 2.0, 3.0} | Locked 1.0 |
| Canvas readback | Cohort + ±1 LSB farble | Pure cohort lock |
| WebGL numeric (MAX_*) | Cohort + ±1 farble | Pure cohort lock |
| Audio Float32 samples | Cohort + ±1e-5 farble | Pure cohort lock |
| DOMRect / TextMetrics | Integer snap + ±1 px farble | Integer snap only |
| Timezone | User-configurable from `COMMON_TIMEZONES` (10 entries) | Locked UTC |
| Letterboxing (window dims) | Native (no quantization in Standard v1) | 200×100 grid |
| Permission API | Consults Module 59 grant store | Polluted-oracle (denied / prompt only) |
| Disabled APIs (L44) | Permission-gated via Module 59 | Hard-denied |
| Screen orientation | Reports actual (mobile-responsive) | Locked `landscape-primary` |

## Farbling design

**Per-(origin, IdentityProfile) deterministic farbling** — same origin under the same identity always produces the same farbled output (UX stable across restarts); different origins or different identities produce different output (cross-site tracking defeated).

**Streams covered:**
- Canvas readback (`FarblingSurface::Canvas`)
- WebGL numeric MAX_* (`FarblingSurface::WebGlNumeric`)
- Audio Float32 samples (`FarblingSurface::Audio`)
- DOMRect coordinates (`FarblingSurface::DomRect`) — audit addition 2026-05-22
- TextMetrics widths (`FarblingSurface::TextMetrics`) — audit addition 2026-05-22

**Cross-surface independence:** each surface has a disjoint SHA-256 stream (different tag byte). A site cannot cross-correlate `canvas-offset[i]` vs `audio-offset[i]` to recover one from the other.

**Seed derivation:** `PartitionKey::farbling_seed()` — 16-byte SHA-256 sub-derivation from `(partition_key.bytes, "PB-FARBLING-V1")`. Domain-separated from the partition-key derivation itself.

**Optional V2 (per-session-rotation):** added 2026-05-22 (P2-2 audit recommendation). Orchestrator can opt-in per IdentityProfile to a `FarblingEpoch` (CSPRNG-generated at startup) that rotates farbling outputs across browser restarts — defeats the WWW'25-class statistical pixel-recovery attack against fixed-amplitude noise. V1 (deterministic) remains the default to preserve same-site stability; V2 is a settings-toggle for users prioritizing WWW'25 resistance.

## What Standard does NOT do

- **No `Sec-CH-UA-*` Client Hints** (Module 22 strips them on the wire; Module 34 doesn't expose `userAgentData`).
- **No Chrome-style brand list** spoofing — would create a Firefox-UA / Chrome-data inconsistency.
- **No per-session farbling reshuffle by default** — UX stability prioritized over WWW'25 resistance unless the user opts in via the V2 toggle.

## How Standard compares

| Surface | DevBrowse Standard | Brave | Firefox 119+ ETP | LibreWolf |
|---|---|---|---|---|
| Canvas | Cohort + deterministic farble | Per-session farble | Cohort, no farble | Tor RFP |
| WebGL | "Mozilla" cohort | Per-session farble | "Mozilla" cohort | Tor RFP |
| Audio | Cohort + farble | Per-session farble | Cohort | Tor RFP |
| **DPR** | **Bucketed (Retina UX)** | Native | Native | Hard 1.0 |
| `hwConcurrency` | 4 cohort | Native | Native | 2 |
| **Farbling determinism** | **Same-site stable** | Per-session | None | n/a |
| Storage estimate | 1 GiB cohort | Partitioned | Per-partition real | Per-partition |
| Network Info | Cohort `"4g"` | Removed | Disabled | Disabled |

The bolded rows are DevBrowse-unique advantages.

## Threat-model coverage

Standard targets passive tracking (A1) and partial cross-site linking. It does NOT target compromised-renderer (A2) attackers the way Strict does — Standard permits permission-gated APIs (geolocation, camera) when the user grants per-site via Module 59.

If your threat model includes a hostile renderer or you need amiunique-class total cohort uniformity, use Strict.
