// Module 64 — First-launch setup wizard (Phase 8).
//
// Architecture L23: per-feature opt-in flow. Features declined here are
// disabled at code-path level, not just UI-hidden.
//
// Wizard pages (in order):
//   1. Privacy mode default select new tab open (Standard / Strict)
//   2. Sync backend selection (BYO-cloud, L21) — or skip
//   3. Search engine (L18: DDG default, curated set)
//   4. DoH provider (L25: Quad9 default; NextDNS requires config ID entry)
//   5. Translation / spellcheck (L20: both OFF by default)
//   6. Fingerprint normalization level (L8/§5.5)
//   7. History retention (L29: forever default)
//   8. Disk logging opt-in (L27: OFF by default)
//   9. Theme Selection Default system (system/light/dark/custom)
//
// L23 invariants — never weaken:
//   * Declined features must be disabled at code-path level.
//   * The wizard marks `config.wizard.completed = true` only after all
//     pages have been shown and choices persisted.
//   * DoH: if user picks NextDNS but declines to enter a config ID, the
//     wizard silently falls back to Quad9 (L25 NextDNS rule).
//
// TODO Module 64: implement each wizard page as an Iced view, the
// per-feature enable/disable wiring, and atomic config save on completion.
