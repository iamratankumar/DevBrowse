// Developer Tools — Module 55.
//
// Implementation: Gecko built-in DevTools (Firefox DevTools), opened via F12
// or right-click → Inspect. Zero custom implementation — we expose what Gecko
// ships. Customization deferred; no approach locked yet.
//
// SECURITY INVARIANT — never change without explicit decision:
//   strict mode  → DevTools blocked entirely at identity context level
//   standard mode → DevTools allowed; opened via F12 / context menu
//
// Rationale for strict block: DevTools console gives direct JS access to
// pre-normalization values, which would let a determined user read their
// actual canvas/timer output before our bucketing is applied.
