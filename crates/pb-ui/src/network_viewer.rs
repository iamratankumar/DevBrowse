// Module 60 — Network viewer / privacy trust panel (Phase 8).
//
// UX flagship feature (architecture §8, L26): real-time per-tab panel showing
// blocked trackers, blocked ads, DoH resolution path, and partition decisions
// per request. This is the "mini Wireshark" for privacy.
//
// L26 invariants — never weaken:
//   * Counters are pure-local and in-process. Never persisted. Never sent
//     over the network. A forensic disk read shows nothing.
//   * The address-bar badge shows the total blocked count; this panel shows
//     the full breakdown (ads vs trackers vs fingerprint attempts).
//   * Module 21 (blocklist) emits classified events; this module only reads
//     them for display — it owns no blocking logic of its own.
//
// TODO Module 60: implement the network request list, per-request detail
// pane, blocked-item breakdown, and DoH resolution path visualizer.
