// Module 59 — Permission center (Phase 8).
//
// UX flagship feature (architecture §8): every permission grant is visible,
// every grant is revocable, and a history of which site asked for what is
// displayed. Permission state is owned per-identity in pb-identity (Module 7)
// and queried/updated through pb-ipc — this module is the UI surface only.
//
// TODO Module 59: implement permission list view, per-site grant/revoke
// controls, and the per-identity permission history timeline.
