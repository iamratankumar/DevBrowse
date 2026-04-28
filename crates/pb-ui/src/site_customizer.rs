// Module 61 — Site customizer (Phase 8).
//
// UX flagship feature (architecture §8): right-click on any page element
// to kill overlays, hide tracker widgets, or dim sections. Choices are
// persisted as cosmetic filter rules scoped to the originating site.
//
// Design boundary: this module emits cosmetic filter rules (CSS selectors +
// actions). It does NOT implement the filter engine — that lives in
// pb-network / pb-fingerprint. The rules are site-scoped so they cannot
// leak across identity profiles.
//
// TODO Module 61: implement the context-menu inspector, element picker
// overlay, and cosmetic rule serialization to pb-config / pb-storage.
