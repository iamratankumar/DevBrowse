# Contributing to DevBrowse

DevBrowse is a privacy-focused Rust browser. This document covers how to set
up the workspace, what we expect from a patch, and the rules that are
non-negotiable.

## Read this first

`docs/architecture.md` is the canonical specification. Every locked decision
(L1 through L39 in v1.6), every security invariant, every module boundary
descends from that document. **When code disagrees with the architecture
doc, the doc wins** until the doc is explicitly revised.

If you are unsure about a design choice, the rule is:

1. Read `docs/architecture.md`.
2. Open a discussion issue and ask.
3. Do not infer from existing code — it may pre-date a revision.

## Workspace layout

13 crates as of v1.6:

- `pb-ipc`, `pb-config`, `pb-sandbox` — anyone may import these.
- `pb-platform` — leaf crate, zero `pb-*` deps.
- `pb-identity`, `pb-storage`, `pb-network`, `pb-fingerprint`, `pb-gpu`,
  `pb-extensions`, `pb-update`, `pb-ui`, `pb-browser`.

The dependency rule (L12) is enforced at Cargo.toml review: a crate may
import only `pb-ipc`, `pb-config`, and `pb-sandbox`. No other `pb-X → pb-Y`
imports.

## Building and testing

Required:

- Rust stable (the workspace `Cargo.toml` does not pin a specific version
  yet; CI tracks current stable).
- Protobuf compiler (`protoc`) for `pb-ipc` codegen.

Common commands:

```sh
cargo build --workspace
cargo test  --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt   --all
cargo deny  check   # supply-chain gate, per L15
```

A patch that breaks any of the above will not be merged.

## Cross-platform discipline (lock)

Every crate must compile on Linux, macOS, and Windows at all times. Mobile
(iOS, Android) is in scope and design-disciplined throughout — see Phase 12
in `docs/architecture.md`. Concretely:

- Public API surface is identical on all platforms.
- Platform-specific code lives behind `#[cfg(unix)]` / `#[cfg(windows)]` /
  `#[cfg(target_os = "...")]` inside a single module, never as a separate
  crate.
- A `compile_error!` guards platforms we do not support yet (so a stray
  `cargo check --target` fails loudly instead of silently producing a stub).

## Unsafe code (lock L13)

- Every crate root carries `#![forbid(unsafe_code)]` by default.
- Crates that need FFI (planned: `pb-fingerprint`, `pb-gpu`, the future
  `pb-sandbox::enforce` submodule) downgrade the crate root to
  `#![deny(unsafe_code)]` and isolate `unsafe` to a single FFI module marked
  with `#[allow(unsafe_code)]`.
- Unsafe blocks remain visible in code review forever. A patch that adds
  `unsafe` outside the annotated FFI module is not mergeable.

## What goes in a patch

Every PR should:

- Have a clear, single-purpose title.
- Include tests. New behavior needs a positive test; new invariants need a
  negative test that fails without the change.
- Update `docs/architecture.md` if it touches a locked decision. Add a
  revision-log entry in §10 with date, what changed, and why.
- Update SECURITY INVARIANT comments in any file whose invariant changed.
- Pass `cargo fmt`, `cargo clippy -D warnings`, `cargo test`, `cargo deny
  check`.

What does not belong in a patch:

- Mass refactors mixed with feature work — split them.
- New dependencies without a cargo-deny clean run — supply chain is a lock.
- Optimizations that weaken a security invariant. Browser code ships
  correctness first.
- Backwards-compatibility shims for code that does not exist yet.

## Commit and PR style

- Imperative mood, present tense ("add", "fix", "lock"; not "added",
  "fixes", "locking").
- Reference architecture sections by number when relevant
  (`enforces §3.4 sharing rule`).
- Squash trivial fixups before review; we want a readable commit graph in
  `main`.

## Reporting security issues

Do not open a public issue for a security report. See `SECURITY.md`.

## Code of conduct

Be kind, be technical, separate the work from the person. We will publish a
formal Code of Conduct alongside the v1.0 release.
