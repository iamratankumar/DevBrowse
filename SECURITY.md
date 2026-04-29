# Security Policy

DevBrowse is a privacy-focused browser. The goal of this document is to make
it easy and predictable for security researchers to report vulnerabilities,
and to set expectations for how we triage, fix, and credit them.

## Reporting a vulnerability

**Do not open a public GitHub issue for a security report.** Use one of:

1. **GitHub Security Advisory** (preferred):
   `https://github.com/iamratankumar/DevBrowse/security/advisories/new`.
   This creates a private channel between you and the maintainers.
2. **Encrypted email** to `security@devbrowse` (placeholder — replace with the
   real address before tagging the first public release). PGP key fingerprint
   will be published alongside the v1.0 release artifacts (lock L39 — release
   signing).

Please include:

- A clear description of the issue and its impact.
- A minimal reproducer (HTML page, network capture, code snippet, etc.).
- The exact build (`devbrowse --version`) and OS where you observed it.
- Whether you intend to publish the issue, and on what timeline.

If you do not get an acknowledgement within **3 working days**, please nudge
the channel — a missed notification is the most common failure mode.

## Scope

**In scope** for a security advisory and credit:

- Code in this repository under `crates/`.
- DevBrowse-specific behavior on top of Gecko (libxul wrapping, IPC schema,
  capability boundaries, partition-key gatekeeper, sandbox profile, etc.).
- Release artifacts produced by our CI (binary, blocklist track, HSTS preload
  track, update manifests).
- Cryptographic protocol composition for the BYO-cloud sync vault (Phase 11.5).

**Out of scope** unless DevBrowse's integration introduces or amplifies the
issue:

- Vulnerabilities in upstream Gecko / libxul itself. Please report those to
  Mozilla. We will track and patch downstream once an upstream fix is
  available.
- Vulnerabilities in audited primitives we compose (Argon2id, XChaCha20-Poly1305,
  HKDF, Ed25519, X25519). Report those to the underlying library.
- Issues that require a local attacker with arbitrary code execution
  privileges already on the user's machine.
- Self-XSS via `javascript:` URLs typed by the user into the address bar.
- Missing security headers on the project website (this is the browser, not
  a web service).

## What we treat as critical

The architecture document (`docs/architecture.md`) enumerates locked invariants
(L1 through L39 in v1.6). Anything that **breaks** one of those locks is by
default Critical. Concrete examples:

- A renderer obtaining direct filesystem access without going through a
  capability handle (breaks L10 / §5.3).
- A storage operation that bypasses the partition-key gatekeeper (breaks
  §5.2).
- A path that leaks Strict-mode storage / cookies / cache to a Standard tab,
  or vice versa (breaks §3.3 / §3.6).
- Unsafe code outside an explicitly-annotated FFI module (breaks L13 / §5.6).
- A renderer that talks directly to the network without going through the
  network broker, or that opens a kernel sandbox hole (breaks §5.1 / §5.8).
- Clipboard read or write without a fresh `GestureToken` (breaks L11 / §5.4).
- Telemetry that ships user-identifying data anywhere (breaks §1.3 anti-goal).
- Any release artifact that fails reproducible-build verification or signature
  verification (breaks L38 / L39).

## Disclosure timeline

We aim for **coordinated disclosure within 90 days** of the report. If we need
longer (complex multi-crate fix, upstream Gecko coordination, blocklist track
update window) we will say so explicitly and propose a revised date.

Once a fix is released, we publish the advisory with credit to the reporter
unless the reporter prefers to remain anonymous.

## Bounty

No paid bounty in v1. We credit reporters in:

- The published GitHub Security Advisory.
- The release notes for the version that fixes the issue.
- An acknowledgements page once one exists (planned for the v1.0 release).

## Cryptographic posture

- TLS uses rustls (no OpenSSL) — see lock L6.
- Identifier crypto and partition keys use UUID v4 + SHA-256 — see L7.
- Sync vault uses Argon2id, XChaCha20-Poly1305, HKDF, Ed25519, X25519 — see
  L22.
- We do not invent ciphers, hashes, or PRFs. Reports of "DevBrowse rolled its
  own crypto" are bugs we want to hear about.

## Release verification

Every published release artifact carries:

- A GPG detached signature from our offline release key (rotated annually;
  fingerprint in the repo).
- A Sigstore signature recorded in the Rekor public transparency log.

Reproducibility:

- The Rust toolchain version and full dependency tree are pinned in the
  release tag.
- The published `sha256` is verifiable by an independent rebuild from source.

If a verification step fails, treat the artifact as untrusted and report it
through the channels above.
