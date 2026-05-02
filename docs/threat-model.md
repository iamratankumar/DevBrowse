# DevBrowse — Threat Model

Last revised 2026-04-30 (anchored to architecture.md v1.9 and plan.md v1.10).

This document fixes the boundaries of the security work in plan.md. It
exists so that scope creep into out-of-model attackers is caught at
review time, not after months of misaligned implementation.

The threat model is paired with architecture.md (which defines *what*
we build) and plan.md (which defines *how*). When in conflict, this
document defines what we *defend against*; the others define what
counts as defense.

---

## Attacker profiles (in scope)

### A1 — Tracking-and-fingerprinting adversary

A web-scale ad/tracking network correlating users across sites via JS
API readouts (canvas, WebGL, audio, fonts, timers, navigator, WebRTC),
TLS handshake (JA3, SNI, CT), and request shape (headers, storage
state, cache state).

**Defenses:** Phase 4 (network), Phase 5 (fingerprint), Phase 10
(adversarial verification), L21 sync that does not exfiltrate, L27
forensic redaction, L30-L37 network-level locks, Adaptation protocol
cohort-watch.

**Won-by:** the user being indistinguishable from the cohort of all
DevBrowse users on the same release.

### A2 — Compromised renderer

A renderer process taken over by exploit. Tries to escalate to read
other identities' storage, peek into the network broker, or violate
the partition-key boundary.

**Defenses:** Module 12 + 80.5 (kernel sandbox), pb-storage gatekeeper,
partition-key recompute on every request (Module 19), per-process
isolation (each renderer is its own OS process). The renderer is
trusted to be untrusted.

**Won-by:** the gatekeeper rejecting every cross-partition access the
renderer attempts, regardless of what it claims about its own identity.

### A3 — LAN attacker

A peer on the same WiFi attempting to: (a) discover what devices a
user owns via mDNS, (b) hijack pairing, (c) impersonate a paired
peer, (d) replay an old sync message.

**Defenses:** L21 mDNS pair-once HMAC identity (rotating-nonce TXT
record so outsiders see only random bytes); SPAKE2 PAKE + 4-emoji
fingerprint compare (Module 87.1, 87.2); QUIC mTLS via pinned Ed25519
keys (no CA); per-pair monotonic sequence + 5-minute replay window
(Module 88).

**Won-by:** an outsider on the same LAN learning nothing beyond "there
exist some DevBrowse devices here."

### A4 — Forensic-disk adversary

An attacker with cold-disk access to a powered-off device. Tries to
read browsing history, sync logs, vault contents, cached credentials.

**Defenses:** L27 forensic redaction (no PII in logs / crash reports
/ config dumps); L24 vault format with Argon2id-derived key + AEAD
(Module 83.1, 83.3); auto-lock on suspend / lid / inactivity (Module
83.5); zeroize on drop (Module 83.4). Strict-tab data is never written
to disk.

**Won-by:** post-mortem disk inspection yielding no PII and no
decryptable data without the passphrase.

### A5 — Hostile sync peer

A formerly-paired device whose user has gone hostile, or a hub-peer
operator (Module 89).

**Defenses:** Module 91 cluster-key rotation invalidates the removed
device's stored data; per-recipient X25519 sealed-box envelopes mean
hub-peer operators cannot read direct-message blobs; signed
append-only sync log (Module 84) makes tamper visible.

**Won-by:** removed peer cannot decrypt new data; hub-peer cannot
read any per-recipient blob.

### A6 — Supply-chain adversary on a privacy-critical primitive

An upstream maintainer publishes a tampered crate version (rustls,
argon2, chacha20poly1305, prost).

**Defenses:** L7 audited primitives only; cohort-watch dependency
list (plan.md Adaptation protocol); reproducible builds (L38); dual
release signing (L39 — offline GPG + Sigstore Rekor); `cargo vet`
in CI; Module 24.2 cohort-drift detection.

**Won-by:** an unsigned or unvet'd primitive bump cannot reach release;
a successful tampering attack is detected by cohort-drift CI before
ship.

---

## Out-of-scope attackers (explicitly)

The following adversaries are **not** defended against. Documenting
this prevents scope creep into work that does not match the project's
size or threat budget.

### N1 — Nation-state with kernel-or-firmware access

Out of scope. If the OS kernel is compromised, or the firmware is
backdoored, no user-space browser can defend. Recommend hardware
solutions (Tor over Tails on a verified-boot device).

### N2 — Targeted attacker with physical access to an unlocked device

Out of scope while the device is unlocked. Vault auto-lock on
suspend / lid / inactivity is the time-window mitigation; if the
device is unlocked and unattended, defense is delegated to the OS
lock screen.

### N3 — Malicious extension (in Standard mode, after explicit user install)

Out of scope. Standard mode allows extensions per L16; the user is
responsible for the extensions they install. Strict mode blocks all
extensions (Module 40), so this attacker is mitigated for
privacy-sensitive sessions.

### N4 — Browser engine zero-day (Gecko)

Mitigated, not defended. Module 12.1 / 80.5 sandbox confines a
successful renderer compromise. We track Mozilla's security advisories
(Module 65 update channel) and ship patches. We do not maintain our
own fork of Gecko.

### N5 — Quantum adversary against current crypto

Mitigated by design. L24 vault format is versioned (Module 83.3);
format_version 2+ allows ML-KEM-768 / ML-DSA-65. Migration is a format
bump, not a rewrite.

### N6 — Side-channel attack via hardware (Spectre, Rowhammer)

Partial mitigation. Site isolation in Standard (§5.11) accepts
co-residence; Spectre mitigations on by default. Strict mandates
per-tab renderer (§3.3). Hardware-side rowhammer is out of scope.

### N7 — Attacker controlling the user's WebDAV relay (Module 92)

Out of scope for confidentiality (relay sees ciphertext only by
construction); in-scope for availability (relay can refuse to
forward). The user is told this in the wizard before they enable a
relay.

---

## Non-goal scope guards

The following are **explicit non-goals**, not simply "deferred." A
request to add any of them is rejected at review time.

- **Hosted DevBrowse cloud sync.** L21 anti-goal. Permanent. The
  architecture revision log (v1.9) ratifies it.
- **Bundled VPN, Tor, or proxy.** Out of scope. Users who want
  network-layer anonymity should use Tor Browser. DevBrowse does not
  aim to hide the user's IP from the network.
- **Anti-AV / anti-EDR stealth.** Out of scope and security-negative.
  The signed update channel and reproducible builds (L38, L39)
  cooperate with AV/EDR vendors, never evade.
- **Crypto-currency wallet integration.** Out of scope; large attack
  surface, no privacy benefit over a separate wallet app.
- **Sync of OS-level credentials (SSH keys, passkeys).** Deferred to
  a separate password-manager-phase project per architecture
  decisions; not part of DevBrowse v1.0.

---

## Defense-in-depth posture

DevBrowse layers defenses; no single layer is the boundary:

1. **Crate boundaries** (L12) prevent capability creep.
2. **Process boundaries** (renderer / network / storage / orchestrator)
   make a single compromise insufficient for privacy violation.
3. **Sandbox** (Modules 12, 80.5) confines the compromised process at
   the kernel level.
4. **Partition-key gatekeeper** (Module 15) rejects every
   cross-identity access regardless of the originating layer.
5. **Forensic redaction** (L27) ensures even legitimate logs and crash
   reports do not exfiltrate PII.
6. **Vault auto-lock** (Module 83.5) limits the cold-disk window to
   the unlocked-and-active period.
7. **Cohort drift detection** (Module 24.2) catches a compromised
   primitive before it reaches release.

A successful attack must defeat *all seven* layers simultaneously.
Each layer's failure mode is documented in the corresponding plan.md
module entry.

---

## Strict-mode invariant (cross-cutting)

For attackers A1, A2, and A3 above, Strict mode is the user's
escape hatch. The following invariants apply to every defense:

- A defense that is weaker in Strict than in Standard is a bug.
- A defense whose Strict variant introduces a new fingerprint surface
  (e.g. a Strict-only HTTP header) is also a bug.
- The wire shape (JA3, ClientHello, request headers, mDNS TXT) is
  identical between Standard and Strict; mode separation lives at
  the application layer.

These rules are enforced at module review per plan.md cross-cutting
concern #12 (Performance contract) and the per-module
"Strict-mode invariant" lines in plan.md.

---

## Revision log

- 2026-04-30 — initial draft, paired with plan.md v1.10 and
  architecture.md v1.9.
