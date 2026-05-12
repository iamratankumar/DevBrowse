//! Ja3Probe fixture, Module 24.2 — JA3 cohort-drift detection.
//!
//! Drives a [`rustls::ClientConnection`] just far enough to render its
//! ClientHello, captures the bytes rustls would have written to the
//! wire, and exposes a parser that extracts the JA3-relevant fields.
//!
//! ## Why no TCP / no tokio
//!
//! The cohort drift we are catching is "did rustls's ClientHello shape
//! shift between versions" — purely a function of the
//! [`rustls::ClientConfig`] passed in. We do not need an actual TLS
//! peer to observe the shift; rustls's state machine writes the
//! ClientHello as soon as it has somewhere to write to. Driving the
//! state machine synchronously via [`ClientConnection::write_tls`]
//! into a [`Vec<u8>`] sink is enough — and avoids pulling tokio /
//! tokio-rustls / TcpListener into the test path.
//!
//! ## What this fixture is and is not
//!
//! It IS:
//!   * A faithful reproduction of the bytes rustls 0.23 (with the
//!     workspace's pinned features) would put on the wire as the first
//!     write of a TLS handshake when configured with the supplied
//!     [`Arc<ClientConfig>`].
//!   * A best-effort parser of TLS 1.2 / 1.3 ClientHello records into
//!     the JA3 fields (legacy_version, cipher_suites, extensions,
//!     supported_groups, ec_point_formats), with GREASE filtering per
//!     the JA3 specification.
//!
//! It IS NOT:
//!   * A TLS handshake driver. Nothing on the other side of the
//!     captured bytes ever responds — we are reading rustls's first
//!     output and stopping there.
//!   * A general TLS parser. The parser handles the well-formed
//!     ClientHellos that rustls 0.23 produces; it does not handle
//!     fragmented records, post-handshake messages, or hostile
//!     malformed inputs. (The rustls bytes are trusted — they came
//!     from rustls.)
//!
//! ## GREASE filtering
//!
//! [RFC 8701 GREASE](https://www.rfc-editor.org/rfc/rfc8701) values
//! are random nonce values intentionally interspersed in
//! cipher_suite / extension / supported_group lists to keep middleboxes
//! from ossifying on a fixed enumeration. They are excluded from the
//! JA3 hash by the JA3 specification because they would otherwise
//! produce a different hash on every handshake. rustls 0.23 does NOT
//! emit GREASE values (BoringSSL / Chrome / Firefox do); the filter
//! exists so the fixture remains correct if a future rustls bump
//! adds GREASE.

#![allow(clippy::needless_range_loop)] // parser style is index-driven

use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use rustls::ClientConnection;
use std::io;
use std::sync::Arc;
use thiserror::Error;

/// Errors the JA3 probe + parser can produce. Display strings are
/// opaque (L27) — no host / config bytes echo through.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProbeError {
    /// The supplied `server_name` failed [`ServerName::try_from`].
    #[error("ja3 probe: invalid server name")]
    ServerName,
    /// rustls refused to construct a [`ClientConnection`].
    #[error("ja3 probe: rustls construct failed")]
    RustlsConstruct,
    /// rustls's first `write_tls` call failed.
    #[error("ja3 probe: rustls write failed")]
    RustlsWrite,
    /// The captured bytes do not parse as a TLS Handshake record
    /// containing a ClientHello.
    #[error("ja3 probe: not a client hello")]
    NotClientHello,
    /// The ClientHello body is shorter than the minimum required
    /// fields (version + random + session_id_len + cipher_suites_len
    /// + ...).
    #[error("ja3 probe: client hello truncated")]
    Truncated,
    /// A length-prefixed list inside the ClientHello declared a
    /// length that ran past the enclosing buffer.
    #[error("ja3 probe: malformed length prefix")]
    MalformedLength,
}

// ── ClientHello capture ──────────────────────────────────────────────────

/// JA3 capture façade. Stateless — exists for naming.
#[derive(Debug, Default, Clone, Copy)]
pub struct Ja3Probe;

impl Ja3Probe {
    /// Capture the ClientHello bytes the supplied `client_config`
    /// would emit when initiating a handshake to `server_name`.
    ///
    /// The returned bytes are exactly what rustls's first
    /// [`ClientConnection::write_tls`] call produces — a TLS Record
    /// (content_type = 22 / Handshake) wrapping a Handshake message
    /// (msg_type = 1 / ClientHello). The handshake is **not** driven
    /// past this point; nothing ever reads the response, because there
    /// is no peer.
    ///
    /// Synchronous: no tokio, no TcpListener, no socket of any kind.
    /// The [`Vec<u8>`] sink the rustls state machine writes into is
    /// the entire I/O surface.
    pub fn capture_client_hello(
        client_config: Arc<ClientConfig>,
        server_name: &str,
    ) -> Result<Vec<u8>, ProbeError> {
        let owned: ServerName<'static> = ServerName::try_from(server_name)
            .map_err(|_| ProbeError::ServerName)?
            .to_owned();
        let mut conn =
            ClientConnection::new(client_config, owned).map_err(|_| ProbeError::RustlsConstruct)?;
        let mut buf: Vec<u8> = Vec::new();
        // Drive write_tls until rustls reports it has nothing more to
        // write. The first record is the ClientHello; rustls will
        // happily write zero bytes thereafter (it is waiting on us to
        // feed it the server's response). We loop instead of a single
        // call so a future rustls minor bump that splits the
        // ClientHello across two write_tls calls does not silently
        // truncate our capture.
        loop {
            let n = conn
                .write_tls(&mut buf as &mut dyn io::Write)
                .map_err(|_| ProbeError::RustlsWrite)?;
            if n == 0 {
                break;
            }
        }
        Ok(buf)
    }
}

// ── JA3 type ─────────────────────────────────────────────────────────────

/// JA3-relevant fields extracted from a parsed ClientHello, in the
/// order JA3 expects.
///
/// The four list fields have already had GREASE values stripped (per
/// JA3 specification + RFC 8701).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ja3 {
    /// `legacy_version` field of the ClientHello body. For TLS 1.3,
    /// rustls writes 0x0303 (TLS 1.2) here for backwards-compat; the
    /// real version is in the supported_versions extension.
    pub legacy_version: u16,
    /// Cipher suite IDs in the order advertised, GREASE removed.
    pub cipher_suites: Vec<u16>,
    /// Extension type IDs in the order advertised, GREASE removed.
    pub extensions: Vec<u16>,
    /// Supported group (curve) IDs from the `supported_groups`
    /// extension (type 10), GREASE removed. Empty if the extension
    /// is absent.
    pub supported_groups: Vec<u16>,
    /// EC point format IDs from the `ec_point_formats` extension
    /// (type 11). Empty if the extension is absent.
    pub ec_point_formats: Vec<u8>,
}

impl Ja3 {
    /// Parse a captured ClientHello byte sequence into a [`Ja3`].
    ///
    /// `bytes` is expected to start with a TLS Record Layer header
    /// (5 bytes: content_type / version / length) wrapping a
    /// Handshake message (4-byte header: msg_type / 24-bit length)
    /// of type ClientHello. This matches the
    /// [`Ja3Probe::capture_client_hello`] output shape.
    pub fn from_client_hello(bytes: &[u8]) -> Result<Self, ProbeError> {
        // ── Record Layer ──
        if bytes.len() < 5 {
            return Err(ProbeError::NotClientHello);
        }
        if bytes[0] != 0x16 {
            // 0x16 == 22 == TLS Handshake.
            return Err(ProbeError::NotClientHello);
        }
        let record_len = u16::from_be_bytes([bytes[3], bytes[4]]) as usize;
        if bytes.len() < 5 + record_len {
            return Err(ProbeError::Truncated);
        }
        let body = &bytes[5..5 + record_len];

        // ── Handshake header ──
        if body.len() < 4 {
            return Err(ProbeError::Truncated);
        }
        if body[0] != 0x01 {
            // 0x01 == ClientHello.
            return Err(ProbeError::NotClientHello);
        }
        let hs_len = ((body[1] as usize) << 16) | ((body[2] as usize) << 8) | (body[3] as usize);
        if body.len() < 4 + hs_len {
            return Err(ProbeError::Truncated);
        }
        let hello = &body[4..4 + hs_len];

        // ── ClientHello body ──
        let mut p = ParseCursor::new(hello);
        let legacy_version = p.read_u16()?;
        p.skip(32)?; // random
        let session_id_len = p.read_u8()? as usize;
        p.skip(session_id_len)?;

        let cipher_suites_bytes = p.read_u16()? as usize;
        if !cipher_suites_bytes.is_multiple_of(2) {
            return Err(ProbeError::MalformedLength);
        }
        let mut cipher_suites = Vec::with_capacity(cipher_suites_bytes / 2);
        for _ in 0..(cipher_suites_bytes / 2) {
            let suite = p.read_u16()?;
            if !is_grease_u16(suite) {
                cipher_suites.push(suite);
            }
        }

        let comp_methods_len = p.read_u8()? as usize;
        p.skip(comp_methods_len)?;

        // ── Extensions ──
        let mut extensions = Vec::new();
        let mut supported_groups = Vec::new();
        let mut ec_point_formats = Vec::new();
        if !p.is_empty() {
            let ext_total = p.read_u16()? as usize;
            let mut ext_cursor = ParseCursor::new(p.take(ext_total)?);
            while !ext_cursor.is_empty() {
                let ext_type = ext_cursor.read_u16()?;
                let ext_len = ext_cursor.read_u16()? as usize;
                let ext_body = ext_cursor.take(ext_len)?;
                if !is_grease_u16(ext_type) {
                    extensions.push(ext_type);
                }
                match ext_type {
                    // supported_groups (RFC 8446 §4.2.7).
                    0x000A => {
                        let mut g = ParseCursor::new(ext_body);
                        let list_bytes = g.read_u16()? as usize;
                        if !list_bytes.is_multiple_of(2) {
                            return Err(ProbeError::MalformedLength);
                        }
                        let list = g.take(list_bytes)?;
                        for chunk in list.chunks_exact(2) {
                            let id = u16::from_be_bytes([chunk[0], chunk[1]]);
                            if !is_grease_u16(id) {
                                supported_groups.push(id);
                            }
                        }
                    }
                    // ec_point_formats (RFC 4492 §5.1).
                    0x000B => {
                        let mut f = ParseCursor::new(ext_body);
                        let list_bytes = f.read_u8()? as usize;
                        let list = f.take(list_bytes)?;
                        ec_point_formats.extend_from_slice(list);
                    }
                    _ => { /* not part of JA3 */ }
                }
            }
        }

        Ok(Self {
            legacy_version,
            cipher_suites,
            extensions,
            supported_groups,
            ec_point_formats,
        })
    }

    /// Render the canonical JA3 string:
    ///
    /// ```text
    /// version,ciphers,extensions,curves,formats
    /// ```
    ///
    /// where `ciphers`, `extensions`, `curves`, `formats` are
    /// dash-separated decimal lists. The string is the input the
    /// JA3 specification feeds to MD5; for cohort-locking we pin
    /// the string itself (more readable than the digest, and an
    /// MD5 dep is avoidable).
    pub fn to_canonical_string(&self) -> String {
        let join_u16 = |v: &[u16]| -> String {
            v.iter()
                .map(|x| x.to_string())
                .collect::<Vec<_>>()
                .join("-")
        };
        let join_u8 = |v: &[u8]| -> String {
            v.iter()
                .map(|x| x.to_string())
                .collect::<Vec<_>>()
                .join("-")
        };
        format!(
            "{},{},{},{},{}",
            self.legacy_version,
            join_u16(&self.cipher_suites),
            join_u16(&self.extensions),
            join_u16(&self.supported_groups),
            join_u8(&self.ec_point_formats),
        )
    }
}

// ── Cursor helper ────────────────────────────────────────────────────────

struct ParseCursor<'a> {
    buf: &'a [u8],
}

impl<'a> ParseCursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    fn read_u8(&mut self) -> Result<u8, ProbeError> {
        let v = *self.buf.first().ok_or(ProbeError::Truncated)?;
        self.buf = &self.buf[1..];
        Ok(v)
    }

    fn read_u16(&mut self) -> Result<u16, ProbeError> {
        if self.buf.len() < 2 {
            return Err(ProbeError::Truncated);
        }
        let v = u16::from_be_bytes([self.buf[0], self.buf[1]]);
        self.buf = &self.buf[2..];
        Ok(v)
    }

    fn skip(&mut self, n: usize) -> Result<(), ProbeError> {
        if self.buf.len() < n {
            return Err(ProbeError::Truncated);
        }
        self.buf = &self.buf[n..];
        Ok(())
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], ProbeError> {
        if self.buf.len() < n {
            return Err(ProbeError::MalformedLength);
        }
        let (head, tail) = self.buf.split_at(n);
        self.buf = tail;
        Ok(head)
    }
}

// ── GREASE detection ─────────────────────────────────────────────────────

/// True iff `v` is a GREASE-reserved 16-bit value
/// (RFC 8701: 0x0a0a, 0x1a1a, 0x2a2a, ..., 0xfafa).
fn is_grease_u16(v: u16) -> bool {
    let high = (v >> 8) & 0xFF;
    let low = v & 0xFF;
    (high == low) && ((low & 0x0F) == 0x0A)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grease_detector_matches_rfc_8701_set() {
        // RFC 8701 §2 reserves 0x0a0a, 0x1a1a, ..., 0xfafa — high
        // byte equals low byte, both ending in 0xA.
        for n in 0..16u16 {
            let byte = (n << 4) | 0x0A;
            let v = (byte << 8) | byte;
            assert!(is_grease_u16(v), "{v:#06x} should be GREASE");
        }
        // Non-GREASE samples (real cipher suite IDs).
        for v in [
            0x1301u16, // TLS_AES_128_GCM_SHA256
            0x1302,    // TLS_AES_256_GCM_SHA384
            0x1303,    // TLS_CHACHA20_POLY1305_SHA256
            0xC02B,    // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            0xC02F,    // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        ] {
            assert!(!is_grease_u16(v), "{v:#06x} should not be GREASE");
        }
    }

    /// Hand-rolled minimal ClientHello for parser tests. Constructs:
    ///   * legacy_version = 0x0303
    ///   * 32-byte zero random
    ///   * empty session_id
    ///   * cipher_suites = [0x1301, 0x0A0A (GREASE), 0xC02B]
    ///   * compression_methods = [0]
    ///   * extensions: supported_groups [0x001D, 0x1A1A (GREASE)],
    ///     ec_point_formats [0x00]
    fn synthetic_client_hello() -> Vec<u8> {
        // ClientHello body
        let mut body: Vec<u8> = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes()); // legacy_version
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session_id len
                      // cipher_suites
        let cs: [u16; 3] = [0x1301, 0x0A0A, 0xC02B];
        body.extend_from_slice(&((cs.len() * 2) as u16).to_be_bytes());
        for s in cs {
            body.extend_from_slice(&s.to_be_bytes());
        }
        // compression_methods
        body.push(1);
        body.push(0);

        // extensions
        let mut exts: Vec<u8> = Vec::new();
        // supported_groups (type 0x000A)
        let groups: [u16; 2] = [0x001D, 0x1A1A];
        let mut sg_body: Vec<u8> = Vec::new();
        sg_body.extend_from_slice(&((groups.len() * 2) as u16).to_be_bytes());
        for g in groups {
            sg_body.extend_from_slice(&g.to_be_bytes());
        }
        exts.extend_from_slice(&0x000Au16.to_be_bytes());
        exts.extend_from_slice(&(sg_body.len() as u16).to_be_bytes());
        exts.extend_from_slice(&sg_body);
        // ec_point_formats (type 0x000B)
        let ec: [u8; 1] = [0x00];
        let mut ec_body: Vec<u8> = Vec::new();
        ec_body.push(ec.len() as u8);
        ec_body.extend_from_slice(&ec);
        exts.extend_from_slice(&0x000Bu16.to_be_bytes());
        exts.extend_from_slice(&(ec_body.len() as u16).to_be_bytes());
        exts.extend_from_slice(&ec_body);

        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        // Handshake header
        let mut hs: Vec<u8> = Vec::new();
        hs.push(0x01); // ClientHello
        let bl = body.len();
        hs.push(((bl >> 16) & 0xFF) as u8);
        hs.push(((bl >> 8) & 0xFF) as u8);
        hs.push((bl & 0xFF) as u8);
        hs.extend_from_slice(&body);

        // Record header
        let mut rec: Vec<u8> = Vec::new();
        rec.push(0x16); // Handshake
        rec.extend_from_slice(&0x0301u16.to_be_bytes()); // legacy record version
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn parse_synthetic_hello_strips_grease() {
        let bytes = synthetic_client_hello();
        let ja3 = Ja3::from_client_hello(&bytes).expect("parse should succeed");
        assert_eq!(ja3.legacy_version, 0x0303);
        // GREASE 0x0A0A removed.
        assert_eq!(ja3.cipher_suites, vec![0x1301, 0xC02B]);
        // Extensions advertised in declaration order.
        assert_eq!(ja3.extensions, vec![0x000A, 0x000B]);
        // GREASE 0x1A1A removed.
        assert_eq!(ja3.supported_groups, vec![0x001D]);
        assert_eq!(ja3.ec_point_formats, vec![0x00]);
    }

    #[test]
    fn canonical_string_matches_ja3_format() {
        let bytes = synthetic_client_hello();
        let ja3 = Ja3::from_client_hello(&bytes).unwrap();
        assert_eq!(ja3.to_canonical_string(), "771,4865-49195,10-11,29,0");
    }

    #[test]
    fn rejects_non_handshake_record() {
        let bytes = vec![0x17, 0x03, 0x03, 0x00, 0x00];
        assert_eq!(
            Ja3::from_client_hello(&bytes).unwrap_err(),
            ProbeError::NotClientHello
        );
    }

    #[test]
    fn rejects_truncated_record() {
        let bytes = vec![0x16, 0x03, 0x03];
        assert_eq!(
            Ja3::from_client_hello(&bytes).unwrap_err(),
            ProbeError::NotClientHello
        );
    }

    #[test]
    fn rejects_non_client_hello_handshake() {
        // A handshake record whose first byte is not 0x01 (ClientHello).
        let mut bytes = vec![0x16, 0x03, 0x03];
        let inner = vec![0x02u8, 0x00, 0x00, 0x00];
        bytes.extend_from_slice(&(inner.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&inner);
        assert_eq!(
            Ja3::from_client_hello(&bytes).unwrap_err(),
            ProbeError::NotClientHello
        );
    }

    #[test]
    fn errors_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ProbeError>();
        assert_send_sync::<Ja3>();
    }
}
