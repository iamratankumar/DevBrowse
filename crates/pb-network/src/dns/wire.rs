//! DNS message wire format, RFC 1035 + RFC 8484 (Module 20).
//!
//! Hand-rolled minimal encoder / decoder for the **A** and **AAAA**
//! query / response subset DevBrowse needs. Hand-rolling avoids a new
//! workspace dependency and lets us bound every read tightly. The
//! decoder defends against the historical DNS parsing bug shapes:
//!
//!   * compression-pointer loops (capped pointer chase depth)
//!   * malformed labels (> 63 bytes rejected)
//!   * malformed names (> 255 bytes total rejected)
//!   * truncated messages (every read is length-checked)
//!   * RDATA overflow (RDLENGTH validated against remaining buffer)
//!   * AAAA RDATA != 16 bytes / A RDATA != 4 bytes (rejected)
//!
//! The output is the smallest possible Rust value (just an effective
//! TTL and a Vec<DnsRecord>); CNAME chains are flattened and any
//! non-A/AAAA RR is silently skipped at decode time so a hostile
//! resolver cannot leak surprising types into the [`crate::Resolver`]
//! contract.
//!
//! ## L27 redaction
//!
//! Every error in this module produces an opaque `Display`; no
//! qname or RDATA bytes ever reach the error string.

use crate::dns::resolver::{DnsRecord, QueryType};
use std::net::{Ipv4Addr, Ipv6Addr};

/// Hard cap on total message length the decoder will consume. RFC 8484
/// recommends application/dns-message stays under 64 KiB; production
/// answers fit comfortably in 4 KiB.
pub const MAX_DNS_MESSAGE_BYTES: usize = 64 * 1024;

/// Maximum compression-pointer hops the decoder will follow. RFC 1035
/// permits compression but not loops; 16 is well above any legitimate
/// answer (deepest practical chain is <= 3).
const MAX_POINTER_HOPS: u32 = 16;

/// Maximum label length per RFC 1035 §3.1.
const MAX_LABEL_LEN: usize = 63;

/// Maximum total name length per RFC 1035 §2.3.4.
const MAX_NAME_LEN: usize = 255;

/// Errors produced by the wire codec. L27: every Display is opaque.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WireError {
    #[error("dns wire: message too large")]
    MessageTooLarge,
    #[error("dns wire: truncated message")]
    Truncated,
    #[error("dns wire: malformed label")]
    MalformedLabel,
    #[error("dns wire: malformed name")]
    MalformedName,
    #[error("dns wire: name compression loop")]
    CompressionLoop,
    #[error("dns wire: question count not 1")]
    UnexpectedQuestionCount,
    #[error("dns wire: rcode indicates server failure")]
    ServerFailure,
    #[error("dns wire: rcode indicates format error")]
    FormatError,
    #[error("dns wire: nxdomain")]
    NxDomain,
    #[error("dns wire: rcode unrecognized")]
    UnknownRcode,
    #[error("dns wire: rdata length mismatch")]
    RdataLengthMismatch,
    #[error("dns wire: invalid hostname")]
    InvalidHostname,
}

/// Encode an `application/dns-message` query body for `qname` / `qtype`.
///
/// Header conventions follow RFC 8484 §4.1:
///   * ID = 0 (correlation is HTTP-level)
///   * RD = 1 (recursion desired)
///   * QDCOUNT = 1
///
/// The encoder lowercases `qname` and validates each label (length and
/// character set). DoH endpoints are case-insensitive but a lowercased
/// query keeps the on-wire bytes deterministic, which simplifies the
/// cohort-watch fingerprint posture (Module 24).
pub fn encode_query(qname: &str, qtype: QueryType) -> Result<Vec<u8>, WireError> {
    let mut out = Vec::with_capacity(64);
    // Header: ID=0, RD=1, QDCOUNT=1, all other counts 0.
    out.extend_from_slice(&[0, 0]); // ID
    out.extend_from_slice(&[0x01, 0x00]); // Flags: standard query, RD=1
    out.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
    out.extend_from_slice(&[0x00, 0x00]); // ANCOUNT
    out.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
    out.extend_from_slice(&[0x00, 0x00]); // ARCOUNT
    encode_name(&mut out, qname)?;
    out.extend_from_slice(&qtype.type_code().to_be_bytes());
    out.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN
    Ok(out)
}

fn encode_name(out: &mut Vec<u8>, qname: &str) -> Result<(), WireError> {
    if qname.is_empty() {
        return Err(WireError::InvalidHostname);
    }
    let mut total_len = 0usize;
    for label in qname.split('.') {
        if label.is_empty() {
            return Err(WireError::InvalidHostname);
        }
        if label.len() > MAX_LABEL_LEN {
            return Err(WireError::InvalidHostname);
        }
        // Labels are LDH (letters / digits / hyphens) per RFC 1035; we
        // accept ASCII alphanumeric + `-` + `_` (the latter for service
        // labels in lookups like `_dmarc`).
        for b in label.bytes() {
            let ok = b.is_ascii_alphanumeric() || b == b'-' || b == b'_';
            if !ok {
                return Err(WireError::InvalidHostname);
            }
        }
        out.push(label.len() as u8);
        for b in label.bytes() {
            out.push(b.to_ascii_lowercase());
        }
        total_len += 1 + label.len();
        if total_len > MAX_NAME_LEN {
            return Err(WireError::InvalidHostname);
        }
    }
    out.push(0); // root label terminator
    Ok(())
}

/// Decoded answer: positive records + effective TTL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedAnswer {
    pub records: Vec<DnsRecord>,
    pub min_ttl: u32,
}

/// Decode an `application/dns-message` response into A/AAAA records.
///
/// Returns `Err(WireError::NxDomain)` for RCODE 3 (NXDOMAIN). All
/// other non-zero RCODEs return their typed variant. RDATA of types
/// other than A/AAAA is silently skipped (CNAMEs are followed
/// implicitly when the resolver chained the name; we only surface
/// addresses).
pub fn decode_response(buf: &[u8]) -> Result<DecodedAnswer, WireError> {
    if buf.len() > MAX_DNS_MESSAGE_BYTES {
        return Err(WireError::MessageTooLarge);
    }
    if buf.len() < 12 {
        return Err(WireError::Truncated);
    }
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    let rcode = (flags & 0x000F) as u8;
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    let ancount = u16::from_be_bytes([buf[6], buf[7]]);
    if qdcount != 1 {
        return Err(WireError::UnexpectedQuestionCount);
    }
    match rcode {
        0 => {} // NoError; continue.
        2 => return Err(WireError::ServerFailure),
        1 => return Err(WireError::FormatError),
        3 => return Err(WireError::NxDomain),
        _ => return Err(WireError::UnknownRcode),
    }
    // Skip the question section: name + qtype(2) + qclass(2).
    let mut cursor = 12usize;
    cursor = skip_name(buf, cursor)?;
    cursor = read_advance(buf, cursor, 4)?;

    let mut records = Vec::new();
    let mut min_ttl = u32::MAX;
    for _ in 0..ancount {
        cursor = skip_name(buf, cursor)?;
        let rrtype = read_u16(buf, cursor)?;
        let _class = read_u16(buf, cursor + 2)?;
        let ttl = read_u32(buf, cursor + 4)?;
        let rdlength = read_u16(buf, cursor + 8)? as usize;
        cursor += 10;
        if cursor + rdlength > buf.len() {
            return Err(WireError::RdataLengthMismatch);
        }
        let rdata = &buf[cursor..cursor + rdlength];
        match rrtype {
            1 => {
                // A
                if rdata.len() != 4 {
                    return Err(WireError::RdataLengthMismatch);
                }
                let ip = Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]);
                records.push(DnsRecord::A(ip));
                if ttl < min_ttl {
                    min_ttl = ttl;
                }
            }
            28 => {
                // AAAA
                if rdata.len() != 16 {
                    return Err(WireError::RdataLengthMismatch);
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(rdata);
                let ip = Ipv6Addr::from(octets);
                records.push(DnsRecord::Aaaa(ip));
                if ttl < min_ttl {
                    min_ttl = ttl;
                }
            }
            _ => {
                // Skip CNAME / OPT / etc. silently.
            }
        }
        cursor += rdlength;
    }
    let min_ttl = if records.is_empty() { 0 } else { min_ttl };
    Ok(DecodedAnswer { records, min_ttl })
}

fn read_advance(buf: &[u8], cursor: usize, n: usize) -> Result<usize, WireError> {
    if cursor + n > buf.len() {
        return Err(WireError::Truncated);
    }
    Ok(cursor + n)
}

fn read_u16(buf: &[u8], cursor: usize) -> Result<u16, WireError> {
    if cursor + 2 > buf.len() {
        return Err(WireError::Truncated);
    }
    Ok(u16::from_be_bytes([buf[cursor], buf[cursor + 1]]))
}

fn read_u32(buf: &[u8], cursor: usize) -> Result<u32, WireError> {
    if cursor + 4 > buf.len() {
        return Err(WireError::Truncated);
    }
    Ok(u32::from_be_bytes([
        buf[cursor],
        buf[cursor + 1],
        buf[cursor + 2],
        buf[cursor + 3],
    ]))
}

/// Walk past a DNS name without materializing it. Defends against
/// compression-pointer loops via [`MAX_POINTER_HOPS`].
fn skip_name(buf: &[u8], start: usize) -> Result<usize, WireError> {
    let mut cursor = start;
    let mut hops = 0u32;
    let mut after_pointer = None;
    let mut total_len = 0usize;
    loop {
        if cursor >= buf.len() {
            return Err(WireError::Truncated);
        }
        let b = buf[cursor];
        if b == 0 {
            cursor += 1;
            return Ok(after_pointer.unwrap_or(cursor));
        }
        if b & 0xC0 == 0xC0 {
            // Compression pointer: 14-bit offset.
            if cursor + 2 > buf.len() {
                return Err(WireError::Truncated);
            }
            let offset = (((b & 0x3F) as usize) << 8) | (buf[cursor + 1] as usize);
            if after_pointer.is_none() {
                after_pointer = Some(cursor + 2);
            }
            cursor = offset;
            hops += 1;
            if hops > MAX_POINTER_HOPS {
                return Err(WireError::CompressionLoop);
            }
            continue;
        }
        if b & 0xC0 != 0 {
            // Reserved bits set on a label length octet.
            return Err(WireError::MalformedLabel);
        }
        let label_len = b as usize;
        if label_len > MAX_LABEL_LEN {
            return Err(WireError::MalformedLabel);
        }
        cursor += 1;
        if cursor + label_len > buf.len() {
            return Err(WireError::Truncated);
        }
        cursor += label_len;
        total_len += 1 + label_len;
        if total_len > MAX_NAME_LEN {
            return Err(WireError::MalformedName);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(rcode: u8, ancount: u16) -> Vec<u8> {
        let mut h = vec![0u8; 12];
        // Flags: QR=1, opcode=0, AA=0, TC=0, RD=1, RA=1, Z=0, RCODE
        let flags = 0x8180u16 | (rcode as u16);
        h[2..4].copy_from_slice(&flags.to_be_bytes());
        h[4..6].copy_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        h[6..8].copy_from_slice(&ancount.to_be_bytes());
        h
    }

    fn write_name(out: &mut Vec<u8>, qname: &str) {
        for label in qname.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
    }

    fn write_question(out: &mut Vec<u8>, qname: &str, qtype: u16) {
        write_name(out, qname);
        out.extend_from_slice(&qtype.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes()); // IN
    }

    fn write_answer_a(out: &mut Vec<u8>, qname: &str, ttl: u32, ip: [u8; 4]) {
        write_name(out, qname);
        out.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
        out.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
        out.extend_from_slice(&ttl.to_be_bytes());
        out.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
        out.extend_from_slice(&ip);
    }

    fn write_answer_aaaa(out: &mut Vec<u8>, qname: &str, ttl: u32, ip: [u8; 16]) {
        write_name(out, qname);
        out.extend_from_slice(&28u16.to_be_bytes()); // TYPE AAAA
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&ttl.to_be_bytes());
        out.extend_from_slice(&16u16.to_be_bytes());
        out.extend_from_slice(&ip);
    }

    #[test]
    fn encode_query_round_trips_question_section() {
        let q = encode_query("example.com", QueryType::A).expect("encode ok");
        // 12-byte header + name (1+7+1+3+1=13) + 4 bytes qtype/qclass = 29.
        assert_eq!(q.len(), 12 + 13 + 4);
        assert_eq!(&q[2..4], &[0x01, 0x00], "flags = standard query, RD=1");
        // QDCOUNT == 1
        assert_eq!(&q[4..6], &[0x00, 0x01]);
        // QTYPE at end = 1 (A); QCLASS = 1 (IN)
        assert_eq!(&q[q.len() - 4..], &[0x00, 0x01, 0x00, 0x01]);
    }

    #[test]
    fn encode_query_lowercases_qname() {
        let q = encode_query("Example.COM", QueryType::A).expect("encode ok");
        // Find the bytes of the first label after header (skip 12).
        // Header is 12 bytes; first byte at offset 12 is the label length.
        let label_len = q[12] as usize;
        let label = &q[13..13 + label_len];
        assert_eq!(label, b"example");
    }

    #[test]
    fn encode_query_aaaa_uses_type_28() {
        let q = encode_query("example.com", QueryType::Aaaa).expect("encode ok");
        // QTYPE is 4 bytes from end (qtype=2, qclass=2).
        assert_eq!(&q[q.len() - 4..q.len() - 2], &28u16.to_be_bytes());
    }

    #[test]
    fn encode_rejects_empty_qname() {
        let r = encode_query("", QueryType::A);
        assert_eq!(r.unwrap_err(), WireError::InvalidHostname);
    }

    #[test]
    fn encode_rejects_label_over_63() {
        let long_label = "a".repeat(64);
        let r = encode_query(&format!("{long_label}.com"), QueryType::A);
        assert_eq!(r.unwrap_err(), WireError::InvalidHostname);
    }

    #[test]
    fn encode_rejects_total_name_over_255() {
        // 5 labels of 60 chars + 4 dots + final dot = 304 bytes encoded.
        let label = "a".repeat(60);
        let qname = [label.as_str(); 5].join(".");
        let r = encode_query(&qname, QueryType::A);
        assert_eq!(r.unwrap_err(), WireError::InvalidHostname);
    }

    #[test]
    fn encode_rejects_disallowed_chars() {
        let r = encode_query("ex ample.com", QueryType::A);
        assert_eq!(r.unwrap_err(), WireError::InvalidHostname);
    }

    #[test]
    fn decode_simple_a_response() {
        let mut msg = header(0, 1);
        write_question(&mut msg, "example.com", 1);
        write_answer_a(&mut msg, "example.com", 300, [93, 184, 216, 34]);
        let answer = decode_response(&msg).expect("decode ok");
        assert_eq!(answer.records.len(), 1);
        assert_eq!(answer.min_ttl, 300);
        assert_eq!(
            answer.records[0],
            DnsRecord::A(Ipv4Addr::new(93, 184, 216, 34))
        );
    }

    #[test]
    fn decode_simple_aaaa_response() {
        let mut msg = header(0, 1);
        write_question(&mut msg, "example.com", 28);
        write_answer_aaaa(
            &mut msg,
            "example.com",
            120,
            [
                0x26, 0x06, 0x28, 0x00, 0x02, 0x20, 0, 0x01, 0x02, 0x48, 0x18, 0x93, 0x25, 0xc8,
                0x19, 0x46,
            ],
        );
        let answer = decode_response(&msg).expect("decode ok");
        assert_eq!(answer.records.len(), 1);
        assert_eq!(answer.min_ttl, 120);
    }

    #[test]
    fn decode_takes_min_ttl_across_multiple_records() {
        let mut msg = header(0, 2);
        write_question(&mut msg, "example.com", 1);
        write_answer_a(&mut msg, "example.com", 300, [1, 2, 3, 4]);
        write_answer_a(&mut msg, "example.com", 60, [5, 6, 7, 8]);
        let answer = decode_response(&msg).expect("decode ok");
        assert_eq!(answer.records.len(), 2);
        assert_eq!(answer.min_ttl, 60, "min TTL across records");
    }

    #[test]
    fn decode_rejects_oversized_message() {
        let big = vec![0u8; MAX_DNS_MESSAGE_BYTES + 1];
        assert_eq!(
            decode_response(&big).unwrap_err(),
            WireError::MessageTooLarge
        );
    }

    #[test]
    fn decode_rejects_truncated_header() {
        let short = vec![0u8; 8];
        assert_eq!(decode_response(&short).unwrap_err(), WireError::Truncated);
    }

    #[test]
    fn decode_rejects_bad_qdcount() {
        let mut msg = header(0, 0);
        msg[4..6].copy_from_slice(&2u16.to_be_bytes());
        assert_eq!(
            decode_response(&msg).unwrap_err(),
            WireError::UnexpectedQuestionCount
        );
    }

    #[test]
    fn decode_returns_nxdomain() {
        let mut msg = header(3, 0);
        write_question(&mut msg, "missing.example", 1);
        assert_eq!(decode_response(&msg).unwrap_err(), WireError::NxDomain);
    }

    #[test]
    fn decode_returns_servfail() {
        let mut msg = header(2, 0);
        write_question(&mut msg, "broken.example", 1);
        assert_eq!(decode_response(&msg).unwrap_err(), WireError::ServerFailure);
    }

    #[test]
    fn decode_returns_format_error() {
        let mut msg = header(1, 0);
        write_question(&mut msg, "broken.example", 1);
        assert_eq!(decode_response(&msg).unwrap_err(), WireError::FormatError);
    }

    #[test]
    fn decode_skips_unknown_rrtype() {
        let mut msg = header(0, 2);
        write_question(&mut msg, "example.com", 1);
        // First answer: unknown type 99 with empty RDATA.
        write_name(&mut msg, "example.com");
        msg.extend_from_slice(&99u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&60u32.to_be_bytes());
        msg.extend_from_slice(&0u16.to_be_bytes());
        // Second answer: A 1.2.3.4 with TTL 60.
        write_answer_a(&mut msg, "example.com", 60, [1, 2, 3, 4]);
        let answer = decode_response(&msg).expect("decode ok");
        assert_eq!(answer.records.len(), 1);
        assert_eq!(answer.min_ttl, 60);
    }

    #[test]
    fn decode_rejects_bad_rdata_len_for_a() {
        let mut msg = header(0, 1);
        write_question(&mut msg, "example.com", 1);
        // A record with RDLENGTH 5 (corrupt).
        write_name(&mut msg, "example.com");
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&60u32.to_be_bytes());
        msg.extend_from_slice(&5u16.to_be_bytes());
        msg.extend_from_slice(&[1, 2, 3, 4, 5]);
        assert_eq!(
            decode_response(&msg).unwrap_err(),
            WireError::RdataLengthMismatch
        );
    }

    #[test]
    fn decode_rejects_compression_pointer_loop() {
        // Header + question with name pointer to itself (offset 12).
        let mut msg = header(0, 0);
        // Place a self-pointing pointer at offset 12: 0xC0 0x0C points
        // back to offset 12 again. This is a one-cycle loop.
        msg.push(0xC0);
        msg.push(0x0C);
        // qtype + qclass:
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        let err = decode_response(&msg).unwrap_err();
        assert!(matches!(
            err,
            WireError::CompressionLoop | WireError::Truncated
        ));
    }

    #[test]
    fn wire_error_display_is_opaque() {
        // Tracking-resistance: error Display strings carry no qname.
        let e = WireError::NxDomain;
        let s = format!("{e}");
        assert_eq!(s, "dns wire: nxdomain");
        assert!(!s.contains("example"));
    }
}
