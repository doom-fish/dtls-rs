//! A deliberately small ASN.1 DER codec — only the subset needed to emit a
//! self-signed ECDSA-P256 certificate and to walk a peer certificate's
//! `SubjectPublicKeyInfo`.
//!
//! No general-purpose ASN.1 library is used (or wanted): the certificate shapes
//! involved are fixed, so a TLV builder plus a forward-only reader is enough.

use crate::error::{Error, Result};

// --- DER class/tag octets used by this crate ---------------------------------

/// `BOOLEAN`.
pub const TAG_BOOLEAN: u8 = 0x01;
/// `INTEGER`.
pub const TAG_INTEGER: u8 = 0x02;
/// `BIT STRING`.
pub const TAG_BIT_STRING: u8 = 0x03;
/// `OCTET STRING`.
pub const TAG_OCTET_STRING: u8 = 0x04;
/// `NULL`.
pub const TAG_NULL: u8 = 0x05;
/// `OBJECT IDENTIFIER`.
pub const TAG_OID: u8 = 0x06;
/// `UTF8String`.
pub const TAG_UTF8_STRING: u8 = 0x0c;
/// `PrintableString`.
pub const TAG_PRINTABLE_STRING: u8 = 0x13;
/// `UTCTime`.
pub const TAG_UTC_TIME: u8 = 0x17;
/// Constructed `SEQUENCE`.
pub const TAG_SEQUENCE: u8 = 0x30;
/// Constructed `SET`.
pub const TAG_SET: u8 = 0x31;

/// Build a context-specific constructed tag, e.g. `[0]` → `0xA0`.
#[must_use]
pub const fn context_constructed(number: u8) -> u8 {
    0xA0 | number
}

// --- Builder -----------------------------------------------------------------

/// Encode a DER length prefix (definite form).
#[must_use]
pub fn encode_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else {
        let mut bytes = len.to_be_bytes().to_vec();
        while bytes.len() > 1 && bytes[0] == 0 {
            bytes.remove(0);
        }
        let mut out = Vec::with_capacity(bytes.len() + 1);
        out.push(0x80 | (bytes.len() as u8));
        out.extend_from_slice(&bytes);
        out
    }
}

/// Emit a tag-length-value triple.
#[must_use]
pub fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(contents.len() + 4);
    out.push(tag);
    out.extend_from_slice(&encode_length(contents.len()));
    out.extend_from_slice(contents);
    out
}

/// Concatenate component encodings inside a `SEQUENCE`.
#[must_use]
pub fn sequence(parts: &[Vec<u8>]) -> Vec<u8> {
    let mut body = Vec::new();
    for part in parts {
        body.extend_from_slice(part);
    }
    tlv(TAG_SEQUENCE, &body)
}

/// Concatenate component encodings inside a `SET`.
#[must_use]
pub fn set(parts: &[Vec<u8>]) -> Vec<u8> {
    let mut body = Vec::new();
    for part in parts {
        body.extend_from_slice(part);
    }
    tlv(TAG_SET, &body)
}

/// Encode an `INTEGER` from a big-endian unsigned magnitude, inserting a
/// leading zero byte when the high bit would otherwise make it negative.
#[must_use]
pub fn integer_unsigned(magnitude: &[u8]) -> Vec<u8> {
    let mut start = 0;
    while start + 1 < magnitude.len() && magnitude[start] == 0 {
        start += 1;
    }
    let trimmed = &magnitude[start..];
    let mut body = Vec::with_capacity(trimmed.len() + 1);
    if trimmed.first().is_some_and(|b| b & 0x80 != 0) {
        body.push(0x00);
    }
    body.extend_from_slice(trimmed);
    tlv(TAG_INTEGER, &body)
}

/// Encode a small non-negative `INTEGER`.
#[must_use]
pub fn integer_u64(value: u64) -> Vec<u8> {
    integer_unsigned(&value.to_be_bytes())
}

/// Encode a `BIT STRING` with zero unused bits.
#[must_use]
pub fn bit_string(bytes: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(bytes.len() + 1);
    body.push(0x00); // unused-bits count
    body.extend_from_slice(bytes);
    tlv(TAG_BIT_STRING, &body)
}

/// Encode an `OBJECT IDENTIFIER` from its arc list.
///
/// # Panics
///
/// Panics if `arcs` has fewer than two arcs — every real OID has at least two.
#[must_use]
pub fn oid(arcs: &[u64]) -> Vec<u8> {
    assert!(arcs.len() >= 2, "an OID needs at least two arcs");
    let mut body = vec![(arcs[0] * 40 + arcs[1]) as u8];
    for &arc in &arcs[2..] {
        body.extend_from_slice(&base128(arc));
    }
    tlv(TAG_OID, &body)
}

fn base128(mut value: u64) -> Vec<u8> {
    let mut group = vec![(value & 0x7f) as u8];
    value >>= 7;
    while value > 0 {
        group.push(((value & 0x7f) as u8) | 0x80);
        value >>= 7;
    }
    group.reverse();
    group
}

/// Encode a `NULL`.
#[must_use]
pub fn null() -> Vec<u8> {
    tlv(TAG_NULL, &[])
}

/// Encode a `BOOLEAN`.
#[must_use]
pub fn boolean(value: bool) -> Vec<u8> {
    tlv(TAG_BOOLEAN, &[if value { 0xFF } else { 0x00 }])
}

/// Encode a `PrintableString`.
#[must_use]
pub fn printable_string(text: &str) -> Vec<u8> {
    tlv(TAG_PRINTABLE_STRING, text.as_bytes())
}

/// Encode a `UTCTime` from a pre-formatted `YYMMDDHHMMSSZ` string.
#[must_use]
pub fn utc_time(formatted: &str) -> Vec<u8> {
    tlv(TAG_UTC_TIME, formatted.as_bytes())
}

/// Wrap `contents` (already a complete DER element) in an explicit context tag.
#[must_use]
pub fn explicit(number: u8, contents: &[u8]) -> Vec<u8> {
    tlv(context_constructed(number), contents)
}

// --- Reader ------------------------------------------------------------------

/// One decoded TLV element: its tag and a borrow of its contents.
#[derive(Debug, Clone, Copy)]
pub struct Element<'a> {
    /// The identifier octet.
    pub tag: u8,
    /// The value contents (after the length).
    pub contents: &'a [u8],
}

impl<'a> Element<'a> {
    /// Treat the contents as a sequence of child elements.
    ///
    /// # Errors
    ///
    /// Returns an error if a child element is malformed.
    pub fn children(&self) -> Result<Vec<Element<'a>>> {
        let mut reader = DerReader::new(self.contents);
        let mut out = Vec::new();
        while !reader.is_empty() {
            out.push(reader.read()?);
        }
        Ok(out)
    }
}

/// A forward-only DER reader over a byte slice.
pub struct DerReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> DerReader<'a> {
    /// Wrap a slice.
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Whether all bytes have been consumed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    /// Read one TLV element.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Truncated`] or [`Error::Decode`] on malformed input.
    pub fn read(&mut self) -> Result<Element<'a>> {
        let tag = *self.data.get(self.pos).ok_or(Error::Truncated("DER tag"))?;
        self.pos += 1;
        let first = *self
            .data
            .get(self.pos)
            .ok_or(Error::Truncated("DER length"))?;
        self.pos += 1;
        let len = if first < 0x80 {
            first as usize
        } else {
            let count = (first & 0x7f) as usize;
            if count == 0 || count > 4 {
                return Err(Error::Decode("unsupported DER length form".to_owned()));
            }
            let mut value = 0usize;
            for _ in 0..count {
                let byte = *self
                    .data
                    .get(self.pos)
                    .ok_or(Error::Truncated("DER long length"))?;
                self.pos += 1;
                value = (value << 8) | byte as usize;
            }
            value
        };
        let end = self
            .pos
            .checked_add(len)
            .ok_or(Error::Decode("DER length overflow".to_owned()))?;
        let contents = self
            .data
            .get(self.pos..end)
            .ok_or(Error::Truncated("DER contents"))?;
        self.pos = end;
        Ok(Element { tag, contents })
    }
}
