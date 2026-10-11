//! Server name of a QUIC (HTTP/3) connection, read from the client's Initial packets.
//!
//! Initial packets are encrypted, but with keys derived from the destination connection ID the
//! client puts in clear (RFC 9001 §5.2), precisely so that middleboxes can read them. Nothing
//! secret is involved: this is the QUIC equivalent of reading the SNI of a TLS ClientHello.

use crate::sni::{self, Peek};
use aes::cipher::{Array, BlockCipherEncrypt, KeyInit};
use aes::Aes128;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::Aes128Gcm;
use hkdf::Hkdf;
use sha2::Sha256;
use std::collections::BTreeMap;

const VERSION_1: u32 = 1;
const INITIAL_SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
];
/// A ClientHello larger than this is not plausible; give up instead of buffering more.
const MAX_CRYPTO: usize = 64 * 1024;

#[derive(Debug, PartialEq)]
pub enum QuicPeek {
    /// The ClientHello continues in later Initial packets.
    NeedMore,
    Name(String),
    /// Not a QUIC v1 Initial, undecryptable, or a ClientHello without a name.
    Unknown,
}

fn varint(data: &[u8], at: &mut usize) -> Option<u64> {
    let first = *data.get(*at)?;
    let length = 1usize << (first >> 6);
    let bytes = data.get(*at..*at + length)?;
    let mut value = (first & 0x3F) as u64;
    for &b in &bytes[1..] {
        value = (value << 8) | b as u64;
    }
    *at += length;
    Some(value)
}

/// HKDF-Expand-Label from TLS 1.3 with an empty context.
fn expand_label(secret: &[u8], label: &str, length: usize) -> Option<Vec<u8>> {
    let full = format!("tls13 {label}");
    let mut info = Vec::with_capacity(4 + full.len());
    info.extend_from_slice(&(length as u16).to_be_bytes());
    info.push(full.len() as u8);
    info.extend_from_slice(full.as_bytes());
    info.push(0);
    let mut out = vec![0u8; length];
    Hkdf::<Sha256>::from_prk(secret).ok()?.expand(&info, &mut out).ok()?;
    Some(out)
}

struct InitialKeys {
    key: Vec<u8>,
    iv: Vec<u8>,
    hp: Vec<u8>,
}

impl InitialKeys {
    fn client(dcid: &[u8]) -> Option<Self> {
        let (initial_secret, _) = Hkdf::<Sha256>::extract(Some(&INITIAL_SALT_V1), dcid);
        let client_secret = expand_label(&initial_secret, "client in", 32)?;
        Some(InitialKeys {
            key: expand_label(&client_secret, "quic key", 16)?,
            iv: expand_label(&client_secret, "quic iv", 12)?,
            hp: expand_label(&client_secret, "quic hp", 16)?,
        })
    }
}

/// Decrypted payload of the first packet of `datagram` if it is a client Initial (QUIC v1), and
/// the destination connection ID it was protected with.
fn open_initial(datagram: &[u8], expected_dcid: Option<&[u8]>) -> Option<(Vec<u8>, Vec<u8>)> {
    let first = *datagram.first()?;
    // Long header, fixed bit, packet type 0 (Initial).
    if first & 0xC0 != 0xC0 || (first >> 4) & 0x03 != 0 {
        return None;
    }
    if u32::from_be_bytes(datagram.get(1..5)?.try_into().ok()?) != VERSION_1 {
        return None;
    }
    let mut at = 5;
    let dcid_length = *datagram.get(at)? as usize;
    if dcid_length > 20 {
        return None;
    }
    let dcid = datagram.get(at + 1..at + 1 + dcid_length)?.to_vec();
    if expected_dcid.is_some_and(|expected| expected != dcid.as_slice()) {
        return None;
    }
    at += 1 + dcid_length;
    at += 1 + *datagram.get(at)? as usize; // source connection ID
    let token_length = varint(datagram, &mut at)? as usize;
    at += token_length;
    let length = varint(datagram, &mut at)? as usize;
    let pn_offset = at;
    let packet = datagram.get(..pn_offset + length)?;

    let keys = InitialKeys::client(&dcid)?;
    // Header protection: the mask comes from a sample 4 bytes after the packet number start.
    let sample: [u8; 16] = packet.get(pn_offset + 4..pn_offset + 20)?.try_into().ok()?;
    let mut mask = Array::from(sample);
    Aes128::new_from_slice(&keys.hp).ok()?.encrypt_block(&mut mask);
    let mut header = packet[..pn_offset].to_vec();
    header[0] ^= mask[0] & 0x0F;
    let pn_length = (header[0] & 0x03) as usize + 1;
    let mut packet_number = 0u64;
    for i in 0..pn_length {
        let byte = packet[pn_offset + i] ^ mask[1 + i];
        header.push(byte);
        packet_number = (packet_number << 8) | byte as u64;
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&keys.iv);
    for (n, p) in nonce[4..].iter_mut().zip(packet_number.to_be_bytes()) {
        *n ^= p;
    }
    let cipher = Aes128Gcm::new_from_slice(&keys.key).ok()?;
    let plaintext = cipher
        .decrypt(&Array::from(nonce), Payload { msg: &packet[pn_offset + pn_length..], aad: &header })
        .ok()?;
    Some((plaintext, dcid))
}

/// CRYPTO frames of a decrypted Initial payload, as (offset, data).
fn crypto_frames(payload: &[u8]) -> Option<Vec<(u64, Vec<u8>)>> {
    let mut frames = Vec::new();
    let mut at = 0;
    while at < payload.len() {
        match varint(payload, &mut at)? {
            0x00 | 0x01 => {} // PADDING, PING
            kind @ (0x02 | 0x03) => {
                // ACK: largest, delay, range count, first range, then (gap, length) pairs.
                varint(payload, &mut at)?;
                varint(payload, &mut at)?;
                let ranges = varint(payload, &mut at)?;
                varint(payload, &mut at)?;
                for _ in 0..ranges * 2 {
                    varint(payload, &mut at)?;
                }
                if kind == 0x03 {
                    for _ in 0..3 {
                        varint(payload, &mut at)?;
                    }
                }
            }
            0x06 => {
                let offset = varint(payload, &mut at)?;
                let length = varint(payload, &mut at)? as usize;
                frames.push((offset, payload.get(at..at + length)?.to_vec()));
                at += length;
            }
            // CONNECTION_CLOSE or anything not allowed in Initial packets.
            _ => break,
        }
    }
    Some(frames)
}

/// Gathers the client's Initial packets of one QUIC connection until the ClientHello is whole.
#[derive(Default)]
pub struct InitialReader {
    dcid: Option<Vec<u8>>,
    fragments: BTreeMap<u64, Vec<u8>>,
    buffered: usize,
}

impl InitialReader {
    pub fn feed(&mut self, datagram: &[u8]) -> QuicPeek {
        let Some((payload, dcid)) = open_initial(datagram, self.dcid.as_deref()) else {
            // Later packets of a connection whose first one was understood are just not Initials.
            return if self.dcid.is_some() { QuicPeek::NeedMore } else { QuicPeek::Unknown };
        };
        self.dcid = Some(dcid);
        let Some(frames) = crypto_frames(&payload) else { return QuicPeek::Unknown };
        for (offset, data) in frames {
            self.buffered += data.len();
            self.fragments.insert(offset, data);
        }
        if self.buffered > MAX_CRYPTO {
            return QuicPeek::Unknown;
        }
        // Contiguous handshake bytes from offset 0.
        let mut handshake = Vec::new();
        for (&offset, data) in &self.fragments {
            let offset = offset as usize;
            if offset > handshake.len() {
                break;
            }
            let end = offset + data.len();
            if end > handshake.len() {
                handshake.extend_from_slice(&data[handshake.len() - offset..]);
            }
        }
        match sni::client_hello_name(&handshake) {
            Peek::Name(name) => QuicPeek::Name(name),
            Peek::NeedMore => QuicPeek::NeedMore,
            Peek::NoName => QuicPeek::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rfc_packet() -> Vec<u8> {
        let hex: String = include_str!("testdata/rfc9001_client_initial.hex").split_whitespace().collect();
        (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn derives_the_rfc9001_initial_keys() {
        let keys = InitialKeys::client(&[0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08]).unwrap();
        assert_eq!(hex(&keys.key), "1f369613dd76d5467730efcbe3b1a22d");
        assert_eq!(hex(&keys.iv), "fa044b2f42a3fd3b46fb255c");
        assert_eq!(hex(&keys.hp), "9f50449e04a0e810283a1e9933adedd2");
    }

    #[test]
    fn reads_the_server_name_of_the_rfc9001_client_initial() {
        let mut reader = InitialReader::default();
        assert_eq!(reader.feed(&rfc_packet()), QuicPeek::Name("example.com".into()));
    }

    #[test]
    fn rejects_tampered_and_foreign_packets() {
        let mut tampered = rfc_packet();
        tampered[600] ^= 1;
        assert_eq!(InitialReader::default().feed(&tampered), QuicPeek::Unknown);
        let mut version_2 = rfc_packet();
        version_2[1..5].copy_from_slice(&0x6b33_43cfu32.to_be_bytes());
        assert_eq!(InitialReader::default().feed(&version_2), QuicPeek::Unknown);
        assert_eq!(InitialReader::default().feed(b"not quic at all"), QuicPeek::Unknown);
        assert_eq!(InitialReader::default().feed(&[]), QuicPeek::Unknown);
    }

    /// Client Initial (QUIC v1) carrying one CRYPTO frame, protected as a real client would.
    fn seal_initial(dcid: &[u8], packet_number: u32, offset: u64, data: &[u8]) -> Vec<u8> {
        let keys = InitialKeys::client(dcid).unwrap();
        let mut frames = vec![0x06];
        frames.extend_from_slice(&(0x8000_0000u32 | offset as u32).to_be_bytes()); // 4-byte varint
        frames.extend_from_slice(&(0x4000u16 | data.len() as u16).to_be_bytes()); // 2-byte varint
        frames.extend_from_slice(data);
        frames.resize(frames.len().max(1100), 0); // PADDING, as clients pad Initials to 1200
        let length = 4 + frames.len() + 16;
        let mut header = vec![0xC3];
        header.extend_from_slice(&VERSION_1.to_be_bytes());
        header.push(dcid.len() as u8);
        header.extend_from_slice(dcid);
        header.extend_from_slice(&[0, 0]); // no source connection ID, no token
        header.extend_from_slice(&(0x4000u16 | length as u16).to_be_bytes());
        let pn_offset = header.len();
        header.extend_from_slice(&packet_number.to_be_bytes());
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&keys.iv);
        for (n, p) in nonce[8..].iter_mut().zip(packet_number.to_be_bytes()) {
            *n ^= p;
        }
        let sealed = Aes128Gcm::new_from_slice(&keys.key)
            .unwrap()
            .encrypt(&Array::from(nonce), Payload { msg: &frames, aad: &header })
            .unwrap();
        let mut packet = header;
        packet.extend_from_slice(&sealed);
        let sample: [u8; 16] = packet[pn_offset + 4..pn_offset + 20].try_into().unwrap();
        let mut mask = Array::from(sample);
        Aes128::new_from_slice(&keys.hp).unwrap().encrypt_block(&mut mask);
        packet[0] ^= mask[0] & 0x0F;
        for i in 0..4 {
            packet[pn_offset + i] ^= mask[1 + i];
        }
        packet
    }

    #[test]
    fn reassembles_a_client_hello_split_over_two_initials_in_any_order() {
        // ~1.8 KB ClientHello, as with post-quantum key shares: does not fit in one packet.
        let hello = crate::sni::build_client_hello("video.example.org", 1600, 1 << 14);
        let handshake = &hello[5..]; // QUIC carries handshake bytes without the TLS record layer
        let dcid = [7u8; 8];
        let (a, b) = handshake.split_at(1000);
        let first = seal_initial(&dcid, 0, 0, a);
        let second = seal_initial(&dcid, 1, 1000, b);

        let mut in_order = InitialReader::default();
        assert_eq!(in_order.feed(&first), QuicPeek::NeedMore);
        assert_eq!(in_order.feed(&second), QuicPeek::Name("video.example.org".into()));

        let mut reversed = InitialReader::default();
        assert_eq!(reversed.feed(&second), QuicPeek::NeedMore);
        assert_eq!(reversed.feed(b"short header packet"), QuicPeek::NeedMore);
        assert_eq!(reversed.feed(&first), QuicPeek::Name("video.example.org".into()));

        // A packet for another connection ID cannot be mixed in.
        let mut mixed = InitialReader::default();
        assert_eq!(mixed.feed(&first), QuicPeek::NeedMore);
        assert_eq!(mixed.feed(&seal_initial(&[9u8; 8], 1, 1000, b)), QuicPeek::NeedMore);
    }
}
