//! Server name of a TCP connection, read from the first bytes the app sends, without decrypting
//! anything: the SNI extension of a TLS ClientHello, or the Host header of a plain HTTP request.
//! With Encrypted Client Hello this is the outer (public) name.

use crate::filter::normalize_domain;

/// Largest first flight inspected: one full TLS record (16 KiB) plus its header. Post-quantum key
/// shares make ClientHellos span two TCP segments, so a single read is not enough.
pub const MAX_PEEK: usize = 16 * 1024 + 5;
const MAX_HTTP_HEADER: usize = 8 * 1024;

#[derive(Debug, PartialEq)]
pub enum Peek {
    /// Not enough bytes yet to decide.
    NeedMore,
    /// Normalized server name.
    Name(String),
    /// Some other protocol, or a request without a usable name.
    NoName,
}

const HTTP_METHODS: [&[u8]; 9] = [b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"TRACE ", b"CONNECT "];

pub fn server_name(data: &[u8]) -> Peek {
    match data.first() {
        None => Peek::NeedMore,
        Some(0x16) => tls_server_name(data),
        Some(_) => http_host(data),
    }
}

fn u16_at(data: &[u8], at: usize) -> Option<usize> {
    Some(u16::from_be_bytes([*data.get(at)?, *data.get(at + 1)?]) as usize)
}

fn tls_server_name(data: &[u8]) -> Peek {
    // Handshake bytes, gathered from consecutive handshake records.
    let mut handshake = Vec::new();
    let mut at = 0;
    while let Some(header) = data.get(at..at + 5) {
        if header[0] != 0x16 {
            break;
        }
        let length = u16::from_be_bytes([header[3], header[4]]) as usize;
        match data.get(at + 5..at + 5 + length) {
            Some(fragment) => handshake.extend_from_slice(fragment),
            None => {
                handshake.extend_from_slice(&data[(at + 5).min(data.len())..]);
                break;
            }
        }
        at += 5 + length;
        if handshake.len() >= 4 && handshake.len() >= 4 + client_hello_length(&handshake) {
            break;
        }
    }
    match client_hello_name(&handshake) {
        Peek::NeedMore if data.len() >= MAX_PEEK => Peek::NoName,
        peek => peek,
    }
}

/// Server name in raw TLS handshake bytes (no record layer), as carried by TLS records or by
/// QUIC CRYPTO frames.
pub fn client_hello_name(handshake: &[u8]) -> Peek {
    if handshake.len() < 4 {
        return Peek::NeedMore;
    }
    if handshake[0] != 1 {
        return Peek::NoName; // not a ClientHello
    }
    let Some(hello) = handshake.get(4..4 + client_hello_length(handshake)) else { return Peek::NeedMore };
    parse_client_hello(hello).map_or(Peek::NoName, Peek::Name)
}

fn client_hello_length(handshake: &[u8]) -> usize {
    ((handshake[1] as usize) << 16) | ((handshake[2] as usize) << 8) | handshake[3] as usize
}

fn parse_client_hello(hello: &[u8]) -> Option<String> {
    let mut at = 2 + 32; // legacy version, random
    at += 1 + *hello.get(at)? as usize; // session id
    at += 2 + u16_at(hello, at)?; // cipher suites
    at += 1 + *hello.get(at)? as usize; // compression methods
    let extensions_end = at + 2 + u16_at(hello, at)?;
    at += 2;
    while at + 4 <= extensions_end.min(hello.len()) {
        let kind = u16_at(hello, at)?;
        let length = u16_at(hello, at + 2)?;
        let body = hello.get(at + 4..at + 4 + length)?;
        if kind == 0 {
            // server_name: list length, then entries of (type, length, name); type 0 is a hostname.
            let mut entry = 2;
            while entry + 3 <= body.len() {
                let name_length = u16_at(body, entry + 1)?;
                let name = body.get(entry + 3..entry + 3 + name_length)?;
                if body[entry] == 0 {
                    return normalize_domain(std::str::from_utf8(name).ok()?);
                }
                entry += 3 + name_length;
            }
            return None;
        }
        at += 4 + length;
    }
    None
}

fn http_host(data: &[u8]) -> Peek {
    let prefix = &data[..data.len().min(8)];
    let is_method = HTTP_METHODS.iter().any(|m| m.starts_with(prefix) || prefix.starts_with(m));
    if !is_method {
        return Peek::NoName;
    }
    let Some(end) = data.windows(4).position(|w| w == b"\r\n\r\n") else {
        return if data.len() >= MAX_HTTP_HEADER { Peek::NoName } else { Peek::NeedMore };
    };
    let Ok(head) = std::str::from_utf8(&data[..end]) else { return Peek::NoName };
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let host = if let Some(target) = request_line.strip_prefix("CONNECT ") {
        target.split(' ').next().map(str::to_string)
    } else {
        lines.find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim().eq_ignore_ascii_case("host").then(|| value.trim().to_string())
        })
    };
    let Some(host) = host else { return Peek::NoName };
    // Strip a port, unless it is a bracketed IPv6 literal (rejected by normalize_domain anyway).
    let host = match host.rsplit_once(':') {
        Some((name, port)) if !name.contains(':') && port.bytes().all(|b| b.is_ascii_digit()) => name.to_string(),
        _ => host,
    };
    normalize_domain(&host).map_or(Peek::NoName, Peek::Name)
}

/// ClientHello with an SNI extension, split into TLS records of `record_size` bytes.
#[cfg(test)]
pub(crate) fn build_client_hello(name: &str, padding: usize, record_size: usize) -> Vec<u8> {
    let mut sni = Vec::new();
    sni.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
    sni.push(0);
    sni.extend_from_slice(&(name.len() as u16).to_be_bytes());
    sni.extend_from_slice(name.as_bytes());
    let mut extensions = Vec::new();
    // A large unrelated extension first (like a post-quantum key share), then server_name.
    extensions.extend_from_slice(&0x0033u16.to_be_bytes());
    extensions.extend_from_slice(&(padding as u16).to_be_bytes());
    extensions.extend(std::iter::repeat_n(0xAB, padding));
    extensions.extend_from_slice(&0u16.to_be_bytes());
    extensions.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&sni);
    let mut hello = vec![3, 3];
    hello.extend_from_slice(&[7; 32]);
    hello.push(32);
    hello.extend_from_slice(&[9; 32]);
    hello.extend_from_slice(&[0, 4, 0x13, 0x01, 0x13, 0x02]);
    hello.extend_from_slice(&[1, 0]);
    hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    hello.extend_from_slice(&extensions);
    let mut handshake = vec![1];
    handshake.extend_from_slice(&(hello.len() as u32).to_be_bytes()[1..]);
    handshake.extend_from_slice(&hello);
    let mut out = Vec::new();
    for chunk in handshake.chunks(record_size) {
        out.extend_from_slice(&[0x16, 3, 1]);
        out.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
        out.extend_from_slice(chunk);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_sni_from_a_client_hello() {
        let hello = build_client_hello("Ads.DoubleClick.net", 40, 16384);
        assert_eq!(server_name(&hello), Peek::Name("ads.doubleclick.net".into()));
    }

    #[test]
    fn waits_for_a_client_hello_split_across_segments_and_records() {
        // ~1.8 KB like a post-quantum ClientHello, in two records, delivered in two TCP segments.
        let hello = build_client_hello("tracker.example.org", 1600, 1000);
        assert_eq!(server_name(&hello[..1200]), Peek::NeedMore);
        assert_eq!(server_name(&hello[..3]), Peek::NeedMore);
        assert_eq!(server_name(&hello), Peek::Name("tracker.example.org".into()));
    }

    #[test]
    fn reads_http_host() {
        assert_eq!(
            server_name(b"GET /ad HTTP/1.1\r\nUser-Agent: x\r\nhost: Ads.Example.com:8080\r\n\r\n"),
            Peek::Name("ads.example.com".into())
        );
        assert_eq!(server_name(b"CONNECT tracker.example.org:443 HTTP/1.1\r\n\r\n"), Peek::Name("tracker.example.org".into()));
        assert_eq!(server_name(b"GET / HTTP/1.1\r\nHost: ads.exa"), Peek::NeedMore);
        assert_eq!(server_name(b"GE"), Peek::NeedMore);
        assert_eq!(server_name(b"GET / HTTP/1.0\r\n\r\n"), Peek::NoName);
        assert_eq!(server_name(b"GET / HTTP/1.1\r\nHost: 192.0.2.1\r\n\r\n"), Peek::NoName);
    }

    #[test]
    fn other_protocols_have_no_name() {
        assert_eq!(server_name(b"SSH-2.0-OpenSSH_9.6\r\n"), Peek::NoName);
        assert_eq!(server_name(&[0x16, 3, 1, 0, 4, 2, 0, 0, 0]), Peek::NoName); // ServerHello
        assert_eq!(server_name(&[]), Peek::NeedMore);
        let mut garbage = vec![0x16, 3, 1, 0x40, 0];
        garbage.extend(std::iter::repeat_n(0, MAX_PEEK));
        assert_eq!(server_name(&garbage), Peek::NoName);
    }
}
