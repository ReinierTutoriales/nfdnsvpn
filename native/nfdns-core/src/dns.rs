//! Minimal DNS message handling: read the question of a query and answer blocked names locally.

pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;
const TYPE_CNAME: u16 = 5;
/// Service binding records. They carry the ECH keys that hide the server name of a TLS or QUIC
/// connection, which is what the SNI filter reads.
pub const TYPE_SVCB: u16 = 64;
pub const TYPE_HTTPS: u16 = 65;
const RCODE_NXDOMAIN: u16 = 3;
const CLASS_IN: u16 = 1;
const HEADER_LEN: usize = 12;
/// Short so that a list or allowlist change reaches apps within a minute.
const BLOCKED_TTL: u32 = 60;

pub struct Question {
    /// Lowercase, dotted, without the trailing dot.
    pub name: String,
    pub qtype: u16,
    qclass: u16,
    /// Offset just past the question section.
    end: usize,
}

fn read_u16(data: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*data.get(at)?, *data.get(at + 1)?]))
}

/// The single question of a standard query, or `None` for anything else (responses, other
/// opcodes, several questions, compressed or malformed names). Those are forwarded untouched.
pub fn parse_query(message: &[u8]) -> Option<Question> {
    if message.len() < HEADER_LEN {
        return None;
    }
    let flags = read_u16(message, 2)?;
    let is_response = flags & 0x8000 != 0;
    let opcode = (flags >> 11) & 0xF;
    if is_response || opcode != 0 || read_u16(message, 4)? != 1 {
        return None;
    }
    let mut at = HEADER_LEN;
    let mut name = String::new();
    loop {
        let len = *message.get(at)? as usize;
        at += 1;
        if len == 0 {
            break;
        }
        if len > 63 {
            return None;
        }
        let label = message.get(at..at + len)?;
        if !name.is_empty() {
            name.push('.');
        }
        for &b in label {
            if !(b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
                return None;
            }
            name.push(b.to_ascii_lowercase() as char);
        }
        at += len;
        if name.len() > 253 {
            return None;
        }
    }
    let qtype = read_u16(message, at)?;
    let qclass = read_u16(message, at + 2)?;
    Some(Question { name, qtype, qclass, end: at + 4 })
}

/// Name at `at` (compression pointers allowed), lowercase and dotted, plus the offset after it.
fn read_name(message: &[u8], mut at: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    let mut end = None;
    // Each pointer must go backwards, so a loop cannot be longer than the message.
    let mut jumps = 0;
    loop {
        let length = *message.get(at)? as usize;
        match length {
            0 => {
                return Some((name, end.unwrap_or(at + 1)));
            }
            0xC0..=0xFF => {
                let target = ((length & 0x3F) << 8) | *message.get(at + 1)? as usize;
                jumps += 1;
                if target >= at || jumps > 32 {
                    return None;
                }
                end.get_or_insert(at + 2);
                at = target;
            }
            1..=63 => {
                let label = message.get(at + 1..at + 1 + length)?;
                if !name.is_empty() {
                    name.push('.');
                }
                name.extend(label.iter().map(|b| b.to_ascii_lowercase() as char));
                if name.len() > 253 {
                    return None;
                }
                at += 1 + length;
            }
            _ => return None,
        }
    }
}

/// Records of the answer section as (type, offset of rdata, rdata length), or none at all if
/// the header or the question section cannot be read.
fn answer_records(message: &[u8]) -> Vec<(u16, usize, usize)> {
    let mut records = Vec::new();
    let (Some(questions), Some(answers)) = (read_u16(message, 4), read_u16(message, 6)) else { return records };
    let mut at = HEADER_LEN;
    for _ in 0..questions {
        let Some((_, next)) = read_name(message, at) else { return records };
        at = next + 4;
    }
    for _ in 0..answers {
        let Some((_, next)) = read_name(message, at) else { break };
        let (Some(kind), Some(length)) = (read_u16(message, next), read_u16(message, next + 8)) else { break };
        let rdata = next + 10;
        if rdata + length as usize > message.len() {
            break;
        }
        records.push((kind, rdata, length as usize));
        at = rdata + length as usize;
    }
    records
}

/// Targets of the CNAME records in the answer section. Trackers hide behind a first-party name
/// (`metrics.shop.example CNAME shop.tracker.example`); checking the chain uncloaks them.
pub fn cname_targets(message: &[u8]) -> Vec<String> {
    answer_records(message)
        .into_iter()
        .filter(|&(kind, _, _)| kind == TYPE_CNAME)
        .filter_map(|(_, rdata, _)| read_name(message, rdata).map(|(target, _)| target))
        .collect()
}

/// Addresses of the A and AAAA records in the answer section, with their TTL in seconds.
pub fn answer_addresses(message: &[u8]) -> Vec<(std::net::IpAddr, u32)> {
    answer_records(message)
        .into_iter()
        .filter_map(|(kind, rdata, length)| {
            let ttl = u32::from_be_bytes(message.get(rdata - 6..rdata - 2)?.try_into().ok()?);
            let bytes = message.get(rdata..rdata + length)?;
            let ip = match (kind, length) {
                (TYPE_A, 4) => std::net::IpAddr::from(<[u8; 4]>::try_from(bytes).ok()?),
                (TYPE_AAAA, 16) => std::net::IpAddr::from(<[u8; 16]>::try_from(bytes).ok()?),
                _ => return None,
            };
            Some((ip, ttl))
        })
        .collect()
}

/// Answer for a blocked name: `0.0.0.0` for A, `::` for AAAA and an empty NOERROR answer for
/// every other type (HTTPS/SVCB included, so no record hints at the real servers).
pub fn blocked_response(query: &[u8], question: &Question) -> Vec<u8> {
    response(query, question, 0)
}

/// "No such domain": the answer that tells Firefox not to turn on its own DNS over HTTPS.
pub fn nxdomain_response(query: &[u8], question: &Question) -> Vec<u8> {
    response(query, question, RCODE_NXDOMAIN)
}

fn response(query: &[u8], question: &Question, rcode: u16) -> Vec<u8> {
    let rdata: &[u8] = match (rcode, question.qclass, question.qtype) {
        (0, CLASS_IN, TYPE_A) => &[0; 4],
        (0, CLASS_IN, TYPE_AAAA) => &[0; 16],
        _ => &[],
    };
    let answers: u16 = if rdata.is_empty() { 0 } else { 1 };
    let mut out = Vec::with_capacity(question.end + 16 + rdata.len());
    out.extend_from_slice(&query[0..2]); // ID
    let request_flags = read_u16(query, 2).unwrap_or(0);
    // QR=1, same opcode and RD, RA=1, and the given RCODE.
    let flags = 0x8000 | (request_flags & 0x7900) | 0x0080 | rcode;
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&answers.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&[0, 0, 0, 0]); // NSCOUNT, ARCOUNT (EDNS is dropped)
    out.extend_from_slice(&query[HEADER_LEN..question.end]);
    if answers == 1 {
        out.extend_from_slice(&[0xC0, HEADER_LEN as u8]); // pointer to the question name
        out.extend_from_slice(&question.qtype.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out.extend_from_slice(&BLOCKED_TTL.to_be_bytes());
        out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(rdata);
    }
    out
}

#[cfg(test)]
pub(crate) fn build_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut q = Vec::new();
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    q.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&CLASS_IN.to_be_bytes());
    q
}

#[cfg(test)]
pub(crate) fn build_cname_answer(query: &[u8], targets: &[&str]) -> Vec<u8> {
    let question = parse_query(query).unwrap();
    let mut r = query[..question.end].to_vec();
    r[2] |= 0x80;
    r[6..8].copy_from_slice(&((targets.len() + 1) as u16).to_be_bytes());
    let mut owner: u16 = 0xC000 | HEADER_LEN as u16; // pointer to the question name
    for target in targets {
        r.extend_from_slice(&owner.to_be_bytes());
        r.extend_from_slice(&TYPE_CNAME.to_be_bytes());
        r.extend_from_slice(&CLASS_IN.to_be_bytes());
        r.extend_from_slice(&300u32.to_be_bytes());
        let mut name = Vec::new();
        for label in target.split('.') {
            name.push(label.len() as u8);
            name.extend_from_slice(label.as_bytes());
        }
        name.push(0);
        r.extend_from_slice(&(name.len() as u16).to_be_bytes());
        owner = 0xC000 | (r.len() as u16); // the next record is owned by this target
        r.extend_from_slice(&name);
    }
    r.extend_from_slice(&owner.to_be_bytes());
    r.extend_from_slice(&TYPE_A.to_be_bytes());
    r.extend_from_slice(&CLASS_IN.to_be_bytes());
    r.extend_from_slice(&300u32.to_be_bytes());
    r.extend_from_slice(&[0, 4, 192, 0, 2, 1]);
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_cname_chain_with_compression() {
        let query = build_query(5, "metrics.shop.example", TYPE_A);
        let answer = build_cname_answer(&query, &["shop.tracker.example", "edge.cdn.example"]);
        assert_eq!(cname_targets(&answer), vec!["shop.tracker.example", "edge.cdn.example"]);
        assert!(cname_targets(&answer[..20]).is_empty());
        assert!(cname_targets(&query).is_empty());
    }

    #[test]
    fn reads_answer_addresses_after_a_cname_chain() {
        let query = build_query(5, "metrics.shop.example", TYPE_A);
        let answer = build_cname_answer(&query, &["edge.cdn.example"]);
        assert_eq!(answer_addresses(&answer), vec![("192.0.2.1".parse().unwrap(), 300)]);
        assert!(answer_addresses(&answer[..answer.len() - 1]).is_empty(), "truncated rdata");
        assert!(answer_addresses(&query).is_empty());
    }

    #[test]
    fn rejects_forward_and_looping_pointers() {
        let mut message = vec![0u8; 12];
        message.extend_from_slice(&[0xC0, 14, 0]);
        assert!(read_name(&message, 12).is_none());
        let mut looping = vec![0u8; 12];
        looping.extend_from_slice(&[0xC0, 12]);
        assert!(read_name(&looping, 12).is_none());
    }

    #[test]
    fn parses_question() {
        let q = parse_query(&build_query(7, "Ads.Example.com", TYPE_A)).unwrap();
        assert_eq!(q.name, "ads.example.com");
        assert_eq!(q.qtype, TYPE_A);
    }

    #[test]
    fn rejects_responses_and_garbage() {
        let mut response = build_query(7, "example.com", TYPE_A);
        response[2] |= 0x80;
        assert!(parse_query(&response).is_none());
        assert!(parse_query(&[0; 5]).is_none());
        let mut truncated = build_query(7, "example.com", TYPE_A);
        truncated.truncate(truncated.len() - 3);
        assert!(parse_query(&truncated).is_none());
        let mut pointer = build_query(7, "example.com", TYPE_A);
        pointer[12] = 0xC0;
        assert!(parse_query(&pointer).is_none());
    }

    #[test]
    fn blocked_a_answers_zero_address() {
        let query = build_query(0xBEEF, "ads.example.com", TYPE_A);
        let q = parse_query(&query).unwrap();
        let r = blocked_response(&query, &q);
        assert_eq!(&r[0..2], &[0xBE, 0xEF]);
        assert_eq!(read_u16(&r, 2).unwrap() & 0x8000, 0x8000);
        assert_eq!(read_u16(&r, 2).unwrap() & 0x0100, 0x0100); // RD echoed
        assert_eq!(read_u16(&r, 2).unwrap() & 0x000F, 0); // NOERROR
        assert_eq!(read_u16(&r, 6), Some(1));
        assert_eq!(&r[r.len() - 6..], &[0, 4, 0, 0, 0, 0]);
    }

    #[test]
    fn blocked_aaaa_answers_unspecified_address() {
        let query = build_query(1, "ads.example.com", TYPE_AAAA);
        let r = blocked_response(&query, &parse_query(&query).unwrap());
        assert_eq!(read_u16(&r, 6), Some(1));
        assert_eq!(&r[r.len() - 18..r.len() - 16], &[0, 16]);
        assert!(r[r.len() - 16..].iter().all(|&b| b == 0));
    }

    #[test]
    fn blocked_other_types_get_empty_answer() {
        let query = build_query(1, "ads.example.com", 65);
        let r = blocked_response(&query, &parse_query(&query).unwrap());
        assert_eq!(read_u16(&r, 6), Some(0));
        assert_eq!(r.len(), query.len());
    }
}
