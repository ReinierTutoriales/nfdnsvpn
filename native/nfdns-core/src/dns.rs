//! Minimal DNS message handling: read the question of a query and answer blocked names locally.

pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;
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

/// Answer for a blocked name: `0.0.0.0` for A, `::` for AAAA and an empty NOERROR answer for
/// every other type (HTTPS/SVCB included, so no record hints at the real servers).
pub fn blocked_response(query: &[u8], question: &Question) -> Vec<u8> {
    let rdata: &[u8] = match (question.qclass, question.qtype) {
        (CLASS_IN, TYPE_A) => &[0; 4],
        (CLASS_IN, TYPE_AAAA) => &[0; 16],
        _ => &[],
    };
    let answers: u16 = if rdata.is_empty() { 0 } else { 1 };
    let mut out = Vec::with_capacity(question.end + 16 + rdata.len());
    out.extend_from_slice(&query[0..2]); // ID
    let request_flags = read_u16(query, 2).unwrap_or(0);
    // QR=1, same opcode and RD, RA=1, RCODE=NOERROR.
    let flags = 0x8000 | (request_flags & 0x7900) | 0x0080;
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
mod tests {
    use super::*;

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
