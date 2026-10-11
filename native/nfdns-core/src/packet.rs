//! Raw IPv4/IPv6 packets as read from and written to the TUN interface.

use std::net::IpAddr;

pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;
const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_ACK: u8 = 0x10;

pub struct Packet<'a> {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub protocol: u8,
    pub src_port: u16,
    pub dst_port: u16,
    /// Transport header (UDP: 8 bytes, TCP: with options).
    header: &'a [u8],
    pub payload: &'a [u8],
}

fn u16_at(data: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(data.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(data.get(at..at + 4)?.try_into().ok()?))
}

/// UDP or TCP over IPv4/IPv6. Fragments, IPv6 extension headers and other protocols give `None`.
pub fn parse(data: &[u8]) -> Option<Packet<'_>> {
    let (src, dst, protocol, body) = match data.first()? >> 4 {
        4 => {
            let header_len = ((data[0] & 0x0F) as usize) * 4;
            let total = u16_at(data, 2)? as usize;
            if header_len < 20 || total < header_len || total > data.len() {
                return None;
            }
            if u16_at(data, 6)? & 0x3FFF != 0 {
                return None; // fragment
            }
            let src: [u8; 4] = data[12..16].try_into().ok()?;
            let dst: [u8; 4] = data[16..20].try_into().ok()?;
            (IpAddr::from(src), IpAddr::from(dst), data[9], &data[header_len..total])
        }
        6 => {
            let total = 40 + u16_at(data, 4)? as usize;
            if total > data.len() {
                return None;
            }
            let src: [u8; 16] = data[8..24].try_into().ok()?;
            let dst: [u8; 16] = data[24..40].try_into().ok()?;
            (IpAddr::from(src), IpAddr::from(dst), data[6], &data[40..total])
        }
        _ => return None,
    };
    let (header_len, end) = match protocol {
        PROTO_UDP => {
            let len = u16_at(body, 4)? as usize;
            if len < 8 || len > body.len() {
                return None;
            }
            (8, len)
        }
        PROTO_TCP => {
            let len = ((*body.get(12)? >> 4) as usize) * 4;
            if len < 20 || len > body.len() {
                return None;
            }
            (len, body.len())
        }
        _ => return None,
    };
    Some(Packet {
        src,
        dst,
        protocol,
        src_port: u16_at(body, 0)?,
        dst_port: u16_at(body, 2)?,
        header: &body[..header_len],
        payload: &body[header_len..end],
    })
}

fn sum_words(mut sum: u32, data: &[u8]) -> u32 {
    let (pairs, rest) = data.as_chunks::<2>();
    for &pair in pairs {
        sum += u16::from_be_bytes(pair) as u32;
    }
    if let [last] = rest {
        sum += (*last as u32) << 8;
    }
    sum
}

fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

fn ip_bytes(address: IpAddr) -> Vec<u8> {
    match address {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => a.octets().to_vec(),
    }
}

/// Wraps `transport` (checksum field zeroed) in an IP header and fills both checksums.
fn ip_packet(src: IpAddr, dst: IpAddr, protocol: u8, mut transport: Vec<u8>) -> Vec<u8> {
    let (src_bytes, dst_bytes) = (ip_bytes(src), ip_bytes(dst));
    let mut pseudo = sum_words(0, &src_bytes);
    pseudo = sum_words(pseudo, &dst_bytes);
    pseudo += protocol as u32 + transport.len() as u32;
    let mut checksum = fold(sum_words(pseudo, &transport));
    if protocol == PROTO_UDP && checksum == 0 {
        checksum = 0xFFFF;
    }
    let field = if protocol == PROTO_UDP { 6 } else { 16 };
    transport[field..field + 2].copy_from_slice(&checksum.to_be_bytes());

    let mut out = Vec::with_capacity(40 + transport.len());
    match (src, dst) {
        (IpAddr::V4(_), IpAddr::V4(_)) => {
            out.extend_from_slice(&[0x45, 0]);
            out.extend_from_slice(&((20 + transport.len()) as u16).to_be_bytes());
            out.extend_from_slice(&[0, 0, 0x40, 0, 64, protocol, 0, 0]); // id, DF, TTL
            out.extend_from_slice(&src_bytes);
            out.extend_from_slice(&dst_bytes);
            let header_checksum = fold(sum_words(0, &out));
            out[10..12].copy_from_slice(&header_checksum.to_be_bytes());
        }
        _ => {
            out.extend_from_slice(&[0x60, 0, 0, 0]);
            out.extend_from_slice(&(transport.len() as u16).to_be_bytes());
            out.extend_from_slice(&[protocol, 64]);
            out.extend_from_slice(&src_bytes);
            out.extend_from_slice(&dst_bytes);
        }
    }
    out.extend_from_slice(&transport);
    out
}

/// UDP datagram from the original destination back to the sender carrying `payload`.
pub fn udp_reply(request: &Packet<'_>, payload: &[u8]) -> Vec<u8> {
    let mut udp = Vec::with_capacity(8 + payload.len());
    udp.extend_from_slice(&request.dst_port.to_be_bytes());
    udp.extend_from_slice(&request.src_port.to_be_bytes());
    udp.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    udp.extend_from_slice(&[0, 0]);
    udp.extend_from_slice(payload);
    ip_packet(request.dst, request.src, PROTO_UDP, udp)
}

/// RST that makes the sender give up at once instead of waiting for a timeout (RFC 9293 §3.10.7.1).
/// `None` for a segment that is itself a reset.
pub fn tcp_reset(request: &Packet<'_>) -> Option<Vec<u8>> {
    let flags = request.header[13];
    if flags & TCP_RST != 0 {
        return None;
    }
    let their_seq = u32_at(request.header, 4)?;
    let their_ack = u32_at(request.header, 8)?;
    let (seq, ack, reply_flags) = if flags & TCP_ACK != 0 {
        (their_ack, 0, TCP_RST)
    } else {
        let length = request.payload.len() as u32 + u32::from(flags & TCP_SYN != 0) + u32::from(flags & TCP_FIN != 0);
        (0, their_seq.wrapping_add(length), TCP_RST | TCP_ACK)
    };
    let mut tcp = Vec::with_capacity(20);
    tcp.extend_from_slice(&request.dst_port.to_be_bytes());
    tcp.extend_from_slice(&request.src_port.to_be_bytes());
    tcp.extend_from_slice(&seq.to_be_bytes());
    tcp.extend_from_slice(&ack.to_be_bytes());
    tcp.extend_from_slice(&[0x50, reply_flags, 0, 0, 0, 0, 0, 0]); // offset 5, window, checksum, urgent
    Some(ip_packet(request.dst, request.src, PROTO_TCP, tcp))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn udp_packet(src: IpAddr, dst: IpAddr, src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let request = Packet { src: dst, dst: src, protocol: PROTO_UDP, src_port: dst_port, dst_port: src_port, header: &[], payload: &[] };
        udp_reply(&request, payload)
    }

    pub fn tcp_syn(src: IpAddr, dst: IpAddr, src_port: u16, dst_port: u16, seq: u32) -> Vec<u8> {
        let mut tcp = Vec::new();
        tcp.extend_from_slice(&src_port.to_be_bytes());
        tcp.extend_from_slice(&dst_port.to_be_bytes());
        tcp.extend_from_slice(&seq.to_be_bytes());
        tcp.extend_from_slice(&[0, 0, 0, 0, 0x50, TCP_SYN, 0xFF, 0xFF, 0, 0, 0, 0]);
        ip_packet(src, dst, PROTO_TCP, tcp)
    }

    fn checksum_ok(packet: &[u8]) -> bool {
        let p = parse(packet).unwrap();
        let (header_len, total) = match p.src {
            IpAddr::V4(_) => {
                if fold(sum_words(0, &packet[..20])) != 0 {
                    return false;
                }
                (20, packet.len())
            }
            IpAddr::V6(_) => (40, packet.len()),
        };
        let transport = &packet[header_len..total];
        let mut pseudo = sum_words(sum_words(0, &ip_bytes(p.src)), &ip_bytes(p.dst));
        pseudo += p.protocol as u32 + transport.len() as u32;
        fold(sum_words(pseudo, transport)) == 0
    }

    #[test]
    fn udp_reply_swaps_endpoints_v4() {
        let client: IpAddr = "10.111.0.2".parse().unwrap();
        let dns: IpAddr = "10.111.0.1".parse().unwrap();
        let query = udp_packet(client, dns, 40000, 53, b"query");
        let parsed = parse(&query).unwrap();
        assert_eq!((parsed.src, parsed.dst, parsed.src_port, parsed.dst_port), (client, dns, 40000, 53));
        assert_eq!(parsed.payload, b"query");
        let reply = udp_reply(&parsed, b"answer!");
        let r = parse(&reply).unwrap();
        assert_eq!((r.src, r.dst, r.src_port, r.dst_port), (dns, client, 53, 40000));
        assert_eq!(r.payload, b"answer!");
        assert!(checksum_ok(&reply));
    }

    #[test]
    fn udp_reply_swaps_endpoints_v6() {
        let client: IpAddr = "fd00:6e66::2".parse().unwrap();
        let dns: IpAddr = "2001:4860:4860::8888".parse().unwrap();
        let query = udp_packet(client, dns, 1234, 53, b"q");
        let reply = udp_reply(&parse(&query).unwrap(), b"odd");
        let r = parse(&reply).unwrap();
        assert_eq!((r.src, r.dst), (dns, client));
        assert!(checksum_ok(&reply));
    }

    #[test]
    fn reset_answers_syn() {
        let client: IpAddr = "10.111.0.2".parse().unwrap();
        let resolver: IpAddr = "8.8.8.8".parse().unwrap();
        let syn = tcp_syn(client, resolver, 50000, 853, 1000);
        let reset = tcp_reset(&parse(&syn).unwrap()).unwrap();
        let r = parse(&reset).unwrap();
        assert_eq!((r.src, r.dst, r.src_port, r.dst_port), (resolver, client, 853, 50000));
        assert_eq!(r.header[13], TCP_RST | TCP_ACK);
        assert_eq!(u32_at(r.header, 8), Some(1001));
        assert!(checksum_ok(&reset));
        assert!(tcp_reset(&r).is_none());
    }

    #[test]
    fn rejects_fragments_and_short_packets() {
        let client: IpAddr = "10.0.0.2".parse().unwrap();
        let mut packet = udp_packet(client, client, 1, 53, b"x");
        packet[6] = 0x20; // more fragments
        assert!(parse(&packet).is_none());
        assert!(parse(&[0x45, 0, 0]).is_none());
        assert!(parse(&[]).is_none());
    }
}
