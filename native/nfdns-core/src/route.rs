//! First decision for every packet read from the TUN, before the TCP/IP stack sees it.

use crate::dns;
use crate::filter::Filter;
use crate::packet::{self, PROTO_TCP, PROTO_UDP};
use std::net::IpAddr;

const DNS_PORT: u16 = 53;
/// DNS over TLS (TCP) and DNS over QUIC (UDP).
const ENCRYPTED_DNS_PORT: u16 = 853;
/// Firefox asks for this name before turning on its own DNS over HTTPS; "no such domain" keeps
/// it on the system DNS (Mozilla's documented network signal).
const FIREFOX_DOH_CANARY: &str = "use-application-dns.net";

#[derive(Debug, PartialEq)]
pub enum Verdict {
    /// Discarded: malformed, unsupported protocol or a bypass attempt over UDP.
    Drop,
    /// Answered locally; `packet` goes straight back to the TUN. `blocked` names the DNS name
    /// that was refused, `None` for a TCP reset.
    Reply { packet: Vec<u8>, blocked: Option<String> },
    /// Allowed DNS query: send `query` upstream and wrap the answer with [`wrap_reply`].
    Forward { query: Vec<u8>, name: String },
    /// Ordinary traffic for the TCP/IP stack and the relay (full mode only).
    Stack,
}

fn reset(p: &packet::Packet<'_>) -> Verdict {
    packet::tcp_reset(p).map_or(Verdict::Drop, |packet| Verdict::Reply { packet, blocked: None })
}

/// Every DNS query is answered here whatever address it was sent to, so apps that hardcode a
/// resolver are filtered too. Encrypted DNS and the public resolvers' other ports are refused so
/// that apps fall back to plain DNS. In light mode only resolver addresses reach the TUN, so
/// [`Verdict::Stack`] never comes up there.
pub fn classify(filter: &Filter, intercepted: &[IpAddr], data: &[u8]) -> Verdict {
    let Some(p) = packet::parse(data) else { return Verdict::Drop };
    if p.protocol == PROTO_UDP && p.dst_port == DNS_PORT {
        return match dns::parse_query(p.payload) {
            // No HTTPS/SVCB records: without their ECH keys, TLS and QUIC show the server name,
            // which is what lets the filter see where an allowed app connects. Clients fall back
            // to A/AAAA, so nothing breaks.
            Some(q) if q.qtype == dns::TYPE_HTTPS || q.qtype == dns::TYPE_SVCB => {
                let answer = dns::blocked_response(p.payload, &q);
                Verdict::Reply { packet: packet::udp_reply(&p, &answer), blocked: None }
            }
            Some(q) if q.name == FIREFOX_DOH_CANARY => {
                let answer = dns::nxdomain_response(p.payload, &q);
                Verdict::Reply { packet: packet::udp_reply(&p, &answer), blocked: None }
            }
            Some(q) if filter.is_blocked(&q.name) => {
                let answer = dns::blocked_response(p.payload, &q);
                Verdict::Reply { packet: packet::udp_reply(&p, &answer), blocked: Some(q.name) }
            }
            Some(q) => Verdict::Forward { query: p.payload.to_vec(), name: q.name },
            // Unusual but well-formed messages are left for the upstream resolver to judge.
            None if p.payload.len() >= 12 => Verdict::Forward { query: p.payload.to_vec(), name: String::new() },
            None => Verdict::Drop,
        };
    }
    let refused = p.dst_port == ENCRYPTED_DNS_PORT
        || (p.protocol == PROTO_TCP && p.dst_port == DNS_PORT)
        || intercepted.contains(&p.dst)
        || filter.is_ip_blocked(&p.dst);
    match (refused, p.protocol) {
        (true, PROTO_TCP) => reset(&p),
        (true, _) => Verdict::Drop,
        (false, _) => Verdict::Stack,
    }
}

/// IP/UDP packet carrying the upstream `answer` back to the app that sent `request`.
pub fn wrap_reply(request: &[u8], answer: &[u8]) -> Option<Vec<u8>> {
    let p = packet::parse(request)?;
    (p.protocol == PROTO_UDP).then(|| packet::udp_reply(&p, answer))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{TYPE_A, build_query};
    use crate::filter::FilterBuilder;
    use crate::packet::tests::{tcp_syn, udp_packet};

    fn sample_filter() -> Filter {
        let mut builder = FilterBuilder::default();
        builder.add_list("||doubleclick.net^\n");
        builder.build()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn intercepted() -> Vec<IpAddr> {
        vec![ip("10.111.0.1"), ip("8.8.8.8")]
    }

    #[test]
    fn blocked_query_is_answered_locally_for_any_resolver() {
        for resolver in ["10.111.0.1", "192.0.2.53"] {
            let query = udp_packet(ip("10.111.0.2"), ip(resolver), 40000, 53, &build_query(9, "pubads.g.doubleclick.net", TYPE_A));
            let Verdict::Reply { packet, blocked } = classify(&sample_filter(), &intercepted(), &query) else { panic!() };
            assert_eq!(blocked.as_deref(), Some("pubads.g.doubleclick.net"));
            let reply = packet::parse(&packet).unwrap();
            assert_eq!((reply.src, reply.dst, reply.src_port, reply.dst_port), (ip(resolver), ip("10.111.0.2"), 53, 40000));
            assert_eq!(&reply.payload[reply.payload.len() - 4..], &[0, 0, 0, 0]);
        }
    }

    #[test]
    fn allowed_query_is_forwarded_and_wrapped() {
        let dns_query = build_query(9, "example.com", TYPE_A);
        let query = udp_packet(ip("10.111.0.2"), ip("10.111.0.1"), 40000, 53, &dns_query);
        let Verdict::Forward { query: forwarded, name } = classify(&sample_filter(), &intercepted(), &query) else { panic!() };
        assert_eq!((forwarded.as_slice(), name.as_str()), (dns_query.as_slice(), "example.com"));
        let wrapped = wrap_reply(&query, b"upstream answer").unwrap();
        let reply = packet::parse(&wrapped).unwrap();
        assert_eq!((reply.dst, reply.dst_port), (ip("10.111.0.2"), 40000));
        assert_eq!(reply.payload, b"upstream answer");
    }

    #[test]
    fn ech_records_and_firefox_doh_are_refused_for_any_name() {
        let f = sample_filter();
        for (qtype, name, rcode) in
            [(dns::TYPE_HTTPS, "example.com", 0), (dns::TYPE_SVCB, "_dns.resolver.arpa", 0), (TYPE_A, FIREFOX_DOH_CANARY, 3)]
        {
            let query = udp_packet(ip("10.111.0.2"), ip("10.111.0.1"), 40000, 53, &build_query(9, name, qtype));
            let Verdict::Reply { packet, blocked: None } = classify(&f, &intercepted(), &query) else { panic!("{name}") };
            let reply = packet::parse(&packet).unwrap();
            assert_eq!(reply.payload[3] & 0x0F, rcode, "{name}");
            assert_eq!(&reply.payload[6..8], &[0, 0], "{name}: no answer records");
        }
    }

    #[test]
    fn encrypted_dns_and_resolver_bypass_are_refused() {
        let f = sample_filter();
        let client = ip("10.111.0.2");
        let dot_anywhere = tcp_syn(client, ip("203.0.113.9"), 50000, 853, 7);
        assert!(matches!(classify(&f, &intercepted(), &dot_anywhere), Verdict::Reply { blocked: None, .. }));
        let dns_over_tcp = tcp_syn(client, ip("203.0.113.9"), 50000, 53, 7);
        assert!(matches!(classify(&f, &intercepted(), &dns_over_tcp), Verdict::Reply { blocked: None, .. }));
        let doh_to_resolver = tcp_syn(client, ip("8.8.8.8"), 50000, 443, 7);
        assert!(matches!(classify(&f, &intercepted(), &doh_to_resolver), Verdict::Reply { blocked: None, .. }));
        let quic_to_resolver = udp_packet(client, ip("8.8.8.8"), 50000, 443, b"quic");
        assert_eq!(classify(&f, &intercepted(), &quic_to_resolver), Verdict::Drop);
        let doq = udp_packet(client, ip("203.0.113.9"), 50000, 853, b"doq");
        assert_eq!(classify(&f, &intercepted(), &doq), Verdict::Drop);
    }

    #[test]
    fn listed_encrypted_dns_addresses_are_refused_but_still_get_dns() {
        let mut builder = FilterBuilder::default();
        builder.add_list("203.0.113.53\n");
        let f = builder.build();
        let client = ip("10.111.0.2");
        let doh = tcp_syn(client, ip("203.0.113.53"), 50000, 443, 7);
        assert!(matches!(classify(&f, &[], &doh), Verdict::Reply { blocked: None, .. }));
        let doq = udp_packet(client, ip("203.0.113.53"), 50000, 8853, b"doq");
        assert_eq!(classify(&f, &[], &doq), Verdict::Drop);
        let plain_dns = udp_packet(client, ip("203.0.113.53"), 50000, 53, &build_query(3, "example.com", TYPE_A));
        assert!(matches!(classify(&f, &[], &plain_dns), Verdict::Forward { .. }));
    }

    #[test]
    fn ordinary_traffic_goes_to_the_stack() {
        let f = sample_filter();
        let https = tcp_syn(ip("10.111.0.2"), ip("203.0.113.9"), 50000, 443, 7);
        assert_eq!(classify(&f, &intercepted(), &https), Verdict::Stack);
        let quic = udp_packet(ip("10.111.0.2"), ip("203.0.113.9"), 50000, 443, b"quic");
        assert_eq!(classify(&f, &intercepted(), &quic), Verdict::Stack);
        assert_eq!(classify(&f, &intercepted(), &[1, 2, 3]), Verdict::Drop);
    }
}
