//! Core of the nfdnsvpn local VPN: classifies the packets read from the TUN interface and filters
//! DNS names. Socket I/O stays in Kotlin (`ShieldVpnService`), so everything here is pure and
//! runs in host unit tests.
//!
//! Handles are raw pointers to boxed filters owned by `com.reiniertutoriales.nfdnsvpn.core.NativeCore`.

pub mod dns;
pub mod filter;
pub mod packet;

use filter::{Filter, FilterBuilder};
use jni::errors::ThrowRuntimeExAndDefault;
use jni::objects::{JByteArray, JClass, JObjectArray, JString};
use jni::sys::{jint, jlong};
use jni::EnvUnowned;
use packet::{PROTO_TCP, PROTO_UDP};

const DNS_PORT: u16 = 53;

#[derive(Debug, PartialEq)]
pub enum Action {
    /// Nothing to send back (unsupported or malformed packet).
    Ignore,
    /// Blocked DNS name answered locally; `packet` goes back to the TUN.
    Blocked { packet: Vec<u8>, name: String },
    /// TCP to an intercepted resolver (DoT, DoH, DNS over TCP) refused with a RST.
    Reset { packet: Vec<u8> },
    /// Allowed query: send `query` upstream and wrap the answer with [`wrap_reply`].
    Forward { query: Vec<u8>, name: String },
}

/// Only DNS reaches the TUN in light mode: the virtual resolver and the public resolvers routed
/// into it. Everything else sent to those addresses is a bypass attempt.
pub fn handle(filter: &Filter, data: &[u8]) -> Action {
    let Some(p) = packet::parse(data) else { return Action::Ignore };
    match (p.protocol, p.dst_port) {
        (PROTO_UDP, DNS_PORT) => match dns::parse_query(p.payload) {
            Some(q) if filter.is_blocked(&q.name) => {
                let answer = dns::blocked_response(p.payload, &q);
                Action::Blocked { packet: packet::udp_reply(&p, &answer), name: q.name }
            }
            Some(q) => Action::Forward { query: p.payload.to_vec(), name: q.name },
            // Unusual but well-formed messages are left for the upstream resolver to judge.
            None if p.payload.len() >= 12 => Action::Forward { query: p.payload.to_vec(), name: String::new() },
            None => Action::Ignore,
        },
        (PROTO_TCP, _) => packet::tcp_reset(&p).map_or(Action::Ignore, |packet| Action::Reset { packet }),
        // QUIC/HTTP3 and other UDP to a resolver address: dropped, apps fall back to plain DNS.
        _ => Action::Ignore,
    }
}

/// IP/UDP packet carrying the upstream `answer` back to the app that sent `request`.
pub fn wrap_reply(request: &[u8], answer: &[u8]) -> Option<Vec<u8>> {
    let p = packet::parse(request)?;
    (p.protocol == PROTO_UDP).then(|| packet::udp_reply(&p, answer))
}

const KIND_IGNORE: u8 = 0;
const KIND_BLOCKED: u8 = 1;
const KIND_RESET: u8 = 2;
const KIND_FORWARD: u8 = 3;

/// `[kind][name length: u16][name][data]`, one JNI call per packet.
fn encode(action: Action) -> Vec<u8> {
    let (kind, name, data) = match action {
        Action::Ignore => (KIND_IGNORE, String::new(), Vec::new()),
        Action::Blocked { packet, name } => (KIND_BLOCKED, name, packet),
        Action::Reset { packet } => (KIND_RESET, String::new(), packet),
        Action::Forward { query, name } => (KIND_FORWARD, name, query),
    };
    let mut out = Vec::with_capacity(3 + name.len() + data.len());
    out.push(kind);
    out.extend_from_slice(&(name.len() as u16).to_be_bytes());
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(&data);
    out
}

fn filter<'a>(handle: jlong) -> Option<&'a Filter> {
    // SAFETY: handles are only produced by `nativeCreate` and destroyed once by `nativeDestroy`,
    // after the packet loop that uses them has stopped.
    (handle != 0).then(|| unsafe { &*(handle as *const Filter) })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_reiniertutoriales_nfdnsvpn_core_NativeCore_nativeCreate<'caller>(
    mut unowned: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    lists: JObjectArray<'caller, JString<'caller>>,
) -> jlong {
    unowned
        .with_env(|env| -> jni::errors::Result<jlong> {
            let mut builder = FilterBuilder::default();
            // One list at a time: no combined copy of several megabytes of text.
            for index in 0..lists.len(env)? {
                let list = lists.get_element(env, index)?;
                builder.add_list(&list.try_to_string(env)?);
            }
            Ok(Box::into_raw(Box::new(builder.build())) as jlong)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_reiniertutoriales_nfdnsvpn_core_NativeCore_nativeDestroy<'caller>(
    _unowned: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    handle: jlong,
) {
    if handle != 0 {
        // SAFETY: see `filter`; Kotlin clears its copy of the handle before calling this.
        drop(unsafe { Box::from_raw(handle as *mut Filter) });
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_reiniertutoriales_nfdnsvpn_core_NativeCore_nativeRuleCount<'caller>(
    _unowned: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    handle: jlong,
) -> jint {
    filter(handle).map_or(0, |f| f.rule_count() as jint)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_reiniertutoriales_nfdnsvpn_core_NativeCore_nativeHandle<'caller>(
    mut unowned: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    handle: jlong,
    packet: JByteArray<'caller>,
) -> JByteArray<'caller> {
    unowned
        .with_env(|env| -> jni::errors::Result<JByteArray<'caller>> {
            let action = match filter(handle) {
                Some(f) => crate::handle(f, &env.convert_byte_array(&packet)?),
                None => Action::Ignore,
            };
            env.byte_array_from_slice(&encode(action))
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_reiniertutoriales_nfdnsvpn_core_NativeCore_nativeWrapReply<'caller>(
    mut unowned: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    request: JByteArray<'caller>,
    answer: JByteArray<'caller>,
) -> JByteArray<'caller> {
    unowned
        .with_env(|env| -> jni::errors::Result<JByteArray<'caller>> {
            let request = env.convert_byte_array(&request)?;
            let answer = env.convert_byte_array(&answer)?;
            env.byte_array_from_slice(&wrap_reply(&request, &answer).unwrap_or_default())
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{build_query, TYPE_A};
    use crate::packet::tests::{tcp_syn, udp_packet};
    use std::net::IpAddr;

    fn sample_filter() -> Filter {
        let mut builder = FilterBuilder::default();
        builder.add_list("||doubleclick.net^\n");
        builder.build()
    }

    fn client() -> IpAddr {
        "10.111.0.2".parse().unwrap()
    }

    fn resolver() -> IpAddr {
        "10.111.0.1".parse().unwrap()
    }

    #[test]
    fn blocked_query_is_answered_locally() {
        let query = udp_packet(client(), resolver(), 40000, 53, &build_query(9, "pubads.g.doubleclick.net", TYPE_A));
        let Action::Blocked { packet, name } = handle(&sample_filter(), &query) else { panic!() };
        assert_eq!(name, "pubads.g.doubleclick.net");
        let reply = packet::parse(&packet).unwrap();
        assert_eq!((reply.src, reply.dst, reply.src_port, reply.dst_port), (resolver(), client(), 53, 40000));
        assert_eq!(&reply.payload[reply.payload.len() - 4..], &[0, 0, 0, 0]);
    }

    #[test]
    fn allowed_query_is_forwarded_and_wrapped() {
        let dns_query = build_query(9, "example.com", TYPE_A);
        let query = udp_packet(client(), resolver(), 40000, 53, &dns_query);
        let Action::Forward { query: forwarded, name } = handle(&sample_filter(), &query) else { panic!() };
        assert_eq!((forwarded.as_slice(), name.as_str()), (dns_query.as_slice(), "example.com"));
        let wrapped = wrap_reply(&query, b"upstream answer").unwrap();
        let reply = packet::parse(&wrapped).unwrap();
        assert_eq!((reply.dst, reply.dst_port), (client(), 40000));
        assert_eq!(reply.payload, b"upstream answer");
    }

    #[test]
    fn tcp_to_resolver_is_reset_and_other_udp_ignored() {
        let dot = tcp_syn(client(), "1.1.1.1".parse().unwrap(), 50000, 853, 7);
        assert!(matches!(handle(&sample_filter(), &dot), Action::Reset { .. }));
        let quic = udp_packet(client(), "1.1.1.1".parse().unwrap(), 50000, 443, b"quic");
        assert_eq!(handle(&sample_filter(), &quic), Action::Ignore);
        assert_eq!(handle(&sample_filter(), &[1, 2, 3]), Action::Ignore);
    }

    #[test]
    fn encoding_layout() {
        let encoded = encode(Action::Forward { query: vec![9, 9], name: "ab".into() });
        assert_eq!(encoded, vec![KIND_FORWARD, 0, 2, b'a', b'b', 9, 9]);
        assert_eq!(encode(Action::Ignore), vec![KIND_IGNORE, 0, 0]);
    }
}
