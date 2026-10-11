//! Core of the nfdnsvpn local VPN: packet classification, DNS filtering and the tunnel event
//! loop (userspace TCP/IP stack and relay).
//!
//! Handles are raw pointers to boxed values owned by `com.reiniertutoriales.nfdnsvpn.core.NativeCore`:
//! a filter handle lives until `nativeDestroy` or until `nativeTunnelCreate` takes it over, and a
//! tunnel handle lives until `nativeTunnelFree`.

pub mod dns;
pub mod filter;
pub mod packet;
pub mod quic;
pub mod route;
pub mod sni;
pub mod tunnel;

use filter::{Filter, FilterBuilder};
use jni::errors::ThrowRuntimeExAndDefault;
use jni::objects::{JClass, JObjectArray, JString};
use jni::sys::{jint, jlong};
use jni::EnvUnowned;
use std::net::{IpAddr, SocketAddr};
use tunnel::Tunnel;

const DNS_PORT: u16 = 53;

/// Comma-separated addresses; a bare IP means port 53. Invalid entries are skipped.
pub fn parse_servers(list: &str) -> Vec<SocketAddr> {
    list.split(',')
        .map(str::trim)
        .filter_map(|entry| {
            entry
                .parse::<SocketAddr>()
                .ok()
                .or_else(|| entry.parse::<IpAddr>().ok().map(|ip| SocketAddr::new(ip, DNS_PORT)))
        })
        .collect()
}

fn parse_addresses(list: &str) -> Vec<IpAddr> {
    list.split(',').filter_map(|entry| entry.trim().parse().ok()).collect()
}

fn filter<'a>(handle: jlong) -> Option<&'a Filter> {
    // SAFETY: filter handles come from `nativeCreate` and are released exactly once, by
    // `nativeDestroy` or `nativeTunnelCreate`.
    (handle != 0).then(|| unsafe { &*(handle as *const Filter) })
}

fn tunnel<'a>(handle: jlong) -> Option<&'a Tunnel> {
    // SAFETY: tunnel handles come from `nativeTunnelCreate`; Kotlin stops every other caller
    // before `nativeTunnelFree`.
    (handle != 0).then(|| unsafe { &*(handle as *const Tunnel) })
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
        // SAFETY: see `filter`.
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

/// Takes ownership of the filter handle; the caller must not destroy it afterwards.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_reiniertutoriales_nfdnsvpn_core_NativeCore_nativeTunnelCreate<'caller>(
    mut unowned: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    filter_handle: jlong,
    fd: jint,
    intercepted: JString<'caller>,
) -> jlong {
    unowned
        .with_env(|env| -> jni::errors::Result<jlong> {
            let intercepted = parse_addresses(&intercepted.try_to_string(env)?);
            let filter = if filter_handle == 0 {
                FilterBuilder::default().build()
            } else {
                // SAFETY: see `filter`; ownership moves into the tunnel here.
                *unsafe { Box::from_raw(filter_handle as *mut Filter) }
            };
            Ok(Box::into_raw(Box::new(Tunnel::new(fd, filter, intercepted))) as jlong)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_reiniertutoriales_nfdnsvpn_core_NativeCore_nativeTunnelSetUpstream<'caller>(
    mut unowned: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    handle: jlong,
    servers: JString<'caller>,
) {
    unowned
        .with_env(|env| -> jni::errors::Result<()> {
            if let Some(t) = tunnel(handle) {
                t.set_upstream(parse_servers(&servers.try_to_string(env)?));
            }
            Ok(())
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// Takes ownership of the filter handle and puts it in use at once (daily list update).
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_reiniertutoriales_nfdnsvpn_core_NativeCore_nativeTunnelSetFilter<'caller>(
    _unowned: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    handle: jlong,
    filter_handle: jlong,
) {
    if filter_handle == 0 {
        return;
    }
    // SAFETY: see `filter`; ownership moves into the tunnel (or is dropped without one).
    let filter = *unsafe { Box::from_raw(filter_handle as *mut Filter) };
    if let Some(t) = tunnel(handle) {
        t.set_filter(filter);
    }
}

/// Blocks until `nativeTunnelStop`; returns an empty string, or the error that ended the tunnel.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_reiniertutoriales_nfdnsvpn_core_NativeCore_nativeTunnelRun<'caller>(
    mut unowned: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    handle: jlong,
) -> JString<'caller> {
    let outcome = match tunnel(handle) {
        Some(t) => t.run().err().map(|e| e.to_string()).unwrap_or_default(),
        None => "no tunnel".to_string(),
    };
    unowned
        .with_env(|env| -> jni::errors::Result<JString<'caller>> { env.new_string(outcome) })
        .resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_reiniertutoriales_nfdnsvpn_core_NativeCore_nativeTunnelStop<'caller>(
    _unowned: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    handle: jlong,
) {
    if let Some(t) = tunnel(handle) {
        t.stop();
    }
}

/// `queries,blocked,tcp,udp,quic_refused` followed by recently blocked names, one per line.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_reiniertutoriales_nfdnsvpn_core_NativeCore_nativeTunnelStats<'caller>(
    mut unowned: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    handle: jlong,
) -> JString<'caller> {
    let stats = tunnel(handle).map(|t| t.stats().encode()).unwrap_or_default();
    unowned
        .with_env(|env| -> jni::errors::Result<JString<'caller>> { env.new_string(stats) })
        .resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_reiniertutoriales_nfdnsvpn_core_NativeCore_nativeTunnelFree<'caller>(
    _unowned: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    handle: jlong,
) {
    if handle != 0 {
        // SAFETY: see `tunnel`; `nativeTunnelRun` has returned before Kotlin frees it.
        drop(unsafe { Box::from_raw(handle as *mut Tunnel) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_server_lists() {
        assert_eq!(
            parse_servers("192.168.1.1, 2001:db8::1,[2001:db8::2]:5353,127.0.0.1:5300,garbage"),
            vec![
                "192.168.1.1:53".parse().unwrap(),
                "[2001:db8::1]:53".parse().unwrap(),
                "[2001:db8::2]:5353".parse().unwrap(),
                "127.0.0.1:5300".parse().unwrap(),
            ]
        );
        assert!(parse_servers("").is_empty());
    }
}
