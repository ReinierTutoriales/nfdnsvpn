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
use jni::sys::{jboolean, jint, jlong};
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

/// Starts a filter built list by list (see `nativeBuilderAddFile`), so no list text is ever
/// held in Java memory. Finish with `nativeBuilderBuild` or free with `nativeBuilderDestroy`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_reiniertutoriales_nfdnsvpn_core_NativeCore_nativeBuilderNew<'caller>(
    _unowned: EnvUnowned<'caller>,
    _class: JClass<'caller>,
) -> jlong {
    Box::into_raw(Box::new(FilterBuilder::default())) as jlong
}

fn builder<'a>(handle: jlong) -> Option<&'a mut FilterBuilder> {
    // SAFETY: builder handles come from `nativeBuilderNew` and are used by one thread at a time,
    // until `nativeBuilderBuild` or `nativeBuilderDestroy` releases them.
    (handle != 0).then(|| unsafe { &mut *(handle as *mut FilterBuilder) })
}

/// Reads a list file line by line; false if it cannot be read.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_reiniertutoriales_nfdnsvpn_core_NativeCore_nativeBuilderAddFile<'caller>(
    mut unowned: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    handle: jlong,
    path: JString<'caller>,
) -> jboolean {
    unowned
        .with_env(|env| -> jni::errors::Result<jboolean> {
            let path = path.try_to_string(env)?;
            let Some(b) = builder(handle) else { return Ok(false) };
            let added = std::fs::File::open(&path).and_then(|file| b.add_reader(std::io::BufReader::new(file)));
            Ok(added.is_ok())
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// Adds rules given as text (small inputs: the bundled list, the allowlist).
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_reiniertutoriales_nfdnsvpn_core_NativeCore_nativeBuilderAddText<'caller>(
    mut unowned: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    handle: jlong,
    text: JString<'caller>,
) {
    unowned
        .with_env(|env| -> jni::errors::Result<()> {
            let text = text.try_to_string(env)?;
            if let Some(b) = builder(handle) {
                b.add_list(&text);
            }
            Ok(())
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// Consumes the builder and returns a filter handle (as `nativeCreate`).
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_reiniertutoriales_nfdnsvpn_core_NativeCore_nativeBuilderBuild<'caller>(
    _unowned: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    handle: jlong,
) -> jlong {
    if handle == 0 {
        return 0;
    }
    // SAFETY: see `builder`; ownership ends here.
    let builder = *unsafe { Box::from_raw(handle as *mut FilterBuilder) };
    Box::into_raw(Box::new(builder.build())) as jlong
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_reiniertutoriales_nfdnsvpn_core_NativeCore_nativeBuilderDestroy<'caller>(
    _unowned: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    handle: jlong,
) {
    if handle != 0 {
        // SAFETY: see `builder`.
        drop(unsafe { Box::from_raw(handle as *mut FilterBuilder) });
    }
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
