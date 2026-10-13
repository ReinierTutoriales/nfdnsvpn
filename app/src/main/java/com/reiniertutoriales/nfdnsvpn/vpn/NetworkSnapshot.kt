package com.reiniertutoriales.nfdnsvpn.vpn

import java.net.InetAddress

/**
 * What the tunnel's routes depend on: the real network's resolvers (routed into the tunnel, so
 * DNS sent straight to the router is filtered) and whether it has IPv6. When this changes (other
 * Wi-Fi, Ethernet, the router hands out another DNS, IPv6 comes or goes) the interface is rebuilt,
 * or the new resolver or all IPv6 traffic would go out unfiltered.
 */
data class NetworkSnapshot(val resolvers: List<InetAddress>, val hasIpv6: Boolean) {
    companion object {
        /**
         * Our own virtual resolvers are not the network's. Link-local and loopback resolvers cannot
         * be routed into a VPN (scoped), so they are left out (a known limit, see docs/PLAN.md).
         * Sorted, so the same network always gives an equal snapshot.
         */
        fun of(dnsServers: List<InetAddress>, hasIpv6: Boolean) = NetworkSnapshot(
            dnsServers.filterNot { Routes.isVirtualAddress(it) || it.isLinkLocalAddress || it.isLoopbackAddress }
                .distinct()
                .sortedBy { it.hostAddress },
            hasIpv6,
        )
    }
}
