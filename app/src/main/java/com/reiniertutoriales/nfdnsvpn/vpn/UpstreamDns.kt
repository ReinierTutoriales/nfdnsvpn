package com.reiniertutoriales.nfdnsvpn.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.os.Build
import java.net.Inet6Address

/**
 * Watches the real network (usually the router): its resolvers, which allowed queries are
 * forwarded to, and whether it has IPv6. The app excludes itself from the VPN, so its default
 * network is the underlying one even while the tunnel is up.
 */
class UpstreamDns(
    context: Context,
    private val onServers: (List<String>) -> Unit,
    private val onPrivateDns: (String?) -> Unit,
) {
    private val connectivity = context.getSystemService(ConnectivityManager::class.java)

    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onLinkPropertiesChanged(network: Network, properties: LinkProperties) = update(properties)
    }

    /** IPv6 default route on the real network when this object was created. */
    val hasIpv6: Boolean

    init {
        val properties = connectivity.activeNetwork?.let(connectivity::getLinkProperties)
        hasIpv6 = properties?.routes?.any { it.isDefaultRoute && it.destination.address is Inet6Address } == true
        properties?.let(::update)
        connectivity.registerDefaultNetworkCallback(callback)
    }

    fun close() {
        runCatching { connectivity.unregisterNetworkCallback(callback) }
    }

    private fun update(properties: LinkProperties) {
        // Scoped (link-local) resolvers cannot be written as plain addresses; the core skips them
        // and falls back to Quad9 if nothing else is left.
        onServers(properties.dnsServers.filterNot(ShieldVpnService::isVirtualAddress).mapNotNull { it.hostAddress })
        // Strict private DNS sends queries over TLS to the provider and skips our resolver.
        onPrivateDns(if (Build.VERSION.SDK_INT >= 28) properties.privateDnsServerName else null)
    }
}
