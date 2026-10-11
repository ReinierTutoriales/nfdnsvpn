package com.reiniertutoriales.nfdnsvpn.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.os.Build
import java.net.Inet6Address
import java.net.InetAddress

/**
 * Watches the real network: whether it has IPv6, its resolvers (only to route them into the
 * tunnel, so DNS sent straight to the router is filtered; they never answer anything) and
 * Android's private DNS setting. The app excludes itself from the VPN, so its default network is
 * the underlying one even while the tunnel is up.
 */
class UpstreamDns(
    context: Context,
    private val onPrivateDns: (String?) -> Unit,
) {
    private val connectivity = context.getSystemService(ConnectivityManager::class.java)

    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onLinkPropertiesChanged(network: Network, properties: LinkProperties) = update(properties)
    }

    /** IPv6 default route on the real network when this object was created. */
    val hasIpv6: Boolean

    /**
     * The real network's resolvers when this object was created (usually the router). They are
     * routed into the tunnel too, so an app sending DNS straight to the router is filtered.
     */
    val initialServers: List<InetAddress>

    init {
        val properties = connectivity.activeNetwork?.let(connectivity::getLinkProperties)
        hasIpv6 = properties?.routes?.any { it.isDefaultRoute && it.destination.address is Inet6Address } == true
        initialServers = properties?.dnsServers.orEmpty()
            .filterNot { ShieldVpnService.isVirtualAddress(it) || it.isLinkLocalAddress || it.isLoopbackAddress }
        properties?.let(::update)
        connectivity.registerDefaultNetworkCallback(callback)
    }

    fun close() {
        runCatching { connectivity.unregisterNetworkCallback(callback) }
    }

    private fun update(properties: LinkProperties) {
        // Strict private DNS sends queries over TLS to the provider and skips our resolver.
        onPrivateDns(if (Build.VERSION.SDK_INT >= 28) properties.privateDnsServerName else null)
    }
}
