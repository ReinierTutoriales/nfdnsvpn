package com.reiniertutoriales.nfdnsvpn.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.os.Build
import java.net.Inet6Address

/**
 * Watches the real network: whether it has IPv6, its resolvers (only to route them into the
 * tunnel, so DNS sent straight to the router is filtered; they never answer anything) and
 * Android's private DNS setting. The app excludes itself from the VPN, so its default network is
 * the underlying one even while the tunnel is up.
 */
class UpstreamDns(
    context: Context,
    private val onPrivateDns: (String?) -> Unit,
    /** The routes' inputs changed; called on the connectivity thread with the latest snapshot. */
    private val onNetworkChanged: (NetworkSnapshot) -> Unit,
) {
    private val connectivity = context.getSystemService(ConnectivityManager::class.java)

    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onLinkPropertiesChanged(network: Network, properties: LinkProperties) = update(properties)
    }

    /** The latest state of the real network; the interface is built from it. */
    @Volatile var snapshot: NetworkSnapshot
        private set

    init {
        val properties = connectivity.activeNetwork?.let(connectivity::getLinkProperties)
        snapshot = properties?.let(::snapshotOf) ?: NetworkSnapshot(emptyList(), false)
        properties?.let(::update)
        connectivity.registerDefaultNetworkCallback(callback)
    }

    private fun snapshotOf(properties: LinkProperties) = NetworkSnapshot.of(
        properties.dnsServers,
        properties.routes.any { it.isDefaultRoute && it.destination.address is Inet6Address },
    )

    fun close() {
        runCatching { connectivity.unregisterNetworkCallback(callback) }
    }

    private fun update(properties: LinkProperties) {
        // Strict private DNS sends queries over TLS to the provider and skips our resolver.
        onPrivateDns(if (Build.VERSION.SDK_INT >= 28) properties.privateDnsServerName else null)
        // Losing the network keeps the last snapshot: its routes stay in place, nothing leaks.
        val latest = snapshotOf(properties)
        if (latest != snapshot) {
            snapshot = latest
            onNetworkChanged(latest)
        }
    }
}
