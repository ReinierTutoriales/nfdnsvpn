package com.reiniertutoriales.nfdnsvpn.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.os.Build
import java.net.InetAddress

/**
 * Resolvers of the real network (usually the router) that allowed queries are forwarded to.
 * The app excludes itself from the VPN, so its default network is the underlying one.
 */
class UpstreamDns(context: Context, private val onPrivateDns: (String?) -> Unit) {
    companion object {
        /** Quad9, only when the network announces no resolver. */
        private val FALLBACK = listOf("9.9.9.9", "149.112.112.112").map(InetAddress::getByName)
    }

    private val connectivity = context.getSystemService(ConnectivityManager::class.java)
    @Volatile private var servers: List<InetAddress> = emptyList()

    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onLinkPropertiesChanged(network: Network, properties: LinkProperties) = update(properties)
    }

    init {
        connectivity.activeNetwork?.let(connectivity::getLinkProperties)?.let(::update)
        connectivity.registerDefaultNetworkCallback(callback)
    }

    fun servers(): List<InetAddress> = servers.ifEmpty { FALLBACK }

    fun close() {
        runCatching { connectivity.unregisterNetworkCallback(callback) }
    }

    private fun update(properties: LinkProperties) {
        servers = properties.dnsServers.filterNot { ShieldVpnService.isVirtualAddress(it) }
        // Strict private DNS sends queries over TLS to the provider and skips our resolver.
        onPrivateDns(if (Build.VERSION.SDK_INT >= 28) properties.privateDnsServerName else null)
    }
}
