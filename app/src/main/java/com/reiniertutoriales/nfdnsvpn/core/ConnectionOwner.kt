package com.reiniertutoriales.nfdnsvpn.core

import java.net.InetAddress
import java.net.InetSocketAddress

/**
 * Called by the native tunnel, on its own thread, to learn which app (uid) owns a new
 * connection; only while some app is blocked. The service installs [lookup]
 * (`ConnectivityManager.getConnectionOwnerUid`, Android 10+).
 */
object ConnectionOwner {
    const val UNKNOWN = -1

    @Volatile var lookup: ((protocol: Int, local: InetSocketAddress, remote: InetSocketAddress) -> Int)? = null

    /** [protocol]: 6 (TCP) or 17 (UDP); addresses as 4 or 16 bytes. */
    @JvmStatic
    fun find(protocol: Int, local: ByteArray, localPort: Int, remote: ByteArray, remotePort: Int): Int {
        val lookup = lookup ?: return UNKNOWN
        return try {
            lookup(protocol, InetSocketAddress(InetAddress.getByAddress(local), localPort), InetSocketAddress(InetAddress.getByAddress(remote), remotePort))
        } catch (e: RuntimeException) {
            UNKNOWN // Not the active VPN any more, or the connection is already gone.
        }
    }
}
