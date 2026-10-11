package com.reiniertutoriales.nfdnsvpn.vpn

import com.reiniertutoriales.nfdnsvpn.core.NativeTunnel
import com.reiniertutoriales.nfdnsvpn.core.TunnelStats
import com.reiniertutoriales.nfdnsvpn.lists.ListStatus

/** Live state of the VPN, written by [ShieldVpnService] and polled by the UI. */
object ShieldState {
    enum class Phase { STOPPED, STARTING, RUNNING }

    @Volatile var phase = Phase.STOPPED
    @Volatile var fullTunnel = false
    @Volatile var error: String? = null
    @Volatile var rules = 0
    @Volatile var lists: List<ListStatus> = emptyList()
    @Volatile var privateDnsStrict: String? = null
    /** The running tunnel. The screen reads its counters itself while visible, so nothing polls
     * them (or wakes the TV's CPU) when nobody is looking. */
    @Volatile var tunnel: NativeTunnel? = null

    fun stats(): TunnelStats? = tunnel?.stats()
}
