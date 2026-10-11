package com.reiniertutoriales.nfdnsvpn.vpn

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
    /** Latest counters of the running tunnel, refreshed every second. */
    @Volatile var stats: TunnelStats? = null
}
