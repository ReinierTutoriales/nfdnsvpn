package com.reiniertutoriales.nfdnsvpn.vpn

import com.reiniertutoriales.nfdnsvpn.lists.ListStatus
import java.util.ArrayDeque
import java.util.concurrent.atomic.AtomicLong

/** Live state of the VPN, written by [ShieldVpnService] and polled by the UI. */
object ShieldState {
    enum class Phase { STOPPED, STARTING, RUNNING }

    private const val RECENT_LIMIT = 30

    @Volatile var phase = Phase.STOPPED
    @Volatile var error: String? = null
    @Volatile var rules = 0
    @Volatile var lists: List<ListStatus> = emptyList()
    @Volatile var privateDnsStrict: String? = null
    val queries = AtomicLong()
    val blocked = AtomicLong()
    private val recent = ArrayDeque<String>()

    fun recordBlocked(name: String) {
        blocked.incrementAndGet()
        synchronized(recent) {
            recent.remove(name)
            recent.addFirst(name)
            while (recent.size > RECENT_LIMIT) recent.removeLast()
        }
    }

    fun recentBlocked(): List<String> = synchronized(recent) { recent.toList() }

    fun resetCounters() {
        queries.set(0)
        blocked.set(0)
        synchronized(recent) { recent.clear() }
    }
}
