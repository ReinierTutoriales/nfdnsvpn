package com.reiniertutoriales.nfdnsvpn.vpn

import java.io.Closeable
import java.util.concurrent.atomic.AtomicBoolean

/** What [InterfaceLoop] drives: the native tunnel. [run] blocks until [stop]. */
interface TunnelPort {
    fun run(): String
    fun stop()
    fun setFd(fd: Int)
}

/** An established VPN interface. */
interface VpnInterface : Closeable {
    val fd: Int
}

/**
 * Keeps the tunnel on an interface whose routes match the network, without Android knowledge so
 * it can be tested on the JVM.
 *
 * - [networkChanged]: the running tunnel returns and the interface is rebuilt. Each rebuild reads
 *   the network as it is when it establishes; a change during that establish triggers one more.
 *   Intermediate states can be established briefly; the last change always ends up applied.
 * - The new interface exists before the old one is closed, and only one tunnel run is active.
 * - A rebuild that fails (establish throws, e.g. a route refused) keeps the old interface: Android
 *   keeps it when it cannot create the new one, and closing it could send traffic around the
 *   filter. Its routes may be stale, so health is [Health.DEGRADED] (never "protected") while a
 *   limited number of retries with growing delays runs; a later network change retries too.
 * - establish giving no interface means the VPN consent was revoked: the loop ends.
 * - [stop] ends the loop; an interface established meanwhile is closed, not used.
 */
class InterfaceLoop(
    private val tunnel: TunnelPort,
    /** The interface for the network as it is now; null if the VPN consent is gone. */
    private val establish: () -> VpnInterface?,
    /** Health changes; the message says why it is degraded. */
    private val onHealth: (Health, String?) -> Unit,
    /** Runs `retry` after `delayMs` (on another thread). */
    private val schedule: (delayMs: Long, retry: () -> Unit) -> Unit,
) {
    enum class Health { PROTECTED, DEGRADED }

    enum class End { STOPPED, REVOKED, FAILED }

    data class Outcome(val end: End, val message: String? = null)

    companion object {
        /** Automatic retries after a failed rebuild: 1, 2, 4, 8 and 16 s, then only on change. */
        const val MAX_RETRIES = 5
        fun retryDelayMs(attempt: Int) = 1000L shl (attempt - 1)
    }

    private val rebuild = AtomicBoolean(false)
    @Volatile private var stopping = false
    private var failedRebuilds = 0

    /** From any thread: the network changed. */
    fun networkChanged() {
        rebuild.set(true)
        tunnel.stop()
    }

    /** From any thread: user stop or revocation. */
    fun stop() {
        stopping = true
        tunnel.stop()
    }

    /** Runs the tunnel on [initial] until the end; every interface it held is closed on return. */
    fun run(initial: VpnInterface): Outcome {
        var current = initial
        try {
            // A change reported before this run started (its stop() had nothing to stop yet).
            if (rebuild.get()) tunnel.stop()
            while (true) {
                val failure = tunnel.run()
                if (stopping) return Outcome(End.STOPPED)
                if (!rebuild.getAndSet(false)) {
                    return if (failure.isEmpty()) Outcome(End.STOPPED) else Outcome(End.FAILED, failure)
                }
                val next = try {
                    establish()
                } catch (e: Exception) {
                    rebuildFailed(e)
                    continue // the same tunnel goes on reading the old interface
                } ?: return Outcome(End.REVOKED)
                if (stopping) {
                    next.close()
                    return Outcome(End.STOPPED)
                }
                tunnel.setFd(next.fd)
                current.close()
                current = next
                failedRebuilds = 0
                onHealth(Health.PROTECTED, null)
            }
        } finally {
            current.close()
        }
    }

    private fun rebuildFailed(error: Exception) {
        failedRebuilds++
        onHealth(Health.DEGRADED, error.message ?: error.javaClass.simpleName)
        if (failedRebuilds <= MAX_RETRIES) {
            schedule(retryDelayMs(failedRebuilds)) { if (!stopping) networkChanged() }
        }
    }
}
