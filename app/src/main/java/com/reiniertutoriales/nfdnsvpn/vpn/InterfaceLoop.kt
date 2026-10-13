package com.reiniertutoriales.nfdnsvpn.vpn

import java.io.Closeable

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
 * - Health is [Health.PROTECTED] only while the interface in use was built for the latest change
 *   reported: a change sets [Health.DEGRADED] at once, until an interface built after it is in use.
 * - The new interface exists before the old one is closed, and only one tunnel run is active.
 * - A rebuild that fails (establish throws, e.g. a route refused) keeps the old interface: Android
 *   keeps it when it cannot create the new one, and closing it could send traffic around the
 *   filter. Its routes may be stale, so health is [Health.DEGRADED] (never "protected") while a
 *   limited number of retries with growing delays runs; a later network change retries too. A
 *   retry no longer due (protection restored, a newer retry, the loop ended) does nothing.
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
        /** Why health is degraded while the interface for a new network is being built. */
        const val PENDING = "la red cambió; actualizando rutas"

        /** Automatic retries after a failed rebuild: 1, 2, 4, 8 and 16 s, then only on change. */
        const val MAX_RETRIES = 5
        fun retryDelayMs(attempt: Int) = 1000L shl (attempt - 1)
    }

    @Volatile private var stopping = false

    /**
     * Guards the pending change, whether the tunnel is running and the stop signal, together with
     * health and retries: a change, a retry and a recovery are each decided and carried out
     * inside it, so none can act on a state another has already moved past.
     */
    private val lock = Any()
    /** A change not yet consumed by a rebuild. */
    private var rebuild = false
    /** The tunnel is (about to be) running and only a stop() makes it return. */
    private var inRun = false
    private var failedRebuilds = 0
    /**
     * Only the retry holding the current token may fire. It changes when a rebuild succeeds,
     * when another retry is scheduled and when the loop ends, so a retry left from an older
     * failure never cuts connections after protection was restored.
     */
    private var retryToken = 0L

    /** From any thread: the network changed. Not protected until an interface for it is in use. */
    fun networkChanged() {
        synchronized(lock) { changed() }
    }

    /**
     * With [lock] held. The tunnel is stopped only for the first change while it runs: a stop
     * for a change that is already pending, or while no run is going on, would be left over
     * and end a later run with nothing to apply.
     */
    private fun changed() {
        val alreadyPending = rebuild
        rebuild = true
        onHealth(Health.DEGRADED, PENDING)
        if (inRun && !alreadyPending) tunnel.stop()
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
            // Protected only if no change came in since [initial] was established (start included).
            synchronized(lock) {
                if (!rebuild) onHealth(Health.PROTECTED, null)
            }
            while (true) {
                // Either a change is already pending (rebuild now), or run until one arrives.
                val pending = synchronized(lock) {
                    if (rebuild) {
                        rebuild = false
                        true
                    } else {
                        inRun = true
                        false
                    }
                }
                if (!pending) {
                    val failure = tunnel.run()
                    val changedMeanwhile = synchronized(lock) {
                        inRun = false
                        rebuild.also { rebuild = false }
                    }
                    if (stopping) return Outcome(End.STOPPED)
                    if (!changedMeanwhile) {
                        if (failure.isNotEmpty()) return Outcome(End.FAILED, failure)
                        continue // a wake with nothing to apply never ends the loop
                    }
                }
                if (stopping) return Outcome(End.STOPPED)
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
                synchronized(lock) {
                    failedRebuilds = 0
                    retryToken++
                    // Another change came in during establish: its routes are still to be applied.
                    if (!rebuild) onHealth(Health.PROTECTED, null)
                }
            }
        } finally {
            synchronized(lock) { retryToken++ }
            current.close()
        }
    }

    private fun rebuildFailed(error: Exception) {
        synchronized(lock) {
            failedRebuilds++
            onHealth(Health.DEGRADED, error.message ?: error.javaClass.simpleName)
            if (failedRebuilds <= MAX_RETRIES) {
                val token = ++retryToken
                schedule(retryDelayMs(failedRebuilds)) { retry(token) }
            }
        }
    }

    /** Validating the token and acting on it are one step: no recovery or end can come between. */
    private fun retry(token: Long) {
        synchronized(lock) {
            if (stopping || token != retryToken) return
            changed()
        }
    }
}
