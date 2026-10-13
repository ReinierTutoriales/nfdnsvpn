package com.reiniertutoriales.nfdnsvpn.vpn

import com.reiniertutoriales.nfdnsvpn.vpn.InterfaceLoop.Health.DEGRADED
import com.reiniertutoriales.nfdnsvpn.vpn.InterfaceLoop.Health.PROTECTED
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Semaphore
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread

/**
 * Deterministic: every wait is for an event (a run, a health report, a stop call), never a fixed
 * delay; retries are invoked by the test, not by a clock.
 */
class InterfaceLoopTest {
    /** Like the native tunnel: run() blocks until stop(); one stored permit, as tokio's Notify. */
    private class FakeTunnel : TunnelPort {
        private val permit = Semaphore(0)
        private val running = AtomicInteger()
        val maxConcurrentRuns = AtomicInteger()
        val fds = CopyOnWriteArrayList<Int>()
        val runs = AtomicInteger()
        val stops = AtomicInteger()

        override fun run(): String {
            maxConcurrentRuns.accumulateAndGet(running.incrementAndGet(), ::maxOf)
            runs.incrementAndGet()
            permit.acquire()
            running.decrementAndGet()
            return ""
        }

        @Synchronized override fun stop() {
            stops.incrementAndGet()
            if (permit.availablePermits() == 0) permit.release()
        }

        override fun setFd(fd: Int) {
            fds += fd
        }
    }

    private class FakeInterface(override val fd: Int, val network: Int) : VpnInterface {
        @Volatile var closed = false
        override fun close() {
            closed = true
        }
    }

    private class Harness(private val changeBeforeRun: Boolean = false) {
        val tunnel = FakeTunnel()
        @Volatile var network = 1
        val built = CopyOnWriteArrayList<FakeInterface>()
        /** Health reports and establish calls, in order. */
        val events = CopyOnWriteArrayList<String>()
        val scheduled = CopyOnWriteArrayList<Pair<Long, () -> Unit>>()
        @Volatile var onEstablish: (Harness) -> FakeInterface? = { h -> h.newInterface() }
        val initial = FakeInterface(100, 1)
        val loop = InterfaceLoop(
            tunnel,
            establish = { events += "establish"; onEstablish(this) },
            onHealth = { state, _ -> events += state.name },
            schedule = { delay, retry -> scheduled += delay to retry },
        )
        @Volatile var outcome: InterfaceLoop.Outcome? = null
        private val runner: Thread

        init {
            if (changeBeforeRun) loop.networkChanged()
            runner = thread { outcome = loop.run(initial) }
        }

        fun newInterface() = FakeInterface(101 + built.size, network).also { built += it }

        fun health() = events.filter { it != "establish" }

        fun finish(): InterfaceLoop.Outcome {
            runner.join(5000)
            return checkNotNull(outcome) { "loop did not end" }
        }
    }

    private fun awaitUntil(what: String, condition: () -> Boolean) {
        val deadline = System.currentTimeMillis() + 5000
        while (!condition()) {
            check(System.currentTimeMillis() < deadline) { "timed out waiting for $what" }
            Thread.sleep(1)
        }
    }

    @Test
    fun aNormalStartIsProtected() {
        val h = Harness()
        awaitUntil("first run") { h.tunnel.runs.get() == 1 }
        assertEquals(listOf("PROTECTED"), h.health())
        h.loop.stop()
        assertEquals(InterfaceLoop.End.STOPPED, h.finish().end)
        assertTrue(h.initial.closed)
    }

    @Test
    fun aChangeBeforeTheStartIsNeverReportedProtectedUntilApplied() {
        val h = Harness(changeBeforeRun = true)
        awaitUntil("rebuild and second run") { h.tunnel.runs.get() == 2 }
        assertEquals("degraded first, protected only once rebuilt", listOf("DEGRADED", "establish", "PROTECTED"), h.events)
        assertEquals(1, h.built.size)
        h.loop.stop()
        h.finish()
    }

    @Test
    fun aChangeDuringEstablishKeepsItDegradedUntilTheNextRebuild() {
        val h = Harness()
        val first = CountDownLatch(1)
        h.onEstablish = { harness ->
            val made = harness.newInterface()
            if (harness.built.size == 1) {
                // The network changes again while the first rebuild is establishing.
                harness.network = 3
                harness.loop.networkChanged()
                first.countDown()
            }
            made
        }
        awaitUntil("first run") { h.tunnel.runs.get() == 1 }
        h.network = 2
        h.loop.networkChanged()
        assertTrue(first.await(5, TimeUnit.SECONDS))
        awaitUntil("second rebuild in use") { h.tunnel.runs.get() == 3 }
        assertEquals(
            "no PROTECTED between the two rebuilds",
            listOf("PROTECTED", "DEGRADED", "establish", "DEGRADED", "establish", "PROTECTED"),
            h.events,
        )
        assertEquals(3, h.built.last().network)
        assertTrue(h.initial.closed && h.built.first().closed)
        assertEquals(h.built.map { it.fd }, h.tunnel.fds)
        assertEquals("never two runs at once", 1, h.tunnel.maxConcurrentRuns.get())
        h.loop.stop()
        h.finish()
    }

    @Test
    fun consecutiveChangesWhileEstablishingEndOnTheLatestNetwork() {
        val h = Harness()
        val inEstablish = CountDownLatch(1)
        val release = CountDownLatch(1)
        h.onEstablish = { harness ->
            // The network as establish reads it when it starts.
            val seen = harness.network
            if (harness.built.isEmpty()) {
                inEstablish.countDown()
                release.await(5, TimeUnit.SECONDS)
            }
            FakeInterface(101 + harness.built.size, seen).also { harness.built += it }
        }
        awaitUntil("first run") { h.tunnel.runs.get() == 1 }
        h.network = 2
        h.loop.networkChanged()
        assertTrue(inEstablish.await(5, TimeUnit.SECONDS))
        // Two more changes while the first rebuild is still establishing.
        h.network = 3
        h.loop.networkChanged()
        h.network = 4
        h.loop.networkChanged()
        release.countDown()
        awaitUntil("protected again") { h.health().last() == "PROTECTED" && h.tunnel.runs.get() == 3 }
        assertEquals("exactly one more rebuild, on the latest network", listOf(2, 4), h.built.map { it.network })
        h.loop.stop()
        h.finish()
    }

    @Test
    fun aFailedRebuildKeepsTheOldInterfaceDegradedAndRetries() {
        val h = Harness()
        h.onEstablish = { throw IllegalStateException("route refused") }
        awaitUntil("first run") { h.tunnel.runs.get() == 1 }
        h.loop.networkChanged()
        awaitUntil("run on the old interface") { h.tunnel.runs.get() == 2 }
        assertFalse("the interface Android kept is not closed", h.initial.closed)
        assertTrue("the tunnel keeps reading it", h.tunnel.fds.isEmpty())
        assertEquals(listOf("PROTECTED", "DEGRADED", "DEGRADED"), h.health())
        assertEquals(1000L, h.scheduled.single().first)

        h.onEstablish = { harness -> harness.newInterface() }
        h.scheduled.single().second()
        awaitUntil("protected again") { h.health().last() == "PROTECTED" }
        assertTrue(h.initial.closed)
        h.loop.stop()
        h.finish()
    }

    @Test
    fun aRetryAfterProtectionWasRestoredDoesNothing() {
        val h = Harness()
        h.onEstablish = { throw IllegalStateException("route refused") }
        awaitUntil("first run") { h.tunnel.runs.get() == 1 }
        h.loop.networkChanged()
        awaitUntil("retry scheduled") { h.scheduled.size == 1 }
        // Protection comes back through a later network change, not through the retry.
        h.onEstablish = { harness -> harness.newInterface() }
        h.loop.networkChanged()
        awaitUntil("protected again") { h.health().last() == "PROTECTED" }
        val stops = h.tunnel.stops.get()
        h.scheduled.single().second() // the old retry fires late
        assertEquals("it must not stop the tunnel and cut connections", stops, h.tunnel.stops.get())
        assertEquals(1, h.built.size)
        h.loop.stop()
        h.finish()
    }

    @Test
    fun anOlderRetryIsSupersededByANewerOne() {
        val h = Harness()
        h.onEstablish = { throw IllegalStateException("route refused") }
        awaitUntil("first run") { h.tunnel.runs.get() == 1 }
        h.loop.networkChanged()
        awaitUntil("first retry") { h.scheduled.size == 1 }
        h.loop.networkChanged()
        awaitUntil("second retry") { h.scheduled.size == 2 }
        val stops = h.tunnel.stops.get()
        h.scheduled[0].second()
        assertEquals("the older retry does nothing", stops, h.tunnel.stops.get())
        h.scheduled[1].second()
        assertEquals("the newer one rebuilds", stops + 1, h.tunnel.stops.get())
        h.loop.stop()
        h.finish()
    }

    @Test
    fun aRetryAfterTheLoopEndedDoesNothing() {
        val h = Harness()
        h.onEstablish = { throw IllegalStateException("route refused") }
        awaitUntil("first run") { h.tunnel.runs.get() == 1 }
        h.loop.networkChanged()
        awaitUntil("retry scheduled") { h.scheduled.size == 1 }
        h.loop.stop()
        h.finish()
        val stops = h.tunnel.stops.get()
        val events = h.events.size
        h.scheduled.single().second()
        assertEquals(stops, h.tunnel.stops.get())
        assertEquals("no health report after the end", events, h.events.size)
    }

    @Test
    fun retriesAreLimited() {
        val h = Harness()
        h.onEstablish = { throw IllegalStateException("route refused") }
        awaitUntil("first run") { h.tunnel.runs.get() == 1 }
        h.loop.networkChanged()
        // Each retry fails again; after the last allowed one, no further retry is scheduled.
        for (attempt in 1..InterfaceLoop.MAX_RETRIES) {
            awaitUntil("retry $attempt") { h.scheduled.size == attempt && h.tunnel.runs.get() == attempt + 1 }
            h.scheduled[attempt - 1].second()
        }
        // The failure after the last retry is reported before the tunnel runs again.
        awaitUntil("run after the last failure") { h.tunnel.runs.get() == InterfaceLoop.MAX_RETRIES + 2 }
        assertEquals(InterfaceLoop.MAX_RETRIES, h.scheduled.size)
        assertEquals(listOf(1000L, 2000L, 4000L, 8000L, 16000L), h.scheduled.map { it.first })
        assertTrue(h.health().drop(1).all { it == "DEGRADED" })
        h.loop.stop()
        h.finish()
    }

    @Test
    fun revokedConsentEndsTheLoopAndClosesEverything() {
        val h = Harness()
        h.onEstablish = { null }
        awaitUntil("first run") { h.tunnel.runs.get() == 1 }
        h.loop.networkChanged()
        assertEquals(InterfaceLoop.End.REVOKED, h.finish().end)
        assertTrue(h.initial.closed)
    }

    @Test
    fun stopDuringASubstitutionClosesTheNewInterfaceUnused() {
        val h = Harness()
        h.onEstablish = { harness ->
            harness.loop.stop()
            harness.newInterface()
        }
        awaitUntil("first run") { h.tunnel.runs.get() == 1 }
        h.loop.networkChanged()
        assertEquals(InterfaceLoop.End.STOPPED, h.finish().end)
        assertTrue("the new interface is closed", h.built.single().closed)
        assertTrue("and never read", h.tunnel.fds.isEmpty())
        assertTrue(h.initial.closed)
    }
}
