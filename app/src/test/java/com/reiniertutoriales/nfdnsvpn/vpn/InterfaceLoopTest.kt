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
        /** Called inside the loop's health report (that is, with its lock held). */
        @Volatile var onReport: (String) -> Unit = {}
        @Volatile var onEstablish: (Harness) -> FakeInterface? = { h -> h.newInterface() }
        val initial = FakeInterface(100, 1)
        val loop = InterfaceLoop(
            tunnel,
            establish = { events += "establish"; onEstablish(this) },
            onHealth = { state, _ -> events += state.name; onReport(state.name) },
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
        // The pending change is applied before the tunnel ever runs on the stale interface.
        awaitUntil("rebuild, then the first run") { h.tunnel.runs.get() == 1 }
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
        // The pending change is rebuilt at once, without running on the half-updated interface.
        awaitUntil("second rebuild in use") { h.tunnel.runs.get() == 2 }
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
        awaitUntil("protected again") { h.health().last() == "PROTECTED" && h.tunnel.runs.get() == 2 }
        assertEquals("changes while not running stop nothing", 1, h.tunnel.stops.get())
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

    @Test
    fun aRetryHeldWhileProtectionIsRestoredDoesNothingWhenReleased() {
        val h = Harness()
        h.onEstablish = { throw IllegalStateException("route refused") }
        awaitUntil("first run") { h.tunnel.runs.get() == 1 }
        h.loop.networkChanged()
        awaitUntil("retry scheduled") { h.scheduled.size == 1 }

        // Protection is being restored: the recovery holds the loop's lock (its report blocks).
        val inRecovery = CountDownLatch(1)
        val finishRecovery = CountDownLatch(1)
        h.onReport = { state ->
            if (state == "PROTECTED") {
                inRecovery.countDown()
                finishRecovery.await(5, TimeUnit.SECONDS)
            }
        }
        h.onEstablish = { harness -> harness.newInterface() }
        h.loop.networkChanged()
        assertTrue(inRecovery.await(5, TimeUnit.SECONDS))
        // The old retry fires now: it cannot validate its token until the recovery is done.
        val retry = thread { h.scheduled.single().second() }
        awaitUntil("retry waiting for the recovery") { retry.state == Thread.State.BLOCKED }
        val stops = h.tunnel.stops.get()
        finishRecovery.countDown()
        retry.join(5000)
        assertEquals("no cut", stops, h.tunnel.stops.get())
        assertEquals("no extra rebuild", 1, h.built.size)
        assertEquals("still protected", "PROTECTED", h.health().last())
        h.loop.stop()
        h.finish()
    }

    @Test
    fun aStopSignalWithNothingToApplyNeverEndsTheLoop() {
        val h = Harness()
        awaitUntil("first run") { h.tunnel.runs.get() == 1 }
        h.loop.networkChanged()
        awaitUntil("rebuilt and running") { h.tunnel.runs.get() == 2 && h.health().last() == "PROTECTED" }
        // A stop signal arriving late, after its change was already applied.
        h.tunnel.stop()
        awaitUntil("running again") { h.tunnel.runs.get() == 3 }
        assertEquals("the loop goes on", null, h.outcome)
        assertEquals("nothing rebuilt for it", 1, h.built.size)
        assertEquals("still protected", "PROTECTED", h.health().last())
        h.loop.stop()
        assertEquals(InterfaceLoop.End.STOPPED, h.finish().end)
    }

    @Test
    fun aStopHeldWhileTheChangeIsSignalledIsTheOnlyOne() {
        val h = Harness()
        awaitUntil("first run") { h.tunnel.runs.get() == 1 }
        // The first change's signal is held inside the loop's lock, before its stop. While it is
        // held, the loop cannot consume the change, and a second change made at that point (the
        // first still pending) adds no stop of its own.
        val stopsWhileHeld = AtomicInteger(-1)
        val runsWhileHeld = AtomicInteger(-1)
        h.onReport = { state ->
            if (state == "DEGRADED" && stopsWhileHeld.get() == -1) {
                stopsWhileHeld.set(h.tunnel.stops.get())
                h.loop.networkChanged() // same thread, lock is reentrant: the first is still pending
                runsWhileHeld.set(h.tunnel.runs.get())
            }
        }
        h.loop.networkChanged()
        assertEquals("nothing stopped while held", 0, stopsWhileHeld.get())
        assertEquals("the loop did not move while held", 1, runsWhileHeld.get())
        awaitUntil("rebuilt and running") { h.tunnel.runs.get() == 2 && h.health().last() == "PROTECTED" }
        assertEquals("one stop for both changes", 1, h.tunnel.stops.get())
        assertEquals("one rebuild", 1, h.built.size)
        assertEquals("the loop goes on", null, h.outcome)
        h.loop.stop()
        h.finish()
    }
}
