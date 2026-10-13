package com.reiniertutoriales.nfdnsvpn.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Semaphore
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread

class InterfaceLoopTest {
    /** Like the native tunnel: run() blocks until stop(); one stored permit, as tokio's Notify. */
    private class FakeTunnel : TunnelPort {
        private val permit = Semaphore(0)
        private val running = AtomicInteger()
        val maxConcurrentRuns = AtomicInteger()
        val fds = CopyOnWriteArrayList<Int>()
        val runs = AtomicInteger()

        override fun run(): String {
            maxConcurrentRuns.accumulateAndGet(running.incrementAndGet(), ::maxOf)
            runs.incrementAndGet()
            permit.acquire()
            running.decrementAndGet()
            return ""
        }

        @Synchronized override fun stop() {
            if (permit.availablePermits() == 0) permit.release()
        }

        override fun setFd(fd: Int) {
            fds += fd
        }

        fun awaitRuns(count: Int) {
            val deadline = System.currentTimeMillis() + 5000
            while (runs.get() < count) {
                check(System.currentTimeMillis() < deadline) { "tunnel did not run $count times" }
                Thread.sleep(5)
            }
        }
    }

    private class FakeInterface(override val fd: Int, val network: Int) : VpnInterface {
        @Volatile var closed = false
        override fun close() {
            closed = true
        }
    }

    private class Harness {
        val tunnel = FakeTunnel()
        @Volatile var network = 1
        val built = CopyOnWriteArrayList<FakeInterface>()
        val health = CopyOnWriteArrayList<InterfaceLoop.Health>()
        val scheduled = CopyOnWriteArrayList<Pair<Long, () -> Unit>>()
        @Volatile var onEstablish: (Harness) -> FakeInterface? = { h -> h.newInterface() }
        val initial = FakeInterface(100, 1)
        val loop = InterfaceLoop(
            tunnel,
            establish = { onEstablish(this) },
            onHealth = { state, _ -> health += state },
            schedule = { delay, retry -> scheduled += delay to retry },
        )
        @Volatile var outcome: InterfaceLoop.Outcome? = null
        private val runner = thread { outcome = loop.run(initial) }

        fun newInterface() = FakeInterface(101 + built.size, network).also { built += it }

        fun finish(): InterfaceLoop.Outcome {
            runner.join(5000)
            return checkNotNull(outcome) { "loop did not end" }
        }
    }

    @Test
    fun consecutiveChangesEndOnTheLatestNetwork() {
        val h = Harness()
        h.tunnel.awaitRuns(1)
        h.network = 2
        h.loop.networkChanged()
        h.network = 3
        h.loop.networkChanged()
        h.tunnel.awaitRuns(2)
        Thread.sleep(50) // a second rebuild, if one is due, gets its turn
        val current = h.built.last()
        assertEquals("the last change is the one in use", 3, current.network)
        assertTrue("the first interface is closed once replaced", h.initial.closed)
        assertTrue("replaced interfaces are closed", h.built.dropLast(1).all { it.closed })
        assertFalse(current.closed)
        assertEquals(h.built.map { it.fd }, h.tunnel.fds)
        assertEquals("never two runs at once", 1, h.tunnel.maxConcurrentRuns.get())
        h.loop.stop()
        assertEquals(InterfaceLoop.End.STOPPED, h.finish().end)
        assertTrue(current.closed)
    }

    @Test
    fun aChangeDuringEstablishTriggersAnotherRebuild() {
        val h = Harness()
        h.onEstablish = { harness ->
            val made = harness.newInterface()
            if (harness.built.size == 1) {
                // The network changes again while the first rebuild is establishing.
                harness.network = 3
                harness.loop.networkChanged()
            }
            made
        }
        h.tunnel.awaitRuns(1)
        h.network = 2
        h.loop.networkChanged()
        h.tunnel.awaitRuns(3)
        assertEquals("two rebuilds", 2, h.built.size)
        assertEquals("the second one sees the latest network", 3, h.built.last().network)
        h.loop.stop()
        h.finish()
    }

    @Test
    fun aFailedRebuildKeepsTheOldInterfaceDegradedAndRetries() {
        val h = Harness()
        h.onEstablish = { throw IllegalStateException("route refused") }
        h.tunnel.awaitRuns(1)
        h.loop.networkChanged()
        h.tunnel.awaitRuns(2)
        assertFalse("the interface Android kept is not closed", h.initial.closed)
        assertTrue("the tunnel keeps reading it", h.tunnel.fds.isEmpty())
        assertEquals(listOf(InterfaceLoop.Health.DEGRADED), h.health)
        assertEquals(1000L, h.scheduled.single().first)

        // The retry succeeds: protected again on the new interface.
        h.onEstablish = { harness -> harness.newInterface() }
        h.scheduled.single().second()
        h.tunnel.awaitRuns(3)
        assertEquals(listOf(InterfaceLoop.Health.DEGRADED, InterfaceLoop.Health.PROTECTED), h.health)
        assertTrue(h.initial.closed)
        h.loop.stop()
        h.finish()
    }

    @Test
    fun retriesAreLimited() {
        val h = Harness()
        h.onEstablish = { throw IllegalStateException("route refused") }
        h.tunnel.awaitRuns(1)
        h.loop.networkChanged()
        // Each retry fails again; after the last allowed one, no further retry is scheduled.
        for (attempt in 1..InterfaceLoop.MAX_RETRIES) {
            h.tunnel.awaitRuns(attempt + 1)
            h.scheduled[attempt - 1].second()
        }
        h.tunnel.awaitRuns(InterfaceLoop.MAX_RETRIES + 2)
        Thread.sleep(50)
        assertEquals(InterfaceLoop.MAX_RETRIES, h.scheduled.size)
        assertEquals(listOf(1000L, 2000L, 4000L, 8000L, 16000L), h.scheduled.map { it.first })
        assertTrue(h.health.all { it == InterfaceLoop.Health.DEGRADED })
        h.loop.stop()
        h.finish()
    }

    @Test
    fun revokedConsentEndsTheLoopAndClosesEverything() {
        val h = Harness()
        h.onEstablish = { null }
        h.tunnel.awaitRuns(1)
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
        h.tunnel.awaitRuns(1)
        h.loop.networkChanged()
        assertEquals(InterfaceLoop.End.STOPPED, h.finish().end)
        assertTrue("the new interface is closed", h.built.single().closed)
        assertTrue("and never read", h.tunnel.fds.isEmpty())
        assertTrue(h.initial.closed)
    }

    @Test
    fun aChangeBeforeTheRunStartsIsNotLost() {
        val tunnel = FakeTunnel()
        val built = CopyOnWriteArrayList<FakeInterface>()
        val loop = InterfaceLoop(tunnel, { FakeInterface(200, 2).also { built += it } }, { _, _ -> }, { _, _ -> })
        loop.networkChanged() // before run(): stop() has nothing to stop yet
        val runner = thread { loop.run(FakeInterface(100, 1)) }
        tunnel.awaitRuns(2)
        assertEquals(1, built.size)
        loop.stop()
        runner.join(TimeUnit.SECONDS.toMillis(5))
    }
}
