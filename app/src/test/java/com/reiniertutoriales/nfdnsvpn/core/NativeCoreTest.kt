package com.reiniertutoriales.nfdnsvpn.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Runs against the host build of native/nfdns-core: checks every JNI signature end to end.
 * Packet handling itself is covered by the Rust tests and scripts/e2e-linux.sh.
 */
class NativeCoreTest {
    @Test
    fun compilesListsAndCountsRules() {
        val handle = NativeCore.nativeCreate(arrayOf("||doubleclick.net^\n", "0.0.0.0 ads.example.com\n! comment\n"))
        try {
            assertEquals(2, NativeCore.nativeRuleCount(handle))
        } finally {
            NativeCore.nativeDestroy(handle)
        }
    }

    @Test
    fun tunnelLifecycleWithAnInvalidDescriptorFailsInsteadOfHanging() {
        val filter = NativeCore.nativeCreate(arrayOf("||doubleclick.net^\n"))
        val tunnel = NativeTunnel(filter, -1, listOf("10.111.0.1", "8.8.8.8", "not-an-ip"))
        try {
            tunnel.setUpstream(listOf("192.168.1.1", "2001:db8::1"))
            val stats = tunnel.stats()
            assertNotNull(stats)
            assertEquals(0L, stats!!.queries)
            assertTrue(stats.recent.isEmpty())
            val failure = tunnel.run()
            assertTrue("run() must report the bad descriptor: '$failure'", failure.isNotEmpty())
            tunnel.stop()
        } finally {
            tunnel.close()
        }
        assertNull(tunnel.stats())
        tunnel.close() // idempotent
    }

    @Test
    fun parsesStats() {
        val stats = TunnelStats.parse("12,3,4,5\nads.example.com\ntracker.example.org")!!
        assertEquals(listOf(12L, 3L, 4L, 5L), listOf(stats.queries, stats.blocked, stats.tcp, stats.udp))
        assertEquals(listOf("ads.example.com", "tracker.example.org"), stats.recent)
        assertNull(TunnelStats.parse(""))
    }
}
