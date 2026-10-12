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
    fun buildsAFilterFromFilesAndText() {
        val list = java.io.File.createTempFile("list", ".txt").apply {
            writeText("||doubleclick.net^\n0.0.0.0 ads.example.com\n||ads.example.org^\n")
            deleteOnExit()
        }
        val builder = NativeCore.nativeBuilderNew()
        assertTrue(NativeCore.nativeBuilderAddFile(builder, list.absolutePath))
        assertTrue(!NativeCore.nativeBuilderAddFile(builder, "/does/not/exist"))
        NativeCore.nativeBuilderAddText(builder, "||tracker.example.net^\n@@||ads.example.org^\n")
        val filter = NativeCore.nativeBuilderBuild(builder)
        try {
            assertEquals(4, NativeCore.nativeRuleCount(filter))
        } finally {
            NativeCore.nativeDestroy(filter)
        }
        NativeCore.nativeBuilderDestroy(NativeCore.nativeBuilderNew())
    }

    @Test
    fun tunnelLifecycleWithAnInvalidDescriptorFailsInsteadOfHanging() {
        val filter = NativeCore.nativeCreate(arrayOf("||doubleclick.net^\n"))
        val tunnel = NativeTunnel(filter, -1, listOf("10.111.0.1", "8.8.8.8", "not-an-ip"))
        try {
            tunnel.setUpstream(listOf("192.168.1.1", "2001:db8::1"))
            tunnel.setUpstream(listOf("tls://1.1.1.1#cloudflare-dns.com"))
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
    fun blockedAppsInstallTheOwnerCallback() {
        val tunnel = NativeTunnel(NativeCore.nativeCreate(arrayOf("")), -1, emptyList())
        try {
            // Finds ConnectionOwner and checks find()'s signature from native code.
            tunnel.setBlockedApps(intArrayOf(10123, 10124))
            tunnel.setBlockedApps(intArrayOf())
            tunnel.setWatchedApps(intArrayOf(10125))
            assertTrue(tunnel.appActivity(10125).isEmpty())
            tunnel.setWatchedApps(intArrayOf())
        } finally {
            tunnel.close()
        }
    }

    @Test
    fun connectionOwnerPassesAddressesAndHidesFailures() {
        try {
            ConnectionOwner.lookup = null
            assertEquals(ConnectionOwner.UNKNOWN, ConnectionOwner.find(6, byteArrayOf(10, 111, 0, 2), 40000, byteArrayOf(1, 1, 1, 1), 443))
            ConnectionOwner.lookup = { protocol, local, remote ->
                assertEquals("6 /10.111.0.2:40000 /[2001:db8:0:0:0:0:0:1]:443", "$protocol $local $remote")
                10123
            }
            val v6 = ByteArray(16).also { it[0] = 0x20; it[1] = 0x01; it[2] = 0x0d; it[3] = 0xb8.toByte(); it[15] = 1 }
            assertEquals(10123, ConnectionOwner.find(6, byteArrayOf(10, 111, 0, 2), 40000, v6, 443))
            ConnectionOwner.lookup = { _, _, _ -> throw SecurityException("not the active VPN") }
            assertEquals(ConnectionOwner.UNKNOWN, ConnectionOwner.find(17, byteArrayOf(10, 111, 0, 2), 1, byteArrayOf(1, 1, 1, 1), 2))
        } finally {
            ConnectionOwner.lookup = null
        }
    }

    @Test
    fun parsesDestinations() {
        assertEquals(
            listOf(Destination("log.app.example", false), Destination("203.0.113.5", true)),
            Destination.parse("0\tlog.app.example\n1\t203.0.113.5\n"),
        )
        assertTrue(Destination.parse("").isEmpty())
    }

    @Test
    fun parsesStats() {
        val stats = TunnelStats.parse("12,3,4,5,6,7,8\nads.example.com\ntracker.example.org")!!
        assertEquals(
            listOf(12L, 3L, 4L, 5L, 6L, 7L, 8L),
            listOf(stats.queries, stats.blocked, stats.tcp, stats.udp, stats.quicRefused, stats.dnsFailed, stats.flowsRefused),
        )
        assertEquals(listOf("ads.example.com", "tracker.example.org"), stats.recent)
        assertNull(TunnelStats.parse(""))
        assertNull(TunnelStats.parse("1,2,3,4,5,6"))
    }
}
