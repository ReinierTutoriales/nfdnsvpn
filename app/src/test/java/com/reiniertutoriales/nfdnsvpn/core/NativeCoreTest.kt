package com.reiniertutoriales.nfdnsvpn.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream

/** Runs against the host build of native/nfdns-core: checks the JNI signatures end to end. */
class NativeCoreTest {
    private fun dnsQuery(id: Int, name: String): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(byteArrayOf((id shr 8).toByte(), id.toByte(), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0))
        for (label in name.split('.')) {
            out.write(label.length)
            out.write(label.toByteArray())
        }
        out.write(byteArrayOf(0, 0, 1, 0, 1)) // root, type A, class IN
        return out.toByteArray()
    }

    /** IPv4/UDP 10.111.0.2:40000 -> 10.111.0.1:53 (checksums are not verified by the core). */
    private fun udpPacket(payload: ByteArray): ByteArray {
        val total = 28 + payload.size
        val header = byteArrayOf(
            0x45, 0, (total shr 8).toByte(), total.toByte(), 0, 0, 0x40, 0, 64, 17, 0, 0,
            10, 111, 0, 2, 10, 111, 0, 1,
            (40000 shr 8).toByte(), 40000.toByte(), 0, 53, ((8 + payload.size) shr 8).toByte(), (8 + payload.size).toByte(), 0, 0,
        )
        return header + payload
    }

    @Test
    fun blocksListedNamesAndForwardsTheRest() {
        val handle = NativeCore.nativeCreate(arrayOf("||doubleclick.net^\n", "0.0.0.0 ads.example.com\n"))
        try {
            assertEquals(2, NativeCore.nativeRuleCount(handle))

            val blocked = PacketAction.decode(NativeCore.nativeHandle(handle, udpPacket(dnsQuery(1, "pubads.g.doubleclick.net"))))
            assertTrue(blocked is PacketAction.Blocked)
            assertEquals("pubads.g.doubleclick.net", (blocked as PacketAction.Blocked).name)
            // Reply goes back from 10.111.0.1 to 10.111.0.2.
            assertArrayEquals(byteArrayOf(10, 111, 0, 1, 10, 111, 0, 2), blocked.packet.copyOfRange(12, 20))

            val query = dnsQuery(2, "example.org")
            val request = udpPacket(query)
            val forward = PacketAction.decode(NativeCore.nativeHandle(handle, request))
            assertTrue(forward is PacketAction.Forward)
            assertArrayEquals(query, (forward as PacketAction.Forward).query)

            val answer = byteArrayOf(0, 2, 0x81.toByte(), 0x80.toByte())
            val reply = NativeCore.nativeWrapReply(request, answer)
            assertArrayEquals(answer, reply.copyOfRange(28, reply.size))

            assertTrue(PacketAction.decode(NativeCore.nativeHandle(handle, byteArrayOf(1, 2, 3))) === PacketAction.Ignore)
            assertEquals(0, NativeCore.nativeWrapReply(byteArrayOf(1), answer).size)
        } finally {
            NativeCore.nativeDestroy(handle)
        }
    }
}
