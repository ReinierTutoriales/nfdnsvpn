package com.reiniertutoriales.nfdnsvpn.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger
import java.net.InetAddress

class RoutesTest {
    private fun value(address: String) = BigInteger(1, InetAddress.getByName(address).address)

    private fun covers(routes: List<Cidr>, address: String): Boolean {
        val target = value(address)
        return routes.any { route ->
            val shift = route.bits - route.prefix
            BigInteger(1, route.address.address).shiftRight(shift) == target.shiftRight(shift)
        }
    }

    @Test
    fun fullTunnelCoversInternetButNotLocalRanges() {
        val routes = Routes.fullV4
        for (internet in listOf("1.1.1.1", "8.8.8.8", "93.184.216.34", "100.64.0.1", "172.32.0.1", "223.255.255.255", "11.0.0.1")) {
            assertTrue("$internet must be tunnelled", covers(routes, internet))
        }
        for (local in listOf("10.0.0.1", "10.111.0.1", "192.168.1.1", "172.16.5.5", "172.31.255.255", "169.254.1.1", "224.0.0.251", "239.255.255.250", "255.255.255.255", "127.0.0.1", "0.0.0.0")) {
            assertFalse("$local must stay outside", covers(routes, local))
        }
    }

    @Test
    fun complementIsExactAndCompact() {
        val routes = Routes.fullV4
        // Total size equals 2^32 minus the excluded blocks (they do not overlap).
        val total = routes.fold(BigInteger.ZERO) { sum, r -> sum + BigInteger.ONE.shiftLeft(32 - r.prefix) }
        val excluded = Routes.EXCLUDED_V4.fold(BigInteger.ZERO) { sum, r -> sum + BigInteger.ONE.shiftLeft(32 - r.prefix) }
        assertEquals(BigInteger.ONE.shiftLeft(32) - excluded, total)
        // Each excluded block splits its neighbours once per prefix bit: about 46 blocks here,
        // far below what VpnService.Builder accepts.
        assertTrue("${routes.size} routes", routes.size <= 64)
    }

    @Test
    fun complementOfNothingIsTheWhole() {
        assertEquals(listOf(Cidr.parse("0.0.0.0/0")), Routes.complement(Cidr.parse("0.0.0.0/0"), emptyList()))
        assertEquals(
            listOf(Cidr.parse("128.0.0.0/1")),
            Routes.complement(Cidr.parse("0.0.0.0/0"), listOf(Cidr.parse("0.0.0.0/1"))),
        )
    }
}
