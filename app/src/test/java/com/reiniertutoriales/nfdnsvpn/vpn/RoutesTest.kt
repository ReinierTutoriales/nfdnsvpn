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

    private fun network(vararg resolvers: String, ipv6: Boolean = false) =
        NetworkSnapshot.of(resolvers.map(InetAddress::getByName), ipv6)

    @Test
    fun aNewRouterResolverIsRoutedAndTheOldOneIsNot() {
        val before = Routes.forTunnel(true, network("192.168.1.1"))
        val after = Routes.forTunnel(true, network("192.168.0.1"))
        assertTrue(covers(before, "192.168.1.1"))
        assertTrue("DNS straight to the new router must be filtered", covers(after, "192.168.0.1"))
        assertFalse(covers(after, "192.168.1.1"))
        // Only the resolver itself: the rest of the LAN keeps going out directly.
        assertFalse(covers(after, "192.168.0.2"))
        assertTrue(covers(after, Routes.DNS_V4) && covers(after, "8.8.8.8"))
    }

    @Test
    fun ipv6IsRoutedOnlyWhileTheNetworkHasIt() {
        assertFalse(covers(Routes.forTunnel(true, network(ipv6 = false)), "2606:4700::6810:84e5"))
        assertTrue("IPv6 traffic must not leave unfiltered", covers(Routes.forTunnel(true, network(ipv6 = true)), "2606:4700::6810:84e5"))
        // Public resolvers' IPv6 addresses are routed either way (DNS forced into the tunnel).
        assertTrue(covers(Routes.forTunnel(true, network(ipv6 = false)), "2001:4860:4860::8888"))
        assertTrue(covers(Routes.forTunnel(true, network("fd00::1", ipv6 = true)), "fd00::1"))
    }

    @Test
    fun lightModeRoutesOnlyResolvers() {
        val routes = Routes.forTunnel(false, network("192.168.1.1", ipv6 = true))
        assertTrue(covers(routes, "192.168.1.1") && covers(routes, "1.1.1.1"))
        assertFalse(covers(routes, "93.184.216.34"))
        assertFalse(covers(routes, "2606:4700::6810:84e5"))
    }

    @Test
    fun theSameNetworkGivesAnEqualSnapshot() {
        assertEquals(network("192.168.1.1", "192.168.1.2"), network("192.168.1.2", "192.168.1.1", "192.168.1.1"))
        assertFalse(network("192.168.1.1") == network("192.168.1.1", ipv6 = true))
        // Our own virtual resolvers, link-local and loopback are not the network's.
        assertEquals(network(), network(Routes.DNS_V4, Routes.DNS_V6, "fe80::1", "127.0.0.1"))
    }
}
