package com.reiniertutoriales.nfdnsvpn.vpn

import java.math.BigInteger
import java.net.InetAddress

/** An address block, e.g. 10.0.0.0/8. */
data class Cidr(val address: InetAddress, val prefix: Int) {
    val bits get() = address.address.size * 8

    override fun toString() = "${address.hostAddress}/$prefix"

    companion object {
        fun parse(text: String): Cidr {
            val (address, prefix) = text.split('/')
            return Cidr(InetAddress.getByName(address), prefix.toInt())
        }
    }
}

/**
 * Routes of the full tunnel: everything except local and multicast ranges. LAN traffic (casting,
 * discovery, media servers) carries no ads and breaks easily, so it keeps going out directly.
 * Android only accepts routes to add, not to exclude before API 33, hence the complement.
 */
object Routes {
    const val CLIENT_V4 = "10.111.0.2"
    const val DNS_V4 = "10.111.0.1"
    const val CLIENT_V6 = "fd00:6e66::2"
    const val DNS_V6 = "fd00:6e66::1"

    /** Google, Cloudflare, Quad9, OpenDNS and AdGuard: plain DNS, DoT and DoH endpoints. */
    private val PUBLIC_RESOLVERS_V4 = listOf(
        "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112",
        "208.67.222.222", "208.67.220.220", "94.140.14.14", "94.140.15.15",
    )
    private val PUBLIC_RESOLVERS_V6 = listOf(
        "2001:4860:4860::8888", "2001:4860:4860::8844", "2606:4700:4700::1111", "2606:4700:4700::1001",
        "2620:fe::fe", "2620:fe::9", "2620:119:35::35", "2620:119:53::53",
    )

    /** Resolver addresses whose non-DNS traffic (DoH, QUIC) is refused by the core. */
    val INTERCEPTED = listOf(DNS_V4, DNS_V6) + PUBLIC_RESOLVERS_V4 + PUBLIC_RESOLVERS_V6

    private val virtualAddresses = listOf(DNS_V4, DNS_V6, CLIENT_V4, CLIENT_V6).map(InetAddress::getByName)

    fun isVirtualAddress(address: InetAddress) = address in virtualAddresses

    /** A route that could not be added: the interface would leave some traffic unfiltered. */
    class IncompleteRoutes(val route: Cidr, cause: Throwable) : Exception("No se pudo enrutar $route: ${cause.message}", cause)

    /**
     * Adds every route through [add], or throws [IncompleteRoutes] at the first that fails. All of
     * them are mandatory: each one either keeps DNS in the filter (virtual, public and network
     * resolvers) or carries traffic that must be filtered. An interface missing one would show
     * protection while letting part of the traffic out, so none is created.
     */
    fun install(routes: List<Cidr>, add: (Cidr) -> Unit) {
        for (route in routes) {
            try {
                add(route)
            } catch (e: RuntimeException) {
                throw IncompleteRoutes(route, e)
            }
        }
    }

    /**
     * Every route of the interface for this network: our virtual resolvers, the public ones, the
     * network's own resolvers (on the LAN, which the full tunnel leaves out: only those addresses
     * are routed, so DNS sent straight to the router is filtered) and, in full mode, everything
     * else except LAN and multicast, IPv6 only if the network has it (otherwise apps would try
     * IPv6 first and fail).
     */
    fun forTunnel(fullTunnel: Boolean, network: NetworkSnapshot): List<Cidr> {
        val hosts = (listOf(DNS_V4, DNS_V6) + PUBLIC_RESOLVERS_V4 + PUBLIC_RESOLVERS_V6).map(InetAddress::getByName) + network.resolvers
        val routes = hosts.map { Cidr(it, it.address.size * 8) }.toMutableList()
        if (fullTunnel) {
            routes += fullV4
            if (network.hasIpv6) routes += FULL_V6
        }
        return routes.distinct()
    }

    val EXCLUDED_V4 = listOf(
        "0.0.0.0/8", "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16",
        "224.0.0.0/3", // multicast and reserved, including the broadcast address
    ).map(Cidr::parse)

    /** Only global unicast is routed; ULA, link-local and multicast stay outside. */
    val FULL_V6 = listOf(Cidr.parse("2000::/3"))

    val fullV4: List<Cidr> by lazy { complement(Cidr.parse("0.0.0.0/0"), EXCLUDED_V4) }

    /** Smallest set of blocks covering [whole] minus [excluded]. */
    fun complement(whole: Cidr, excluded: List<Cidr>): List<Cidr> {
        val result = mutableListOf<Cidr>()
        fun visit(start: BigInteger, prefix: Int) {
            val block = Range(start, prefix, whole.bits)
            val overlapping = excluded.map { Range(it, whole.bits) }.filter { it.overlaps(block) }
            when {
                overlapping.isEmpty() -> result += block.toCidr()
                overlapping.any { it.contains(block) } -> Unit
                else -> {
                    val half = BigInteger.ONE.shiftLeft(whole.bits - prefix - 1)
                    visit(start, prefix + 1)
                    visit(start + half, prefix + 1)
                }
            }
        }
        visit(Range(whole, whole.bits).start, whole.prefix)
        return result
    }

    private class Range(val start: BigInteger, val prefix: Int, val bits: Int) {
        constructor(cidr: Cidr, bits: Int) : this(
            BigInteger(1, cidr.address.address).shiftRight(bits - cidr.prefix).shiftLeft(bits - cidr.prefix),
            cidr.prefix,
            bits,
        )

        val end: BigInteger = start + BigInteger.ONE.shiftLeft(bits - prefix) - BigInteger.ONE

        fun overlaps(other: Range) = start <= other.end && other.start <= end
        fun contains(other: Range) = start <= other.start && other.end <= end

        fun toCidr(): Cidr {
            val bytes = start.toByteArray().takeLast(bits / 8).toByteArray()
            val padded = ByteArray(bits / 8 - bytes.size) + bytes
            return Cidr(InetAddress.getByAddress(padded), prefix)
        }
    }
}
