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
