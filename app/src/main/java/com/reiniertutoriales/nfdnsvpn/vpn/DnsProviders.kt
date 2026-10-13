package com.reiniertutoriales.nfdnsvpn.vpn

/**
 * Resolvers for every allowed query of the device, always over TLS (DNS over TLS, port 853): the
 * network, the router and the ISP can neither read nor rewrite them, and are never asked. There
 * is no fallback to plain DNS. Filtering stays on the device; only allowed names go out.
 */
object DnsProviders {
    /** Two independent companies: if one is down or blocked, the other answers, still encrypted. */
    const val DEFAULT = "quad9-cloudflare"
    const val CUSTOM = "custom"

    class Provider(val id: String, val name: String, val servers: List<String>)

    /** IPv4 addresses (reachable on any network) and the name their certificate carries. */
    val ALL = listOf(
        Provider(DEFAULT, "Quad9 + Cloudflare (recomendado)", tls("dns.quad9.net", "9.9.9.9") + tls("cloudflare-dns.com", "1.1.1.1") + tls("dns.quad9.net", "149.112.112.112") + tls("cloudflare-dns.com", "1.0.0.1")),
        Provider("cloudflare", "Cloudflare", tls("cloudflare-dns.com", "1.1.1.1", "1.0.0.1")),
        Provider("cloudflare-security", "Cloudflare + bloqueo de malware", tls("security.cloudflare-dns.com", "1.1.1.2", "1.0.0.2")),
        Provider("quad9", "Quad9 (bloquea malware)", tls("dns.quad9.net", "9.9.9.9", "149.112.112.112")),
        Provider("adguard", "AdGuard (bloquea anuncios)", tls("dns.adguard-dns.com", "94.140.14.14", "94.140.15.15")),
        Provider("mullvad", "Mullvad (bloquea anuncios y rastreadores)", tls("adblock.dns.mullvad.net", "194.242.2.3")),
        Provider("google", "Google", tls("dns.google", "8.8.8.8", "8.8.4.4")),
    )

    private fun tls(name: String, vararg addresses: String) = addresses.map { "tls://$it#$name" }

    /** Most resolvers in a custom list; the core's `MAX_DOT_SERVERS` (why: see there). */
    const val MAX_SERVERS = 8

    /** Longest custom list, in UTF-8 bytes; the core's `MAX_DOT_LIST_LEN`. */
    const val MAX_LENGTH = 1024

    private const val SCHEME = "tls://"
    private const val DOT_PORT = 853

    /** Why a custom list is refused; the same reasons as the core's `DotListError`. */
    enum class Reason { TOO_LONG, EMPTY, TOO_MANY, FORMAT, ADDRESS, PORT, NAME, DUPLICATE }

    sealed interface Validation {
        /** The entries as they will be used and shown: trimmed, empty ones left out. */
        data class Valid(val servers: List<String>) : Validation

        /** [entry]: position of the first bad entry, from 1; 0 when the list as a whole is refused. */
        data class Invalid(val reason: Reason, val entry: Int = 0) : Validation
    }

    /**
     * A custom list, all valid or refused whole, with the core's rules (`parse_dot_list`;
     * `testdata/dot-lists.txt` holds the cases both must agree on): comma-separated
     * `tls://address[:port]#name`, the address an IPv4 or bracketed IPv6 literal that can be a
     * resolver (names are never resolved), the port 1 to 65535 (853 if left out) and the name the
     * one in the resolver's certificate. Valid syntax does not mean the resolver answers.
     */
    fun validate(text: String): Validation {
        if (text.length > MAX_LENGTH || text.toByteArray(Charsets.UTF_8).size > MAX_LENGTH) return Validation.Invalid(Reason.TOO_LONG)
        val entries = text.split(',').map { it.trim(' ', '\t') }.filter(String::isNotEmpty)
        if (entries.isEmpty()) return Validation.Invalid(Reason.EMPTY)
        if (entries.size > MAX_SERVERS) return Validation.Invalid(Reason.TOO_MANY)
        val seen = mutableSetOf<String>()
        for ((index, entry) in entries.withIndex()) {
            when (val parsed = parseEntry(entry)) {
                is Entry.Bad -> return Validation.Invalid(parsed.reason, index + 1)
                is Entry.Good -> if (!seen.add(parsed.destination)) return Validation.Invalid(Reason.DUPLICATE, index + 1)
            }
        }
        return Validation.Valid(entries)
    }

    /** The list, or null if [validate] refuses it. */
    fun parseCustom(text: String): List<String>? = (validate(text) as? Validation.Valid)?.servers

    private sealed interface Entry {
        /** [destination]: address and port, comparable between entries. */
        data class Good(val destination: String) : Entry

        data class Bad(val reason: Reason) : Entry
    }

    /** One `tls://address[:port]#name` entry, checked in the core's order. */
    private fun parseEntry(entry: String): Entry {
        if (!entry.startsWith(SCHEME)) return Entry.Bad(Reason.FORMAT)
        val rest = entry.substring(SCHEME.length)
        val hash = rest.indexOf('#')
        if (hash <= 0) return Entry.Bad(Reason.FORMAT)
        val (ip, portText) = splitHostPort(rest.substring(0, hash)) ?: return Entry.Bad(Reason.ADDRESS)
        if (ip == null || !usableResolver(ip)) return Entry.Bad(Reason.ADDRESS)
        val port = if (portText == null) DOT_PORT else parsePort(portText) ?: return Entry.Bad(Reason.PORT)
        if (!validTlsName(rest.substring(hash + 1))) return Entry.Bad(Reason.NAME)
        return Entry.Good(ip.joinToString(".") + "/" + port)
    }

    /** As the core's `split_host_port`: the address bytes (null if not a literal) and the port text. */
    private fun splitHostPort(address: String): Pair<ByteArray?, String?>? {
        if (address.startsWith('[')) {
            val close = address.indexOf(']')
            if (close < 0) return null
            val after = address.substring(close + 1)
            val port = when {
                after.isEmpty() -> null
                after.startsWith(':') -> after.substring(1)
                else -> "" // anything else after the brackets: a bad port
            }
            return parseIpv6(address.substring(1, close)) to port
        }
        val colon = address.indexOf(':')
        return if (colon < 0) parseIpv4(address) to null else parseIpv4(address.substring(0, colon)) to address.substring(colon + 1)
    }

    /** Dotted quad, each part 0 to 255 without leading zeros (as Rust's `Ipv4Addr`). */
    private fun parseIpv4(text: String): ByteArray? {
        val parts = text.split('.')
        if (parts.size != 4) return null
        val bytes = ByteArray(4)
        for ((i, part) in parts.withIndex()) {
            if (part.length !in 1..3 || !part.all(::isDigit) || (part.length > 1 && part[0] == '0')) return null
            val value = part.toInt()
            if (value > 255) return null
            bytes[i] = value.toByte()
        }
        return bytes
    }

    /**
     * As Rust's `Ipv6Addr`: groups of 1 to 4 hex digits, one `::` standing for at least one
     * group, an IPv4 tail counting as two, no zone.
     */
    private fun parseIpv6(text: String): ByteArray? {
        val halves = text.split("::")
        if (halves.size > 2) return null
        val head = ipv6Groups(halves[0], ipv4Tail = halves.size == 1) ?: return null
        val groups = if (halves.size == 1) {
            head.takeIf { it.size == 8 } ?: return null
        } else {
            val tail = ipv6Groups(halves[1], ipv4Tail = true) ?: return null
            if (head.size + tail.size > 7) return null
            head + List(8 - head.size - tail.size) { 0 } + tail
        }
        return ByteArray(16) { i -> (groups[i / 2] shr (if (i % 2 == 0) 8 else 0)).toByte() }
    }

    private fun ipv6Groups(part: String, ipv4Tail: Boolean): List<Int>? {
        if (part.isEmpty()) return emptyList()
        val pieces = part.split(':')
        val groups = mutableListOf<Int>()
        for ((i, piece) in pieces.withIndex()) {
            if (ipv4Tail && i == pieces.lastIndex && '.' in piece) {
                val v4 = parseIpv4(piece) ?: return null
                groups += v4.toUnsigned(0) shl 8 or v4.toUnsigned(1)
                groups += v4.toUnsigned(2) shl 8 or v4.toUnsigned(3)
            } else {
                if (piece.length !in 1..4 || !piece.all(::isHex)) return null
                groups += piece.toInt(16)
            }
        }
        return groups
    }

    private fun ByteArray.toUnsigned(i: Int) = this[i].toInt() and 0xff

    /** Not unspecified, broadcast or multicast: those can never be a resolver. */
    private fun usableResolver(ip: ByteArray): Boolean {
        val first = ip.toUnsigned(0)
        return if (ip.size == 4) {
            ip.any { it != 0.toByte() } && ip.any { it != 0xff.toByte() } && first !in 224..239
        } else {
            ip.any { it != 0.toByte() } && first != 0xff
        }
    }

    /** 1 to 65535, digits only, without leading zeros. */
    private fun parsePort(text: String): Int? =
        text.takeIf { it.length in 1..5 && it[0] != '0' && it.all(::isDigit) }?.toInt()?.takeIf { it in 1..65535 }

    /** As the core's `valid_tls_name`: a host name without trailing dot whose last label is not all digits. */
    private fun validTlsName(name: String): Boolean {
        val labels = name.split('.')
        return name.length <= 253 &&
            labels.all { it.length in 1..63 && it.all { c -> isAsciiLetter(c) || isDigit(c) || c == '-' } && it[0] != '-' && it.last() != '-' } &&
            !labels.last().all(::isDigit)
    }

    private fun isDigit(c: Char) = c in '0'..'9'

    private fun isAsciiLetter(c: Char) = c in 'a'..'z' || c in 'A'..'Z'

    private fun isHex(c: Char) = isDigit(c) || c in 'a'..'f' || c in 'A'..'F'

    /**
     * The choice actually in use, which the settings show as chosen: [id], or [DEFAULT] when [id]
     * is unknown or the custom list is refused (e.g. one saved under older, looser rules).
     */
    fun effective(id: String, custom: String): String = when {
        id == CUSTOM -> if (parseCustom(custom) != null) CUSTOM else DEFAULT
        ALL.any { it.id == id } -> id
        else -> DEFAULT
    }

    /** Resolvers for the core, those of [effective]: never plain DNS. */
    fun servers(id: String, custom: String): List<String> {
        if (id == CUSTOM) parseCustom(custom)?.let { return it }
        return (ALL.firstOrNull { it.id == id } ?: ALL.first()).servers
    }
}
