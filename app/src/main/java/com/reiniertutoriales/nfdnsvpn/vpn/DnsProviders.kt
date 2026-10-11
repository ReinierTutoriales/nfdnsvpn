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

    private val CUSTOM_ENTRY = Regex("""tls://(\d{1,3}(\.\d{1,3}){3}|\[[0-9a-fA-F:]+])(:\d{1,5})?#[A-Za-z0-9.-]+""")

    /** A custom resolver must be encrypted too: `tls://IP#name`, comma-separated. */
    fun parseCustom(text: String): List<String>? {
        val entries = text.split(',').map(String::trim).filter(String::isNotEmpty)
        return entries.takeIf { it.isNotEmpty() && it.all(CUSTOM_ENTRY::matches) }
    }

    /** Resolvers for the core; an unknown or invalid choice falls back to [DEFAULT], never plain. */
    fun servers(id: String, custom: String): List<String> =
        (if (id == CUSTOM) parseCustom(custom) else ALL.firstOrNull { it.id == id }?.servers) ?: ALL.first().servers
}
