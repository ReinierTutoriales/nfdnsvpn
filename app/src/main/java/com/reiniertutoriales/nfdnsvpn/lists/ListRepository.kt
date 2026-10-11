package com.reiniertutoriales.nfdnsvpn.lists

import android.content.Context
import androidx.core.content.edit
import java.io.File
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL

/**
 * A blocklist downloaded from one or more files: domain rules in adblock syntax (`||domain^`), or
 * one IP address per line ([ipList]) for servers reached without a name.
 */
data class BlockList(
    val id: String,
    val name: String,
    val urls: List<String>,
    val enabledByDefault: Boolean,
    val ipList: Boolean = false,
    /** Fewer rules than this in a downloaded file means an error page or a truncated download. */
    val minRules: Int = 100,
) {
    constructor(id: String, name: String, url: String, enabledByDefault: Boolean) : this(id, name, listOf(url), enabledByDefault)

    /** One saved file per URL. */
    fun sources(): List<Pair<String, String>> =
        if (urls.size == 1) listOf(id to urls[0]) else urls.mapIndexed { index, url -> "$id-$index" to url }
}

data class ListStatus(val name: String, val available: Boolean, val updatedAt: Long, val error: String?)

/** Saved list files to compile (read by the core straight from disk), and their status. */
class LoadedLists(val files: List<File>, val status: List<ListStatus>)

/**
 * Keeps a copy of each list on disk and refreshes it at most once a day with a conditional
 * request. A failed download never removes protection: the previous copy stays in use.
 * Lists are streamed to disk and to the core: no list is ever held in memory as a whole.
 */
class ListRepository(private val context: Context) {
    companion object {
        val ALL_LISTS = listOf(
            BlockList("adguard-dns", "AdGuard DNS filter", "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt", true),
            // Blocking first: Ultimate, HaGeZi's strictest general list. Measured with
            // scripts/validate-lists.sh: the defaults block all 131 domains of d3ward's adblock
            // test and none of the 50 critical TV domains; ~340 000 domains, ~7.6 MB.
            BlockList("hagezi-ultimate", "HaGeZi Ultimate", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/ultimate.txt", true),
            // Telemetry of TV, phone and OS makers (Samsung, LG webOS, Amazon, Roku, Xiaomi...).
            BlockList(
                "hagezi-native", "Telemetría de fabricantes y sistemas (HaGeZi native)",
                listOf("samsung", "lgwebos", "amazon", "roku", "xiaomi", "tiktok", "apple", "huawei", "oppo-realme", "vivo", "winoffice")
                    .map { "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.$it.txt" },
                true,
                minRules = 20,
            ),
            // Encrypted DNS servers (DoH/DoQ): apps cannot resolve or reach them, so they fall back to
            // plain DNS. Applied to DNS answers and to the SNI of TCP connections.
            BlockList("hagezi-doh", "HaGeZi Encrypted DNS", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/doh.txt", true),
            // Addresses of encrypted DNS servers, for apps that connect to them by IP (no DNS, no
            // usable SNI). Only non-DNS traffic to them is refused; plain DNS is still answered.
            BlockList(
                "doh-ips", "IPs de DNS cifrado (HaGeZi + dibdot)",
                listOf(
                    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/ips/doh.txt",
                    "https://raw.githubusercontent.com/dibdot/DoH-IP-blocklists/master/doh-ipv4.txt",
                    "https://raw.githubusercontent.com/dibdot/DoH-IP-blocklists/master/doh-ipv6.txt",
                ),
                true,
                ipList = true,
            ),
            // Optional. Pro is a lighter subset of Ultimate (fewer breakages, a bit less blocked).
            BlockList("hagezi-pro", "HaGeZi Multi Pro (más ligera que Ultimate)", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt", false),
            // Mostly overlap with the defaults; big costs about 5 MB more RAM.
            BlockList("oisd-small", "OISD small", "https://small.oisd.nl/", false),
            BlockList("oisd-big", "OISD big", "https://big.oisd.nl/", false),
            // uBlock Origin's own lists. Only their plain domain rules apply outside a browser
            // (paths, cosmetic filters and scriptlets need the page): about 240 domains beyond
            // the defaults, measured 2026-10.
            BlockList(
                "ublock", "uBlock Origin (solo dominios)",
                listOf(
                    "https://ublockorigin.github.io/uAssets/filters/filters.txt",
                    "https://ublockorigin.github.io/uAssets/filters/privacy.txt",
                    "https://ublockorigin.github.io/uAssets/filters/badware.txt",
                ),
                false,
            ),
        )

        fun selected(enabledIds: Set<String>) = ALL_LISTS.filter { it.id in enabledIds }

        const val BUNDLED_ASSET = "video-ads.txt"
        private const val MAX_AGE_MS = 24 * 60 * 60 * 1000L
        private const val MAX_TEXT_CHARS = 16L * 1024 * 1024

        /**
         * Why a downloaded list must not replace the one in use, or null if it may. Lists grow or
         * shrink a little each day; one with less than half the rules of the last good copy is a
         * cut download or a wrong page, and swapping it in would quietly unblock most of the list.
         */
        fun rejection(rules: Int, minRules: Int, previousRules: Int): String? = when {
            rules < minRules -> "El servidor no devolvió una lista válida"
            previousRules > 0 && rules < previousRules / 2 -> "Lista incompleta ($rules reglas; la anterior tenía $previousRules)"
            else -> null
        }
    }

    private val dir = File(context.filesDir, "lists").apply { mkdirs() }
    private val prefs = context.getSharedPreferences("lists", Context.MODE_PRIVATE)

    /** True when one of the enabled lists is missing or older than a day. */
    fun isDue(enabledIds: Set<String>) = selected(enabledIds).flatMap { it.sources() }.any { (key, _) -> isDue(key) }

    private fun file(key: String) = File(dir, "$key.txt")

    private fun isDue(key: String) = !file(key).exists() || System.currentTimeMillis() - prefs.getLong("$key.fetchedAt", 0L) > MAX_AGE_MS

    /** Enabled lists, refreshed when due. */
    fun load(enabledIds: Set<String>): LoadedLists {
        val files = mutableListOf<File>()
        val status = mutableListOf<ListStatus>()
        for (list in selected(enabledIds)) {
            var error: String? = null
            var updatedAt = Long.MAX_VALUE
            var available = false
            for ((key, url) in list.sources()) {
                if (isDue(key)) {
                    try {
                        refresh(key, url, list)
                    } catch (e: IOException) {
                        error = error ?: (e.message ?: e.javaClass.simpleName)
                    }
                }
                val file = file(key)
                if (file.exists()) {
                    files += file
                    available = true
                    updatedAt = minOf(updatedAt, file.lastModified())
                }
            }
            status += ListStatus(list.name, available, if (available) updatedAt else 0L, error)
        }
        return LoadedLists(files, status)
    }

    /** Line starting with an IPv4 or IPv6 address (the core does the real parsing). */
    private fun looksLikeAddress(line: String): Boolean {
        val token = line.substringBefore('#').trim()
        return token.isNotEmpty() && token.none(Char::isWhitespace) &&
            (token.count { it == '.' } == 3 || token.contains(':')) && token.all { it.isLetterOrDigit() || it == '.' || it == ':' }
    }

    fun bundledRules(): String = context.assets.open(BUNDLED_ASSET).bufferedReader().use { it.readText() }

    private fun refresh(key: String, url: String, list: BlockList) {
        val target = file(key)
        val connection = URL(url).openConnection() as HttpURLConnection
        connection.connectTimeout = 10_000
        connection.readTimeout = 20_000
        connection.useCaches = false
        connection.setRequestProperty("User-Agent", "nfdnsvpn/1.0 (filter list updater)")
        // No Accept-Encoding: HttpURLConnection then asks for gzip and decompresses it itself.
        if (target.exists()) {
            prefs.getString("$key.etag", null)?.let { connection.setRequestProperty("If-None-Match", it) }
            prefs.getString("$key.lastModified", null)?.let { connection.setRequestProperty("If-Modified-Since", it) }
        }
        val partial = File(dir, "$key.txt.part")
        try {
            val code = connection.responseCode
            if (code == HttpURLConnection.HTTP_NOT_MODIFIED && target.exists()) {
                prefs.edit { putLong("$key.fetchedAt", System.currentTimeMillis()) }
                return
            }
            if (code !in 200..299) throw IOException("HTTP $code")
            // Only HTTPS, also after redirects: rules must not be swappable on the way.
            if (connection.url.protocol != "https") throw IOException("Redirigido fuera de HTTPS")
            // Line by line to disk, validating on the way: memory use is one line, not one list.
            var characters = 0L
            var rules = 0
            connection.inputStream.bufferedReader().use { reader ->
                partial.bufferedWriter().use { writer ->
                    while (true) {
                        val line = reader.readLine() ?: break
                        characters += line.length + 1
                        if (characters > MAX_TEXT_CHARS) throw IOException("Lista demasiado grande")
                        if (if (list.ipList) looksLikeAddress(line) else line.startsWith("||")) rules++
                        writer.write(line)
                        writer.write('\n'.code)
                    }
                }
            }
            val previousRules = if (target.exists()) prefs.getInt("$key.rules", 0) else 0
            rejection(rules, list.minRules, previousRules)?.let { throw IOException(it) }
            if (!partial.renameTo(target)) throw IOException("No se pudo guardar la lista")
            prefs.edit {
                putLong("$key.fetchedAt", System.currentTimeMillis())
                putInt("$key.rules", rules)
                putString("$key.etag", connection.getHeaderField("ETag"))
                putString("$key.lastModified", connection.getHeaderField("Last-Modified"))
            }
        } finally {
            partial.delete()
            connection.disconnect()
        }
    }
}
