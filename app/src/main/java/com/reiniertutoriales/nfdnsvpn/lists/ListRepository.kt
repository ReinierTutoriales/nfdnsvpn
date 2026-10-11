package com.reiniertutoriales.nfdnsvpn.lists

import android.content.Context
import androidx.core.content.edit
import java.io.File
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL

/** A remote DNS blocklist in adblock syntax (`||domain^`). */
data class BlockList(val id: String, val name: String, val url: String, val enabledByDefault: Boolean)

data class ListStatus(val name: String, val available: Boolean, val updatedAt: Long, val error: String?)

class LoadedLists(val texts: List<String>, val status: List<ListStatus>)

/**
 * Keeps a copy of each list on disk and refreshes it at most once a day with a conditional
 * request. A failed download never removes protection: the previous copy stays in use.
 */
class ListRepository(private val context: Context) {
    companion object {
        val ALL_LISTS = listOf(
            BlockList("adguard-dns", "AdGuard DNS filter", "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt", true),
            BlockList("hagezi-pro", "HaGeZi Multi Pro", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt", true),
            // Encrypted DNS servers (DoH/DoQ): apps cannot resolve or reach them, so they fall back to
            // plain DNS. Applied to DNS answers and to the SNI of TCP connections.
            BlockList("hagezi-doh", "HaGeZi Encrypted DNS", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/doh.txt", true),
            // Optional: mostly overlap with the defaults; big costs about 5 MB more RAM.
            BlockList("oisd-small", "OISD small", "https://small.oisd.nl/", false),
            BlockList("oisd-big", "OISD big", "https://big.oisd.nl/", false),
        )

        fun selected(enabledIds: Set<String>) = ALL_LISTS.filter { it.id in enabledIds }
        const val BUNDLED_ASSET = "video-ads.txt"
        private const val MAX_AGE_MS = 24 * 60 * 60 * 1000L
        private const val MAX_TEXT_CHARS = 16 * 1024 * 1024
        private const val MIN_RULES = 100
    }

    private val dir = File(context.filesDir, "lists").apply { mkdirs() }
    private val prefs = context.getSharedPreferences("lists", Context.MODE_PRIVATE)

    /** True when one of the enabled lists is missing or older than a day. */
    fun isDue(enabledIds: Set<String>) = selected(enabledIds).any { isDue(it) }

    private fun isDue(list: BlockList) =
        !File(dir, "${list.id}.txt").exists() || System.currentTimeMillis() - fetchedAt(list) > MAX_AGE_MS

    /** Enabled lists (refreshed when due), the bundled video ad list and [extraRules] (allowlist). */
    fun load(enabledIds: Set<String>, extraRules: String): LoadedLists {
        val texts = mutableListOf(context.assets.open(BUNDLED_ASSET).bufferedReader().use { it.readText() }, extraRules)
        val status = mutableListOf<ListStatus>()
        for (list in selected(enabledIds)) {
            val file = File(dir, "${list.id}.txt")
            var error: String? = null
            if (isDue(list)) {
                error = try {
                    refresh(list, file)
                    null
                } catch (e: IOException) {
                    e.message ?: e.javaClass.simpleName
                }
            }
            val available = file.exists()
            if (available) texts += file.readText()
            status += ListStatus(list.name, available, if (available) file.lastModified() else 0L, error)
        }
        return LoadedLists(texts, status)
    }

    private fun fetchedAt(list: BlockList) = prefs.getLong("${list.id}.fetchedAt", 0L)

    private fun refresh(list: BlockList, file: File) {
        val connection = URL(list.url).openConnection() as HttpURLConnection
        connection.connectTimeout = 10_000
        connection.readTimeout = 20_000
        connection.useCaches = false
        connection.setRequestProperty("User-Agent", "nfdnsvpn/1.0 (filter list updater)")
        // No Accept-Encoding: HttpURLConnection then asks for gzip and decompresses it itself.
        if (file.exists()) {
            prefs.getString("${list.id}.etag", null)?.let { connection.setRequestProperty("If-None-Match", it) }
            prefs.getString("${list.id}.lastModified", null)?.let { connection.setRequestProperty("If-Modified-Since", it) }
        }
        try {
            val code = connection.responseCode
            if (code == HttpURLConnection.HTTP_NOT_MODIFIED && file.exists()) {
                prefs.edit { putLong("${list.id}.fetchedAt", System.currentTimeMillis()) }
                return
            }
            if (code !in 200..299) throw IOException("HTTP $code")
            val text = connection.inputStream.bufferedReader().use { reader ->
                val out = StringBuilder()
                val buffer = CharArray(64 * 1024)
                while (true) {
                    val read = reader.read(buffer)
                    if (read < 0) break
                    out.appendRange(buffer, 0, read)
                    if (out.length > MAX_TEXT_CHARS) throw IOException("Lista demasiado grande")
                }
                out.toString()
            }
            if (text.lineSequence().count { it.startsWith("||") } < MIN_RULES) {
                throw IOException("El servidor no devolvió una lista válida")
            }
            val partial = File(dir, "${list.id}.txt.part")
            partial.writeText(text)
            if (!partial.renameTo(file)) throw IOException("No se pudo guardar la lista")
            prefs.edit {
                putLong("${list.id}.fetchedAt", System.currentTimeMillis())
                putString("${list.id}.etag", connection.getHeaderField("ETag"))
                putString("${list.id}.lastModified", connection.getHeaderField("Last-Modified"))
            }
        } finally {
            connection.disconnect()
        }
    }
}
