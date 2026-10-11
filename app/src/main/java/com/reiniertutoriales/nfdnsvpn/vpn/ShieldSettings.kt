package com.reiniertutoriales.nfdnsvpn.vpn

import android.content.Context
import androidx.core.content.edit
import com.reiniertutoriales.nfdnsvpn.lists.ListRepository

/** User choices that outlive the VPN session. */
object ShieldSettings {
    private const val FILE = "settings"
    private const val FULL_TUNNEL = "fullTunnel"
    private const val ENABLED_LISTS = "enabledLists"
    private const val ALLOWED_DOMAINS = "allowedDomains"
    private const val EXCLUDED_APPS = "excludedApps"
    private const val START_ON_BOOT = "startOnBoot"
    private const val WANT_RUNNING = "wantRunning"

    private fun prefs(context: Context) = context.getSharedPreferences(FILE, Context.MODE_PRIVATE)

    /**
     * Full tunnel (default): all traffic goes through the app, so no app can get around the
     * filter with its own resolver, encrypted DNS or QUIC. Light mode only routes DNS and the
     * known resolvers: cheaper, but an app with its own DNS server can bypass it.
     */
    fun isFullTunnel(context: Context) = prefs(context).getBoolean(FULL_TUNNEL, true)

    fun setFullTunnel(context: Context, enabled: Boolean) = prefs(context).edit { putBoolean(FULL_TUNNEL, enabled) }

    /** Ids of the downloaded lists in use. */
    fun enabledLists(context: Context): Set<String> =
        prefs(context).getStringSet(ENABLED_LISTS, null)?.toSet()
            ?: ListRepository.ALL_LISTS.filter { it.enabledByDefault }.map { it.id }.toSet()

    fun setListEnabled(context: Context, id: String, enabled: Boolean) {
        val lists = enabledLists(context).toMutableSet()
        if (enabled) lists += id else lists -= id
        prefs(context).edit { putStringSet(ENABLED_LISTS, lists) }
    }

    /** Domains (with their subdomains) never blocked, whatever the lists say. */
    fun allowedDomains(context: Context): Set<String> = prefs(context).getStringSet(ALLOWED_DOMAINS, emptySet())!!.toSet()

    fun setDomainAllowed(context: Context, domain: String, allowed: Boolean) {
        val domains = allowedDomains(context).toMutableSet()
        if (allowed) domains += domain else domains -= domain
        prefs(context).edit { putStringSet(ALLOWED_DOMAINS, domains) }
    }

    /** Packages whose traffic bypasses the VPN entirely (for apps that break when filtered). */
    fun excludedApps(context: Context): Set<String> = prefs(context).getStringSet(EXCLUDED_APPS, emptySet())!!.toSet()

    fun setAppExcluded(context: Context, packageName: String, excluded: Boolean) {
        val apps = excludedApps(context).toMutableSet()
        if (excluded) apps += packageName else apps -= packageName
        prefs(context).edit { putStringSet(EXCLUDED_APPS, apps) }
    }

    fun startOnBoot(context: Context) = prefs(context).getBoolean(START_ON_BOOT, true)

    fun setStartOnBoot(context: Context, enabled: Boolean) = prefs(context).edit { putBoolean(START_ON_BOOT, enabled) }

    /** Whether the user left protection on; restored after a reboot or an app update. */
    fun wantRunning(context: Context) = prefs(context).getBoolean(WANT_RUNNING, false)

    fun setWantRunning(context: Context, running: Boolean) = prefs(context).edit { putBoolean(WANT_RUNNING, running) }

    /** Allowlist as exception rules for the filter (`@@||domain^` also covers subdomains). */
    fun allowlistRules(domains: Collection<String>): String = domains.sorted().joinToString("") { "@@||$it^\n" }
}
