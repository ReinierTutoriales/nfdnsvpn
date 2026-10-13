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
    private const val BLOCKED_APPS = "blockedApps"
    private const val WATCHED_APPS = "watchedApps"
    private const val BLOCKED_DOMAINS = "blockedDomains"
    private const val DNS_PROVIDER = "dnsProvider"
    private const val CUSTOM_DNS = "customDns"
    private const val START_ON_BOOT = "startOnBoot"
    private const val WANT_RUNNING = "wantRunning"
    private const val ASKED_TO_KEEP_RUNNING = "askedToKeepRunning"

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

    /** Packages cut off the network entirely (full mode, Android 10+), even if that breaks them. */
    fun blockedApps(context: Context): Set<String> = prefs(context).getStringSet(BLOCKED_APPS, emptySet())!!.toSet()

    fun setAppBlocked(context: Context, packageName: String, blocked: Boolean) {
        val apps = blockedApps(context).toMutableSet()
        if (blocked) apps += packageName else apps -= packageName
        prefs(context).edit { putStringSet(BLOCKED_APPS, apps) }
    }

    /**
     * Watched packages (full mode, Android 10+): they may only reach readable, allowed server
     * names or addresses our DNS gave out, so hardcoded IPs and their own resolvers are cut.
     */
    fun watchedApps(context: Context): Set<String> = prefs(context).getStringSet(WATCHED_APPS, emptySet())!!.toSet()

    fun setAppWatched(context: Context, packageName: String, watched: Boolean) {
        val apps = watchedApps(context).toMutableSet()
        if (watched) apps += packageName else apps -= packageName
        prefs(context).edit { putStringSet(WATCHED_APPS, apps) }
    }

    /** Domains (with their subdomains) the user blocked, e.g. an allowed app's telemetry. */
    fun blockedDomains(context: Context): Set<String> = prefs(context).getStringSet(BLOCKED_DOMAINS, emptySet())!!.toSet()

    /** Blocking a domain takes it off the allowed ones, or the allowlist would win. */
    fun setDomainBlocked(context: Context, domain: String, blocked: Boolean) {
        val domains = blockedDomains(context).toMutableSet()
        if (blocked) domains += domain else domains -= domain
        prefs(context).edit { putStringSet(BLOCKED_DOMAINS, domains) }
        if (blocked) setDomainAllowed(context, domain, false)
    }

    /** Resolver for every allowed query (see [DnsProviders]), as saved. */
    fun dnsProvider(context: Context): String = prefs(context).getString(DNS_PROVIDER, DnsProviders.DEFAULT)!!

    /** The choice in use, the one to show as chosen (see [DnsProviders.effective]). */
    fun dnsProviderInUse(context: Context): String = DnsProviders.effective(dnsProvider(context), customDns(context))

    fun customDns(context: Context): String = prefs(context).getString(CUSTOM_DNS, "")!!

    fun setDnsProvider(context: Context, id: String, custom: String = customDns(context)) = prefs(context).edit {
        putString(DNS_PROVIDER, id)
        putString(CUSTOM_DNS, custom)
    }

    /** The chosen resolvers for the core, always encrypted. */
    fun chosenDns(context: Context): List<String> = DnsProviders.servers(dnsProvider(context), customDns(context))

    fun startOnBoot(context: Context) = prefs(context).getBoolean(START_ON_BOOT, true)

    fun setStartOnBoot(context: Context, enabled: Boolean) = prefs(context).edit { putBoolean(START_ON_BOOT, enabled) }

    /** Whether the user left protection on; restored after a reboot or an app update. */
    fun wantRunning(context: Context) = prefs(context).getBoolean(WANT_RUNNING, false)

    fun setWantRunning(context: Context, running: Boolean) = prefs(context).edit { putBoolean(WANT_RUNNING, running) }

    /** The battery-optimisation request is shown once; after that it is the user's choice. */
    fun askedToKeepRunning(context: Context) = prefs(context).getBoolean(ASKED_TO_KEEP_RUNNING, false)

    fun setAskedToKeepRunning(context: Context) = prefs(context).edit { putBoolean(ASKED_TO_KEEP_RUNNING, true) }

    /** Allowlist as exception rules for the filter (`@@||domain^` also covers subdomains). */
    fun allowlistRules(domains: Collection<String>): String = domains.sorted().joinToString("") { "@@||$it^\n" }

    /** User blocklist as filter rules (`||domain^` also covers subdomains). */
    fun blocklistRules(domains: Collection<String>): String = domains.sorted().joinToString("") { "||$it^\n" }
}
