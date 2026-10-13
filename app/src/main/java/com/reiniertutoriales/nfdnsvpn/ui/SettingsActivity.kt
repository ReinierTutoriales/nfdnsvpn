package com.reiniertutoriales.nfdnsvpn.ui

import android.app.AlertDialog
import android.content.ActivityNotFoundException
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.os.Debug
import android.os.Process
import android.provider.Settings
import android.text.format.DateFormat
import android.util.TypedValue
import android.view.View
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.core.content.ContextCompat
import com.reiniertutoriales.nfdnsvpn.R
import com.reiniertutoriales.nfdnsvpn.lists.ListRepository
import com.reiniertutoriales.nfdnsvpn.vpn.DnsProviders
import com.reiniertutoriales.nfdnsvpn.vpn.ShieldSettings
import com.reiniertutoriales.nfdnsvpn.vpn.ShieldState
import com.reiniertutoriales.nfdnsvpn.vpn.ShieldVpnService
import java.util.Date

/**
 * Settings for the remote: every row is a focusable checkbox or button in one vertical list, so
 * the D-pad reaches everything. Changes apply when leaving the screen: lists and allowlist by
 * swapping the filter, app exclusions by restarting the tunnel (routes are fixed per session).
 */
class SettingsActivity : ComponentActivity() {
    private lateinit var content: LinearLayout
    private var filterChanged = false
    /** Blocked apps or the DNS resolver changed: applied at once, without a restart. */
    private var applyNeeded = false
    /** Mode or app exclusions changed: routes are fixed per session, so the tunnel restarts. */
    private var restartNeeded = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(48), dp(27), dp(48), dp(27))
        }
        setContentView(ScrollView(this).apply {
            setBackgroundColor(ContextCompat.getColor(context, R.color.background))
            addView(content)
        })
        build()
    }

    override fun onPause() {
        super.onPause()
        if (ShieldState.phase != ShieldState.Phase.STOPPED) {
            if (restartNeeded) ShieldVpnService.restart(this)
            else {
                if (filterChanged) ShieldVpnService.reload(this)
                if (applyNeeded) ShieldVpnService.apply(this)
            }
        }
        filterChanged = false
        applyNeeded = false
        restartNeeded = false
    }

    private fun build() {
        content.removeAllViews()
        title(R.string.settings_title, 28f)
        note(R.string.settings_intro)

        section(R.string.settings_protection)
        checkbox(getString(R.string.settings_full_mode), ShieldSettings.isFullTunnel(this)) { checked ->
            ShieldSettings.setFullTunnel(this, checked)
            restartNeeded = true
        }
        note(R.string.settings_full_mode_note)
        button(getString(R.string.action_allow)) { onAllowDomain() }

        section(R.string.settings_dns)
        note(R.string.settings_dns_note)
        val chosen = ShieldSettings.dnsProviderInUse(this)
        val choices = DnsProviders.ALL.map { it.id to it.name } +
            (DnsProviders.CUSTOM to getString(R.string.dns_custom, ShieldSettings.customDns(this).ifEmpty { "…" }))
        for ((id, name) in choices) {
            button(if (id == chosen) getString(R.string.dns_chosen, name) else name) {
                if (id == DnsProviders.CUSTOM) onCustomDns() else chooseDns(id)
            }
        }
        if (!ShieldState.lockdown) {
            note(R.string.settings_lockdown_note)
            button(getString(R.string.settings_lockdown_open)) {
                try {
                    startActivity(Intent(Settings.ACTION_VPN_SETTINGS))
                } catch (e: ActivityNotFoundException) {
                    // No VPN settings screen on this device.
                }
            }
        }

        section(R.string.settings_lists)
        val enabled = ShieldSettings.enabledLists(this)
        for (list in ListRepository.ALL_LISTS) {
            checkbox(list.name, list.id in enabled) { checked ->
                ShieldSettings.setListEnabled(this, list.id, checked)
                filterChanged = true
            }
        }
        note(R.string.settings_lists_note)

        section(R.string.settings_startup)
        checkbox(getString(R.string.settings_start_on_boot), ShieldSettings.startOnBoot(this)) { checked ->
            ShieldSettings.setStartOnBoot(this, checked)
        }

        section(R.string.settings_allowed)
        val allowed = ShieldSettings.allowedDomains(this).sorted()
        if (allowed.isEmpty()) note(R.string.settings_allowed_empty)
        for (domain in allowed) {
            button(getString(R.string.settings_allowed_remove, domain)) {
                ShieldSettings.setDomainAllowed(this, domain, false)
                filterChanged = true
                build()
            }
        }

        val apps = launchableApps()
        section(R.string.settings_blocked_domains)
        val blockedDomains = ShieldSettings.blockedDomains(this).sorted()
        if (blockedDomains.isEmpty()) note(R.string.settings_allowed_empty)
        for (domain in blockedDomains) {
            button(getString(R.string.settings_blocked_domains_remove, domain)) {
                ShieldSettings.setDomainBlocked(this, domain, false)
                filterChanged = true
                build()
            }
        }

        section(R.string.settings_excluded)
        note(R.string.settings_excluded_note)
        val excluded = ShieldSettings.excludedApps(this)
        for ((packageName, label) in apps) {
            checkbox(label, packageName in excluded) { checked ->
                ShieldSettings.setAppExcluded(this, packageName, checked)
                restartNeeded = true
            }
        }

        if (Build.VERSION.SDK_INT >= 29) {
            section(R.string.settings_blocked)
            note(R.string.settings_blocked_note)
            val blocked = ShieldSettings.blockedApps(this)
            for ((packageName, label) in apps) {
                checkbox(label, packageName in blocked) { checked ->
                    ShieldSettings.setAppBlocked(this, packageName, checked)
                    // An excluded app bypasses the tunnel: it has to come back in first.
                    if (packageName in ShieldSettings.excludedApps(this)) restartNeeded = true else applyNeeded = true
                }
            }

            section(R.string.settings_watched)
            note(R.string.settings_watched_note)
            val watched = ShieldSettings.watchedApps(this)
            for ((packageName, label) in apps) {
                checkbox(label, packageName in watched) { checked ->
                    ShieldSettings.setAppWatched(this, packageName, checked)
                    // A fresh session: apps resolve again, so their addresses are known.
                    restartNeeded = true
                }
            }
            for ((packageName, label) in apps.filter { it.first in watched }) {
                button(getString(R.string.watched_activity, label)) { onWatchedActivity(packageName, label) }
            }
        }

        section(R.string.settings_status)
        noteText(statusText())
        content.getChildAt(4)?.requestFocus()
    }

    /** Lists, rule count and the app's resource use (what the on-device measurement records). */
    private fun statusText(): String {
        val lines = mutableListOf(getString(R.string.settings_rules, ShieldState.rules))
        ShieldState.lists.forEach { list ->
            val updated = if (list.available) DateFormat.getDateFormat(this).format(Date(list.updatedAt)) else getString(R.string.list_missing)
            val failure = list.error?.let { " · " + getString(R.string.list_update_failed, it) } ?: ""
            lines += "${list.name}: $updated$failure"
        }
        val counters = ShieldState.stats()
        if (counters != null) {
            lines += getString(R.string.settings_counters, counters.queries, counters.blocked, counters.tcp, counters.udp, counters.quicRefused)
            lines += getString(R.string.settings_dns_failed, counters.dnsFailed)
            lines += getString(R.string.settings_flows_refused, counters.flowsRefused)
            lines += getString(
                R.string.settings_owner_unknown,
                counters.ownerDrops, counters.ownerNoMatch, counters.ownerTimeout, counters.ownerQueueFull, counters.ownerDisconnected,
            )
            lines += getString(R.string.usage, Debug.getPss() / 1024, Process.getElapsedCpuTime() / 1000)
        }
        return lines.joinToString("\n")
    }

    private fun chooseDns(id: String, custom: String = ShieldSettings.customDns(this)) {
        ShieldSettings.setDnsProvider(this, id, custom)
        applyNeeded = true
        build()
    }

    /** A resolver of the user's own, over TLS too: typed once, with the remote's keyboard. */
    private fun onCustomDns() {
        val input = EditText(this).apply {
            setText(ShieldSettings.customDns(this@SettingsActivity))
            hint = "tls://9.9.9.9#dns.quad9.net"
            isSingleLine = true
        }
        AlertDialog.Builder(this)
            .setTitle(R.string.dns_custom_title)
            .setMessage(getString(R.string.dns_custom_hint, DnsProviders.MAX_SERVERS))
            .setView(input)
            .setPositiveButton(android.R.string.ok) { _, _ ->
                // Saved only when valid, as shown; otherwise the settings in use stay.
                when (val result = DnsProviders.validate(input.text.toString())) {
                    is DnsProviders.Validation.Valid -> chooseDns(DnsProviders.CUSTOM, result.servers.joinToString(", "))
                    is DnsProviders.Validation.Invalid -> Toast.makeText(this, invalidDns(result), Toast.LENGTH_LONG).show()
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun invalidDns(result: DnsProviders.Validation.Invalid): String = when (result.reason) {
        DnsProviders.Reason.TOO_LONG -> getString(R.string.dns_invalid_too_long, DnsProviders.MAX_LENGTH)
        DnsProviders.Reason.EMPTY -> getString(R.string.dns_invalid_empty)
        DnsProviders.Reason.TOO_MANY -> getString(R.string.dns_invalid_too_many, DnsProviders.MAX_SERVERS)
        DnsProviders.Reason.FORMAT -> getString(R.string.dns_invalid_format, result.entry)
        DnsProviders.Reason.ADDRESS -> getString(R.string.dns_invalid_address, result.entry)
        DnsProviders.Reason.PORT -> getString(R.string.dns_invalid_port, result.entry)
        DnsProviders.Reason.NAME -> getString(R.string.dns_invalid_name, result.entry)
        DnsProviders.Reason.DUPLICATE -> getString(R.string.dns_invalid_duplicate, result.entry)
    }

    /** Allowlists one of the recently blocked names, picked with the remote (no typing on a TV). */
    private fun onAllowDomain() {
        val names = ShieldState.stats()?.recent.orEmpty()
        if (names.isEmpty()) {
            AlertDialog.Builder(this).setMessage(R.string.allow_empty).setPositiveButton(android.R.string.ok, null).show()
            return
        }
        AlertDialog.Builder(this)
            .setTitle(R.string.allow_title)
            .setItems(names.toTypedArray()) { _, which ->
                ShieldSettings.setDomainAllowed(this, names[which], true)
                filterChanged = true
                Toast.makeText(this, R.string.allow_hint, Toast.LENGTH_LONG).show()
                build()
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    /**
     * Where a watched app has gone, picked with the remote: an allowed name gets blocked (its
     * telemetry, say), a name the lists refused gets allowed. Bare addresses only inform.
     */
    private fun onWatchedActivity(packageName: String, label: String) {
        val uid = ShieldVpnService.appUids(this, listOf(packageName)).firstOrNull()
        val destinations = uid?.let { ShieldState.tunnel?.appActivity(it) }.orEmpty()
        if (destinations.isEmpty()) {
            AlertDialog.Builder(this).setMessage(R.string.watched_activity_empty).setPositiveButton(android.R.string.ok, null).show()
            return
        }
        val rows = destinations.map { getString(if (it.refused) R.string.watched_refused else R.string.watched_allowed, it.name) }
        AlertDialog.Builder(this)
            .setTitle(getString(R.string.watched_activity, label))
            .setItems(rows.toTypedArray()) { _, which ->
                val destination = destinations[which]
                when {
                    destination.name.any { it == ':' } || destination.name.all { it.isDigit() || it == '.' } ->
                        Toast.makeText(this, R.string.watched_address_hint, Toast.LENGTH_LONG).show()
                    destination.refused -> {
                        ShieldSettings.setDomainAllowed(this, destination.name, true)
                        filterChanged = true
                        Toast.makeText(this, R.string.allow_hint, Toast.LENGTH_LONG).show()
                    }
                    else -> {
                        ShieldSettings.setDomainBlocked(this, destination.name, true)
                        filterChanged = true
                        Toast.makeText(this, getString(R.string.watched_blocked_hint, destination.name), Toast.LENGTH_LONG).show()
                    }
                }
                build()
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    /** Apps with a TV or phone launcher entry, by label; this app itself is always excluded. */
    private fun launchableApps(): List<Pair<String, String>> {
        val manager = packageManager
        val categories = listOf(Intent.CATEGORY_LEANBACK_LAUNCHER, Intent.CATEGORY_LAUNCHER)
        return categories
            .flatMap { category ->
                manager.queryIntentActivities(Intent(Intent.ACTION_MAIN).addCategory(category), PackageManager.MATCH_ALL)
            }
            .map { it.activityInfo.packageName to it.loadLabel(manager).toString() }
            .filter { it.first != packageName }
            .distinctBy { it.first }
            .sortedBy { it.second.lowercase() }
    }

    private fun dp(value: Int) =
        TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, value.toFloat(), resources.displayMetrics).toInt()

    private fun <T : TextView> text(view: T, sizeSp: Float, color: Int): T = view.apply {
        setTextSize(TypedValue.COMPLEX_UNIT_SP, sizeSp)
        setTextColor(ContextCompat.getColor(context, color))
    }

    private fun title(resource: Int, sizeSp: Float) {
        content.addView(text(TextView(this), sizeSp, R.color.text_primary).apply { setText(resource) })
    }

    private fun section(resource: Int) {
        content.addView(text(TextView(this), 18f, R.color.accent).apply {
            setText(resource)
            setPadding(0, dp(24), 0, dp(8))
        })
    }

    private fun noteText(value: String) {
        content.addView(text(TextView(this), 14f, R.color.text_secondary).apply {
            text = value
            setPadding(0, dp(4), 0, dp(4))
        })
    }

    private fun note(resource: Int) {
        content.addView(text(TextView(this), 14f, R.color.text_secondary).apply {
            setText(resource)
            setPadding(0, dp(4), 0, dp(4))
        })
    }

    private fun checkbox(label: String, checked: Boolean, onChange: (Boolean) -> Unit) {
        content.addView(text(CheckBox(this), 16f, R.color.text_primary).apply {
            text = label
            isChecked = checked
            buttonTintList = ContextCompat.getColorStateList(context, R.color.button_text_accent)
            setBackgroundResource(R.drawable.row_focus)
            setPadding(dp(8), dp(6), dp(8), dp(6))
            setOnCheckedChangeListener { _, value -> onChange(value) }
        })
    }

    private fun button(label: String, onClick: () -> Unit) {
        content.addView(text(Button(this), 16f, R.color.text_primary).apply {
            text = label
            isAllCaps = false
            textAlignment = View.TEXT_ALIGNMENT_VIEW_START
            setBackgroundResource(R.drawable.row_focus)
            setOnClickListener { onClick() }
        })
    }
}
