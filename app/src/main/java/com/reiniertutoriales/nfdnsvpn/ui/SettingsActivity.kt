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
import android.util.Log
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
import androidx.activity.OnBackPressedCallback
import androidx.core.content.ContextCompat
import com.reiniertutoriales.nfdnsvpn.R
import com.reiniertutoriales.nfdnsvpn.lists.ListRepository
import com.reiniertutoriales.nfdnsvpn.vpn.DnsProviders
import com.reiniertutoriales.nfdnsvpn.vpn.ShieldSettings
import com.reiniertutoriales.nfdnsvpn.vpn.ShieldState
import com.reiniertutoriales.nfdnsvpn.vpn.ShieldVpnService
import java.util.Date

/** Small settings pages for the D-pad. Saved changes apply explicitly or when leaving the activity. */
class SettingsActivity : ComponentActivity() {
    private enum class Page { HOME, PROTECTION, APPS, APP, DOMAINS, DNS, STATUS }

    private lateinit var content: LinearLayout
    private lateinit var scroll: ScrollView
    private val controls = linkedMapOf<String, View>()
    private val focus = SettingsFocus()
    private val changes = SettingsChanges()
    private var page = Page.HOME
    private var appPackage = ""
    private var appLabel = ""
    // Discover installed apps only on demand, once per activity, not on every DNS/domain edit.
    private val apps by lazy(::launchableApps)
    private var pendingNote: TextView? = null
    private var applyButton: Button? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        page = savedInstanceState?.getString("page")?.let { value -> Page.entries.firstOrNull { it.name == value } } ?: Page.HOME
        appPackage = savedInstanceState?.getString("appPackage").orEmpty()
        appLabel = savedInstanceState?.getString("appLabel").orEmpty()
        savedInstanceState?.getStringArrayList("changes")?.forEach { name ->
            SettingsChanges.Change.entries.firstOrNull { it.name == name }?.let(changes::add)
        }
        content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(48), dp(27), dp(48), dp(27))
        }
        scroll = ScrollView(this).apply {
            setBackgroundColor(ContextCompat.getColor(context, R.color.background))
            addView(content)
        }
        setContentView(scroll)
        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                when (page) {
                    Page.HOME -> finish()
                    Page.APP -> navigate(Page.APPS)
                    else -> navigate(Page.HOME)
                }
            }
        })
        build(remember = false)
    }

    override fun onSaveInstanceState(outState: Bundle) {
        outState.putString("page", page.name)
        outState.putString("appPackage", appPackage)
        outState.putString("appLabel", appLabel)
        outState.putStringArrayList("changes", ArrayList(changes.actions(running = true).map { it.name }))
        super.onSaveInstanceState(outState)
    }

    override fun onPause() {
        applyChanges(notify = false)
        super.onPause()
    }

    private fun positionId() = if (page == Page.APP) "APP:$appPackage" else page.name

    private fun rememberPosition() {
        val key = controls.entries.firstOrNull { it.value.hasFocus() }?.key
        focus.remember(positionId(), key, focusableKeys(), scroll.scrollY)
    }

    private fun focusableKeys() = controls.filterValues { it.isFocusable && it.visibility == View.VISIBLE }.keys.toList()

    private fun navigate(next: Page) {
        rememberPosition()
        page = next
        build(remember = false)
    }

    private fun build(remember: Boolean = true) {
        if (remember) rememberPosition()
        controls.clear()
        content.removeAllViews()
        pendingNote = null
        applyButton = null
        val heading = when (page) {
            Page.HOME -> R.string.settings_title
            Page.PROTECTION -> R.string.settings_protection
            Page.APPS, Page.APP -> R.string.settings_apps
            Page.DOMAINS -> R.string.settings_domains
            Page.DNS -> R.string.settings_dns
            Page.STATUS -> R.string.settings_status
        }
        noteText(if (page == Page.APP) appLabel else getString(heading), 28f)
        note(R.string.settings_navigation)
        when (page) {
            Page.HOME -> home()
            Page.PROTECTION -> protection()
            Page.APPS -> applicationList()
            Page.APP -> applicationDetails()
            Page.DOMAINS -> domains()
            Page.DNS -> dns()
            Page.STATUS -> {
                button("refresh", getString(R.string.settings_refresh)) { build() }
                noteText(statusText())
            }
        }
        pendingNote = noteText("")
        applyButton = button("apply", getString(R.string.settings_apply)) { applyChanges(notify = true) }
        showPending()
        val position = focus.restore(positionId(), focusableKeys())
        val target = position.key?.let(controls::get)
        val builtPage = positionId()
        scroll.post {
            if (positionId() == builtPage) {
                target?.requestFocus()
                scroll.scrollTo(0, position.scroll)
            }
        }
    }

    private fun home() {
        note(R.string.settings_intro)
        button("protection", getString(R.string.settings_protection)) { navigate(Page.PROTECTION) }
        button("apps", getString(R.string.settings_apps)) { navigate(Page.APPS) }
        button("domains", getString(R.string.settings_domains)) { navigate(Page.DOMAINS) }
        button("dns", getString(R.string.settings_dns)) { navigate(Page.DNS) }
        button("status", getString(R.string.settings_status)) { navigate(Page.STATUS) }
    }

    private fun protection() {
        checkbox("full", getString(R.string.settings_full_mode), ShieldSettings.isFullTunnel(this)) { checked ->
            val save: () -> Unit = {
                ShieldSettings.setFullTunnel(this, checked)
                changed(SettingsChanges.Change.RESTART)
            }
            if (checked) save() else confirm(getString(R.string.settings_light_confirm), save)
        }
        note(R.string.settings_full_mode_note)
        checkbox("boot", getString(R.string.settings_start_on_boot), ShieldSettings.startOnBoot(this)) { checked ->
            ShieldSettings.setStartOnBoot(this, checked)
        }
        note(R.string.settings_lockdown_note)
        button("lockdown", getString(R.string.settings_lockdown_open)) {
            try {
                startActivity(Intent(Settings.ACTION_VPN_SETTINGS))
            } catch (e: ActivityNotFoundException) {
                Toast.makeText(this, R.string.settings_vpn_unavailable, Toast.LENGTH_LONG).show()
            }
        }
    }

    private fun applicationList() {
        note(R.string.settings_apps_note)
        if (apps.isEmpty()) note(R.string.settings_apps_empty)
        val blocked = ShieldSettings.blockedApps(this)
        val watched = ShieldSettings.watchedApps(this)
        val excluded = ShieldSettings.excludedApps(this)
        val full = ShieldSettings.isFullTunnel(this)
        for ((packageName, label) in apps) {
            val mode = when {
                !full && (packageName in blocked || packageName in watched) -> R.string.settings_app_inactive
                packageName in blocked -> R.string.settings_app_blocked
                packageName in watched -> R.string.settings_app_watched
                packageName in excluded -> R.string.settings_app_excluded
                else -> R.string.settings_app_filtered
            }
            button(packageName, getString(R.string.settings_app_row, label, getString(mode))) {
                // Save the app list's focus before changing the selected detail page.
                rememberPosition()
                appPackage = packageName
                appLabel = label
                page = Page.APP
                build(remember = false)
            }
        }
    }

    private fun applicationDetails() {
        noteText(appPackage)
        checkbox("excluded", getString(R.string.settings_app_excluded), appPackage in ShieldSettings.excludedApps(this)) { checked ->
            val save: () -> Unit = {
                ShieldSettings.setAppExcluded(this, appPackage, checked)
                changed(SettingsChanges.Change.RESTART)
                if (!checked) build()
            }
            if (checked) confirm(getString(R.string.settings_excluded_note), save) else save()
        }
        note(R.string.settings_excluded_note)
        if (Build.VERSION.SDK_INT < 29) {
            note(R.string.settings_app_requires_android)
            return
        }
        val full = ShieldSettings.isFullTunnel(this)
        if (!full) {
            note(R.string.settings_app_requires_full)
            button("full-mode", getString(R.string.settings_protection)) { navigate(Page.PROTECTION) }
        }
        checkbox("blocked", getString(R.string.settings_app_blocked), appPackage in ShieldSettings.blockedApps(this), enabled = full) { checked ->
            val save: () -> Unit = {
                ShieldSettings.setAppBlocked(this, appPackage, checked)
                changed(if (appPackage in ShieldSettings.excludedApps(this)) SettingsChanges.Change.RESTART else SettingsChanges.Change.RULES)
                if (!checked) build()
            }
            if (checked) confirm(getString(R.string.settings_blocked_note), save) else save()
        }
        note(R.string.settings_blocked_note)
        checkbox("watched", getString(R.string.settings_app_watched), appPackage in ShieldSettings.watchedApps(this), enabled = full) { checked ->
            ShieldSettings.setAppWatched(this, appPackage, checked)
            changed(SettingsChanges.Change.RESTART)
            build()
        }
        note(R.string.settings_watched_note)
        if (appPackage in ShieldSettings.blockedApps(this) || appPackage in ShieldSettings.watchedApps(this)) note(R.string.settings_app_priority)
        if (appPackage in ShieldSettings.watchedApps(this)) {
            button("activity", getString(R.string.watched_activity, appLabel)) { onWatchedActivity() }
        }
    }

    private fun domains() {
        button("allow", getString(R.string.action_allow)) { onAllowDomain() }
        section(R.string.settings_allowed)
        domainRows(ShieldSettings.allowedDomains(this), "allowed", R.string.settings_allowed_remove) { domain ->
            ShieldSettings.setDomainAllowed(this, domain, false)
        }
        section(R.string.settings_blocked_domains)
        domainRows(ShieldSettings.blockedDomains(this), "blocked", R.string.settings_blocked_domains_remove) { domain ->
            ShieldSettings.setDomainBlocked(this, domain, false)
        }
        section(R.string.settings_lists)
        val enabled = ShieldSettings.enabledLists(this)
        for (list in ListRepository.ALL_LISTS) {
            checkbox("list:${list.id}", list.name, list.id in enabled) { checked ->
                ShieldSettings.setListEnabled(this, list.id, checked)
                changed(SettingsChanges.Change.FILTER)
            }
        }
        note(R.string.settings_lists_note)
    }

    private fun domainRows(domains: Set<String>, prefix: String, label: Int, remove: (String) -> Unit) {
        if (domains.isEmpty()) note(R.string.settings_allowed_empty)
        for (domain in domains.sorted()) {
            button("$prefix:$domain", getString(label, domain)) {
                confirm(getString(R.string.settings_remove_domain_confirm, domain)) {
                    remove(domain)
                    changed(SettingsChanges.Change.FILTER)
                }
            }
        }
    }

    private fun dns() {
        note(R.string.settings_dns_note)
        val chosen = ShieldSettings.dnsProviderInUse(this)
        for (provider in DnsProviders.ALL) {
            button(provider.id, if (provider.id == chosen) getString(R.string.dns_chosen, provider.name) else provider.name) {
                if (provider.id != chosen) chooseDns(provider.id)
            }
        }
        val customLabel = getString(R.string.dns_custom_option)
        button("custom", if (chosen == DnsProviders.CUSTOM) getString(R.string.dns_chosen, customLabel) else customLabel) { onCustomDns() }
    }

    private fun changed(change: SettingsChanges.Change) {
        changes.add(change)
        showPending()
    }

    private fun showPending() {
        pendingNote?.setText(if (changes.requiresRestart) R.string.settings_pending_restart else R.string.settings_pending)
        pendingNote?.visibility = if (changes.isPending) View.VISIBLE else View.GONE
        applyButton?.visibility = if (changes.isPending) View.VISIBLE else View.GONE
    }

    private fun applyChanges(notify: Boolean) {
        if (!changes.isPending) return
        try {
            for (action in changes.actions(ShieldState.phase != ShieldState.Phase.STOPPED)) {
                when (action) {
                    SettingsChanges.Change.RESTART -> ShieldVpnService.restart(this)
                    SettingsChanges.Change.FILTER -> ShieldVpnService.reload(this)
                    SettingsChanges.Change.RULES -> ShieldVpnService.apply(this)
                }
            }
            changes.clear()
            if (notify) build() else showPending()
            if (notify) Toast.makeText(this, R.string.settings_applied, Toast.LENGTH_LONG).show()
        } catch (e: RuntimeException) {
            Log.e("ShieldSettings", "Could not apply saved settings", e)
            if (notify) Toast.makeText(this, R.string.settings_apply_failed, Toast.LENGTH_LONG).show()
        }
    }

    private fun chooseDns(id: String, custom: String = ShieldSettings.customDns(this)) {
        ShieldSettings.setDnsProvider(this, id, custom)
        changed(SettingsChanges.Change.RULES)
        build()
    }

    private fun onCustomDns() {
        val input = EditText(this).apply {
            setText(ShieldSettings.customDns(this@SettingsActivity))
            hint = "tls://9.9.9.9#dns.quad9.net"
            isSingleLine = true
        }
        val dialog = AlertDialog.Builder(this)
            .setTitle(R.string.dns_custom_title)
            .setMessage(getString(R.string.dns_custom_hint, DnsProviders.MAX_SERVERS))
            .setView(input)
            .setPositiveButton(android.R.string.ok, null)
            .setNegativeButton(android.R.string.cancel, null)
            .create()
        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                when (val result = DnsProviders.validate(input.text.toString())) {
                    is DnsProviders.Validation.Valid -> {
                        chooseDns(DnsProviders.CUSTOM, result.encoded)
                        dialog.dismiss()
                    }
                    is DnsProviders.Validation.Invalid -> {
                        input.error = invalidDns(result)
                        input.requestFocus()
                    }
                }
            }
        }
        dialog.show()
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

    private fun confirm(message: String, save: () -> Unit) {
        AlertDialog.Builder(this)
            .setTitle(R.string.settings_confirm)
            .setMessage(message)
            .setPositiveButton(android.R.string.ok) { _, _ -> save(); build() }
            .setNegativeButton(android.R.string.cancel) { _, _ -> build() }
            .setOnCancelListener { build() }
            .show()
    }

    private fun setDomain(domain: String, allow: Boolean) {
        confirm(getString(if (allow) R.string.settings_allow_confirm else R.string.settings_block_confirm, domain)) {
            if (allow) ShieldSettings.setDomainAllowed(this, domain, true) else ShieldSettings.setDomainBlocked(this, domain, true)
            changed(SettingsChanges.Change.FILTER)
        }
    }

    private fun onAllowDomain() {
        val names = ShieldState.stats()?.recent.orEmpty()
        if (names.isEmpty()) {
            AlertDialog.Builder(this).setMessage(R.string.allow_empty).setPositiveButton(android.R.string.ok, null).show()
            return
        }
        AlertDialog.Builder(this)
            .setTitle(R.string.allow_title)
            .setItems(names.toTypedArray()) { _, which -> setDomain(names[which], allow = true) }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun onWatchedActivity() {
        val uid = ShieldVpnService.appUids(this, listOf(appPackage)).firstOrNull()
        val destinations = uid?.let { ShieldState.tunnel?.appActivity(it) }.orEmpty()
        if (destinations.isEmpty()) {
            AlertDialog.Builder(this).setMessage(R.string.watched_activity_empty).setPositiveButton(android.R.string.ok, null).show()
            return
        }
        val rows = destinations.map { getString(if (it.refused) R.string.watched_refused else R.string.watched_allowed, it.name) }
        AlertDialog.Builder(this)
            .setTitle(getString(R.string.watched_activity, appLabel))
            .setItems(rows.toTypedArray()) { _, which ->
                val destination = destinations[which]
                if (destination.name.any { it == ':' } || destination.name.all { it.isDigit() || it == '.' }) {
                    Toast.makeText(this, R.string.watched_address_hint, Toast.LENGTH_LONG).show()
                } else setDomain(destination.name, allow = destination.refused)
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun statusText(): String {
        val lines = mutableListOf(getString(R.string.settings_rules, ShieldState.rules))
        ShieldState.lists.forEach { list ->
            val updated = if (list.available) DateFormat.getDateFormat(this).format(Date(list.updatedAt)) else getString(R.string.list_missing)
            val failure = list.error?.let { " · " + getString(R.string.list_update_failed, it) }.orEmpty()
            lines += "${list.name}: $updated$failure"
        }
        ShieldState.stats()?.let { counters ->
            lines += getString(R.string.settings_counters, counters.queries, counters.blocked, counters.tcp, counters.udp, counters.quicRefused)
            lines += getString(R.string.settings_dns_failed, counters.dnsFailed)
            lines += getString(R.string.settings_flows_refused, counters.flowsRefused)
            lines += getString(R.string.settings_owner_unknown, counters.ownerDrops, counters.ownerNoMatch, counters.ownerTimeout, counters.ownerQueueFull, counters.ownerDisconnected)
            lines += getString(R.string.usage, Debug.getPss() / 1024, Process.getElapsedCpuTime() / 1000)
        }
        return lines.joinToString("\n")
    }

    private fun launchableApps(): List<Pair<String, String>> {
        val manager = packageManager
        return listOf(Intent.CATEGORY_LEANBACK_LAUNCHER, Intent.CATEGORY_LAUNCHER)
            .flatMap { category -> manager.queryIntentActivities(Intent(Intent.ACTION_MAIN).addCategory(category), PackageManager.MATCH_ALL) }
            .map { it.activityInfo.packageName to it.loadLabel(manager).toString() }
            .filter { it.first != packageName }
            .distinctBy { it.first }
            .sortedBy { it.second.lowercase() }
    }

    private fun dp(value: Int) = TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, value.toFloat(), resources.displayMetrics).toInt()

    private fun noteText(value: String, size: Float = 16f): TextView = TextView(this).apply {
        text = value
        setTextSize(TypedValue.COMPLEX_UNIT_SP, size)
        setTextColor(ContextCompat.getColor(context, R.color.text_secondary))
        setPadding(0, dp(6), 0, dp(6))
        content.addView(this)
    }

    private fun note(resource: Int) { noteText(getString(resource)) }

    private fun section(resource: Int) { noteText(getString(resource), 20f) }

    private fun <T : TextView> control(key: String, view: T): T = view.apply {
        id = View.generateViewId()
        setTextSize(TypedValue.COMPLEX_UNIT_SP, 18f)
        setTextColor(ContextCompat.getColor(context, R.color.text_primary))
        setBackgroundResource(R.drawable.row_focus)
        setPadding(dp(12), dp(10), dp(12), dp(10))
        minHeight = dp(56)
        controls[key] = this
        content.addView(this)
    }

    private fun checkbox(key: String, label: String, checked: Boolean, enabled: Boolean = true, onChange: (Boolean) -> Unit) {
        control(key, CheckBox(this)).apply {
            text = label
            isChecked = checked
            isEnabled = enabled
            isFocusable = enabled
            alpha = if (enabled) 1f else 0.5f
            buttonTintList = ContextCompat.getColorStateList(context, R.color.button_text_accent)
            setOnCheckedChangeListener { _, value -> onChange(value) }
        }
    }

    private fun button(key: String, label: String, onClick: () -> Unit): Button = control(key, Button(this)).apply {
        text = label
        isAllCaps = false
        textAlignment = View.TEXT_ALIGNMENT_VIEW_START
        setOnClickListener { onClick() }
    }
}
