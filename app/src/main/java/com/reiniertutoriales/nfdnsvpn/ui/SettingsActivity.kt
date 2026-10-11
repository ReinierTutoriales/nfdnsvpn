package com.reiniertutoriales.nfdnsvpn.ui

import android.app.AlertDialog
import android.content.ActivityNotFoundException
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
import android.os.Debug
import android.os.Process
import android.provider.Settings
import android.text.format.DateFormat
import android.util.TypedValue
import android.view.View
import android.widget.Button
import android.widget.CheckBox
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.core.content.ContextCompat
import com.reiniertutoriales.nfdnsvpn.R
import com.reiniertutoriales.nfdnsvpn.lists.ListRepository
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
            else if (filterChanged) ShieldVpnService.reload(this)
        }
        filterChanged = false
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

        section(R.string.settings_excluded)
        note(R.string.settings_excluded_note)
        val excluded = ShieldSettings.excludedApps(this)
        for ((packageName, label) in launchableApps()) {
            checkbox(label, packageName in excluded) { checked ->
                ShieldSettings.setAppExcluded(this, packageName, checked)
                restartNeeded = true
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
            lines += getString(R.string.usage, Debug.getPss() / 1024, Process.getElapsedCpuTime() / 1000)
        }
        return lines.joinToString("\n")
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
