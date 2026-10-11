package com.reiniertutoriales.nfdnsvpn.ui

import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
import android.util.TypedValue
import android.view.View
import android.widget.Button
import android.widget.CheckBox
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.activity.ComponentActivity
import androidx.core.content.ContextCompat
import com.reiniertutoriales.nfdnsvpn.R
import com.reiniertutoriales.nfdnsvpn.lists.ListRepository
import com.reiniertutoriales.nfdnsvpn.vpn.ShieldSettings
import com.reiniertutoriales.nfdnsvpn.vpn.ShieldState
import com.reiniertutoriales.nfdnsvpn.vpn.ShieldVpnService

/**
 * Settings for the remote: every row is a focusable checkbox or button in one vertical list, so
 * the D-pad reaches everything. Changes apply when leaving the screen: lists and allowlist by
 * swapping the filter, app exclusions by restarting the tunnel (routes are fixed per session).
 */
class SettingsActivity : ComponentActivity() {
    private lateinit var content: LinearLayout
    private var filterChanged = false
    private var exclusionsChanged = false

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
            if (exclusionsChanged) ShieldVpnService.restart(this)
            else if (filterChanged) ShieldVpnService.reload(this)
        }
        filterChanged = false
        exclusionsChanged = false
    }

    private fun build() {
        content.removeAllViews()
        title(R.string.settings_title, 28f)

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
                exclusionsChanged = true
            }
        }
        content.getChildAt(2)?.requestFocus()
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
