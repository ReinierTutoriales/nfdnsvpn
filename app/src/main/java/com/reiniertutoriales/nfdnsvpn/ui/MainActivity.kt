package com.reiniertutoriales.nfdnsvpn.ui

import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.os.Debug
import android.os.Process
import android.os.Handler
import android.os.Looper
import android.text.format.DateFormat
import android.view.View
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts
import com.reiniertutoriales.nfdnsvpn.R
import com.reiniertutoriales.nfdnsvpn.vpn.ShieldSettings
import com.reiniertutoriales.nfdnsvpn.vpn.ShieldState
import com.reiniertutoriales.nfdnsvpn.vpn.ShieldVpnService
import java.util.Date

/** One screen for the remote: on/off, counters, warnings and the latest blocked names. */
class MainActivity : ComponentActivity() {
    private val handler = Handler(Looper.getMainLooper())
    private lateinit var toggle: Button
    private lateinit var mode: Button
    private lateinit var status: TextView
    private lateinit var stats: TextView
    private lateinit var warning: TextView
    private lateinit var lists: TextView
    private lateinit var recent: TextView

    private val vpnConsent = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == Activity.RESULT_OK) ShieldVpnService.start(this)
        else ShieldState.error = getString(R.string.error_no_permission)
        render()
    }

    private val refresh = object : Runnable {
        override fun run() {
            render()
            handler.postDelayed(this, 1000)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        toggle = findViewById(R.id.toggle)
        mode = findViewById(R.id.mode)
        status = findViewById(R.id.status)
        stats = findViewById(R.id.stats)
        warning = findViewById(R.id.warning)
        lists = findViewById(R.id.lists)
        recent = findViewById(R.id.recent)
        toggle.setOnClickListener { onToggle() }
        mode.setOnClickListener { onModeChange() }
        findViewById<Button>(R.id.allow).setOnClickListener { onAllowDomain() }
        findViewById<Button>(R.id.settings).setOnClickListener { startActivity(Intent(this, SettingsActivity::class.java)) }
        toggle.requestFocus()
    }

    override fun onResume() {
        super.onResume()
        handler.post(refresh)
    }

    override fun onPause() {
        handler.removeCallbacks(refresh)
        super.onPause()
    }

    private fun onToggle() {
        if (ShieldState.phase != ShieldState.Phase.STOPPED) {
            ShieldVpnService.stop(this)
        } else {
            ShieldState.error = null
            val consent = VpnService.prepare(this)
            if (consent != null) vpnConsent.launch(consent) else ShieldVpnService.start(this)
        }
        render()
    }

    /** Takes effect at once when the VPN is running, otherwise on the next start. */
    private fun onModeChange() {
        ShieldSettings.setFullTunnel(this, !ShieldSettings.isFullTunnel(this))
        if (ShieldState.phase != ShieldState.Phase.STOPPED) ShieldVpnService.restart(this)
        render()
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
                ShieldVpnService.reload(this)
                Toast.makeText(this, R.string.allow_hint, Toast.LENGTH_LONG).show()
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun render() {
        val phase = ShieldState.phase
        toggle.setText(if (phase == ShieldState.Phase.STOPPED) R.string.action_start else R.string.action_stop)
        status.setText(
            when (phase) {
                ShieldState.Phase.STOPPED -> R.string.status_stopped
                ShieldState.Phase.STARTING -> R.string.status_starting
                ShieldState.Phase.RUNNING ->
                    if (ShieldState.fullTunnel) R.string.status_running_full else R.string.status_running_light
            }
        )
        mode.setText(if (ShieldSettings.isFullTunnel(this)) R.string.mode_full else R.string.mode_light)
        val counters = ShieldState.stats()
        val lines = mutableListOf(getString(R.string.stats, ShieldState.rules, counters?.queries ?: 0L, counters?.blocked ?: 0L))
        if (phase == ShieldState.Phase.RUNNING && ShieldState.fullTunnel && counters != null) {
            lines += getString(R.string.stats_connections, counters.tcp, counters.udp, counters.quicRefused)
        }
        if (phase == ShieldState.Phase.RUNNING) {
            // Whole app process: tunnel core, stack buffers and UI (phase 6 measurement).
            lines += getString(R.string.usage, Debug.getPss() / 1024, Process.getElapsedCpuTime() / 1000)
        }
        stats.text = lines.joinToString("\n")

        val problems = listOfNotNull(
            ShieldState.error?.let { getString(R.string.error_prefix, it) },
            ShieldState.privateDnsStrict?.let { getString(R.string.warning_private_dns, it) },
            getString(R.string.warning_lockdown).takeIf { phase == ShieldState.Phase.RUNNING && !ShieldState.lockdown },
        )
        warning.visibility = if (problems.isEmpty()) View.GONE else View.VISIBLE
        warning.text = problems.joinToString("\n\n")

        lists.text = ShieldState.lists.joinToString("\n") { list ->
            val updated = if (list.available) DateFormat.getDateFormat(this).format(Date(list.updatedAt))
                else getString(R.string.list_missing)
            val failure = list.error?.let { " · " + getString(R.string.list_update_failed, it) } ?: ""
            "${list.name}: $updated$failure"
        }

        val names = counters?.recent.orEmpty()
        recent.text = if (names.isEmpty()) getString(R.string.recent_empty) else names.joinToString("\n")
    }
}
