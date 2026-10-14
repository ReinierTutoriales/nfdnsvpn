package com.reiniertutoriales.nfdnsvpn.ui

import android.annotation.SuppressLint
import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.PowerManager
import android.os.SystemClock
import android.provider.Settings
import android.view.View
import android.widget.Button
import android.widget.TextView
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.net.toUri
import com.reiniertutoriales.nfdnsvpn.R
import com.reiniertutoriales.nfdnsvpn.vpn.ShieldSettings
import com.reiniertutoriales.nfdnsvpn.vpn.ShieldState
import com.reiniertutoriales.nfdnsvpn.vpn.ShieldVpnService
import java.text.NumberFormat

/**
 * One big switch. The first time it is turned on, the app asks Android for what it needs (VPN
 * consent, then to be left running); everything else has working defaults, so Options is optional.
 */
class MainActivity : ComponentActivity() {
    private companion object {
        /** A resolver that failed within this time still shows the warning. */
        const val DNS_WARNING_MS = 30_000L
    }

    private val handler = Handler(Looper.getMainLooper())
    private lateinit var toggle: Button
    private lateinit var status: TextView
    private lateinit var stats: TextView
    private lateinit var warning: TextView
    /** Unanswered DNS queries at the last refresh, and when that number last grew. */
    private var dnsFailed = -1L
    private var dnsFailingAt = 0L

    private val vpnConsent = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == Activity.RESULT_OK) turnOn() else ShieldState.error = getString(R.string.error_no_permission)
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
        status = findViewById(R.id.status)
        stats = findViewById(R.id.stats)
        warning = findViewById(R.id.warning)
        toggle.setOnClickListener { onToggle() }
        findViewById<Button>(R.id.options).setOnClickListener { startActivity(Intent(this, SettingsActivity::class.java)) }
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
            if (consent != null) vpnConsent.launch(consent) else turnOn()
        }
        render()
    }

    private fun turnOn() {
        ShieldVpnService.start(this)
        askToKeepRunningOnce()
    }

    /**
     * Asks once to be left out of battery optimisation, so Android does not stop the protection to
     * save power. Some TVs have no such screen; then there is nothing to ask.
     */
    @SuppressLint("BatteryLife") // a system-wide filter is the exemption's intended use; not on Play
    private fun askToKeepRunningOnce() {
        if (ShieldSettings.askedToKeepRunning(this)) return
        ShieldSettings.setAskedToKeepRunning(this)
        val power = getSystemService(PowerManager::class.java)
        if (power.isIgnoringBatteryOptimizations(packageName)) return
        try {
            startActivity(Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, "package:$packageName".toUri()))
        } catch (e: ActivityNotFoundException) {
            // Not offered on this device.
        }
    }

    private fun render() {
        val phase = ShieldState.phase
        val on = phase != ShieldState.Phase.STOPPED
        toggle.isActivated = phase == ShieldState.Phase.RUNNING
        toggle.setText(if (on) R.string.power_on else R.string.power_off)
        status.setText(
            when (phase) {
                ShieldState.Phase.STOPPED -> R.string.status_stopped
                ShieldState.Phase.STARTING -> R.string.status_starting
                ShieldState.Phase.RUNNING -> if (ShieldState.fullTunnel) R.string.status_running_full else R.string.status_running_light
                ShieldState.Phase.DEGRADED -> R.string.status_degraded
            }
        )
        val counters = ShieldState.stats()
        val now = SystemClock.elapsedRealtime()
        counters?.dnsFailed?.let { failed ->
            if (dnsFailed >= 0 && failed > dnsFailed) dnsFailingAt = now
            dnsFailed = failed
        }
        val dnsFailing = phase == ShieldState.Phase.RUNNING && dnsFailingAt > 0 && now - dnsFailingAt < DNS_WARNING_MS
        stats.text = if (phase == ShieldState.Phase.RUNNING && counters != null)
            getString(R.string.blocked_count, NumberFormat.getIntegerInstance().format(counters.blocked)) else ""

        // Only what stops the protection from working: there is nothing else to fix by hand.
        val problems = listOfNotNull(
            if (phase == ShieldState.Phase.DEGRADED) getString(R.string.warning_degraded, ShieldState.degradedReason.orEmpty()) else null,
            ShieldState.error?.let { getString(R.string.error_prefix, it) },
            ShieldState.privateDnsStrict?.let { getString(R.string.warning_private_dns, it) },
            getString(R.string.warning_dns_failing).takeIf { dnsFailing },
        )
        warning.visibility = if (problems.isEmpty()) View.GONE else View.VISIBLE
        warning.text = problems.joinToString("\n\n")
    }
}
