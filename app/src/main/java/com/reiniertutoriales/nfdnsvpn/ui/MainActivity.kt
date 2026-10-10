package com.reiniertutoriales.nfdnsvpn.ui

import android.app.Activity
import android.net.VpnService
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.format.DateFormat
import android.view.View
import android.widget.Button
import android.widget.TextView
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts
import com.reiniertutoriales.nfdnsvpn.R
import com.reiniertutoriales.nfdnsvpn.vpn.ShieldState
import com.reiniertutoriales.nfdnsvpn.vpn.ShieldVpnService
import java.util.Date

/** One screen for the remote: on/off, counters, warnings and the latest blocked names. */
class MainActivity : ComponentActivity() {
    private val handler = Handler(Looper.getMainLooper())
    private lateinit var toggle: Button
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
        status = findViewById(R.id.status)
        stats = findViewById(R.id.stats)
        warning = findViewById(R.id.warning)
        lists = findViewById(R.id.lists)
        recent = findViewById(R.id.recent)
        toggle.setOnClickListener { onToggle() }
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

    private fun render() {
        val phase = ShieldState.phase
        toggle.setText(if (phase == ShieldState.Phase.STOPPED) R.string.action_start else R.string.action_stop)
        status.setText(
            when (phase) {
                ShieldState.Phase.STOPPED -> R.string.status_stopped
                ShieldState.Phase.STARTING -> R.string.status_starting
                ShieldState.Phase.RUNNING -> R.string.status_running
            }
        )
        stats.text = getString(R.string.stats, ShieldState.rules, ShieldState.queries.get(), ShieldState.blocked.get())

        val problems = listOfNotNull(
            ShieldState.error?.let { getString(R.string.error_prefix, it) },
            ShieldState.privateDnsStrict?.let { getString(R.string.warning_private_dns, it) },
        )
        warning.visibility = if (problems.isEmpty()) View.GONE else View.VISIBLE
        warning.text = problems.joinToString("\n\n")

        lists.text = ShieldState.lists.joinToString("\n") { list ->
            val updated = if (list.available) DateFormat.getDateFormat(this).format(Date(list.updatedAt))
                else getString(R.string.list_missing)
            val failure = list.error?.let { " · " + getString(R.string.list_update_failed, it) } ?: ""
            "${list.name}: $updated$failure"
        }

        val names = ShieldState.recentBlocked()
        recent.text = if (names.isEmpty()) getString(R.string.recent_empty) else names.joinToString("\n")
    }
}
