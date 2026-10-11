package com.reiniertutoriales.nfdnsvpn.vpn

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.util.Log

/**
 * Brings protection back after the TV boots or the app is updated, if the user had it on.
 * Needs the VPN consent already granted: a receiver cannot show the consent dialog.
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED && intent.action != Intent.ACTION_MY_PACKAGE_REPLACED) return
        if (!ShieldSettings.startOnBoot(context) || !ShieldSettings.wantRunning(context)) return
        if (VpnService.prepare(context) != null) {
            Log.i("ShieldBoot", "VPN consent missing; open the app to turn protection on")
            return
        }
        ShieldVpnService.startFromBackground(context)
    }
}
