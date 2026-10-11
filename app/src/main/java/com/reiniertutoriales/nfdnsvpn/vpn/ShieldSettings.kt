package com.reiniertutoriales.nfdnsvpn.vpn

import android.content.Context
import androidx.core.content.edit

/** User choices that outlive the VPN session. */
object ShieldSettings {
    private const val FILE = "settings"
    private const val FULL_TUNNEL = "fullTunnel"

    /**
     * Full tunnel: all traffic goes through the app (DNS, plus the stack and relay). Off by default
     * until it has been measured on the target TV; light mode only routes DNS.
     */
    fun isFullTunnel(context: Context) =
        context.getSharedPreferences(FILE, Context.MODE_PRIVATE).getBoolean(FULL_TUNNEL, false)

    fun setFullTunnel(context: Context, enabled: Boolean) {
        context.getSharedPreferences(FILE, Context.MODE_PRIVATE).edit { putBoolean(FULL_TUNNEL, enabled) }
    }
}
