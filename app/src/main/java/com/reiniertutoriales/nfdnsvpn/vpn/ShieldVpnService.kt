package com.reiniertutoriales.nfdnsvpn.vpn

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import com.reiniertutoriales.nfdnsvpn.R
import com.reiniertutoriales.nfdnsvpn.core.NativeCore
import com.reiniertutoriales.nfdnsvpn.core.NativeTunnel
import com.reiniertutoriales.nfdnsvpn.lists.ListRepository
import com.reiniertutoriales.nfdnsvpn.ui.MainActivity
import java.io.IOException
import java.net.InetAddress
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/**
 * Local VPN. The packet loop runs in the Rust core ([NativeTunnel]) in both modes:
 * - light: only DNS reaches the TUN (a virtual resolver plus the public resolvers' addresses);
 * - full: all traffic except LAN and multicast, terminated by a userspace TCP/IP stack and relayed.
 * The app excludes itself, so the core's own sockets never loop back into the tunnel.
 */
class ShieldVpnService : VpnService() {
    companion object {
        private const val TAG = "ShieldVpn"
        const val ACTION_START = "com.reiniertutoriales.nfdnsvpn.START"
        const val ACTION_STOP = "com.reiniertutoriales.nfdnsvpn.STOP"
        /** Applies a mode change: stops the running tunnel and starts a new one. */
        const val ACTION_RESTART = "com.reiniertutoriales.nfdnsvpn.RESTART"
        private const val CHANNEL = "shield"
        private const val NOTIFICATION_ID = 1

        private const val CLIENT_V4 = "10.111.0.2"
        private const val DNS_V4 = "10.111.0.1"
        private const val CLIENT_V6 = "fd00:6e66::2"
        private const val DNS_V6 = "fd00:6e66::1"

        /** Google, Cloudflare, Quad9, OpenDNS and AdGuard: plain DNS, DoT and DoH endpoints. */
        private val PUBLIC_RESOLVERS_V4 = listOf(
            "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112",
            "208.67.222.222", "208.67.220.220", "94.140.14.14", "94.140.15.15",
        )
        private val PUBLIC_RESOLVERS_V6 = listOf(
            "2001:4860:4860::8888", "2001:4860:4860::8844", "2606:4700:4700::1111", "2606:4700:4700::1001",
            "2620:fe::fe", "2620:fe::9", "2620:119:35::35", "2620:119:53::53",
        )
        /** Resolver addresses whose non-DNS traffic (DoH, QUIC) is refused by the core. */
        private val INTERCEPTED = listOf(DNS_V4, DNS_V6) + PUBLIC_RESOLVERS_V4 + PUBLIC_RESOLVERS_V6

        private const val STATS_INTERVAL_MS = 1000L

        private val virtualAddresses = listOf(DNS_V4, DNS_V6, CLIENT_V4, CLIENT_V6).map(InetAddress::getByName)

        fun isVirtualAddress(address: InetAddress) = address in virtualAddresses

        fun start(context: Context) = send(context, ACTION_START)
        fun stop(context: Context) = send(context, ACTION_STOP)
        fun restart(context: Context) = send(context, ACTION_RESTART)

        private fun send(context: Context, action: String) {
            context.startService(Intent(context, ShieldVpnService::class.java).setAction(action))
        }
    }

    @Volatile private var stopping = false
    @Volatile private var tunnel: NativeTunnel? = null
    private var worker: Thread? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                shutdown()
                stopSelf()
                return START_NOT_STICKY
            }
            ACTION_RESTART -> shutdown()
        }
        // ACTION_START from the UI, or SERVICE_INTERFACE when Android starts an always-on VPN.
        promoteToForeground()
        if (worker == null) {
            stopping = false
            worker = Thread(::run, "shield-tunnel").also { it.start() }
        }
        return START_STICKY
    }

    override fun onRevoke() {
        shutdown()
        stopSelf()
    }

    override fun onDestroy() {
        shutdown()
        super.onDestroy()
    }

    private fun shutdown() {
        stopping = true
        tunnel?.stop()
        worker?.let { thread ->
            thread.interrupt()
            runCatching { thread.join(3000) }
        }
        worker = null
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
    }

    /**
     * Keeps the notification visible. The VPN keeps running without it (the system holds an
     * established VpnService), so a refusal is logged rather than fatal.
     */
    private fun promoteToForeground() {
        val manager = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= 26) {
            manager.createNotificationChannel(
                NotificationChannel(CHANNEL, getString(R.string.notification_channel), NotificationManager.IMPORTANCE_LOW)
            )
        }
        val open = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val notification = NotificationCompat.Builder(this, CHANNEL)
            .setSmallIcon(R.drawable.ic_shield)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(getString(R.string.notification_text))
            .setContentIntent(open)
            .setOngoing(true)
            .build()
        val type = if (Build.VERSION.SDK_INT >= 34) ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE else 0
        try {
            ServiceCompat.startForeground(this, NOTIFICATION_ID, notification, type)
        } catch (e: RuntimeException) {
            Log.w(TAG, "Foreground service refused; continuing as a plain VPN service", e)
        }
    }

    private fun run() {
        val fullTunnel = ShieldSettings.isFullTunnel(this)
        ShieldState.phase = ShieldState.Phase.STARTING
        ShieldState.fullTunnel = fullTunnel
        ShieldState.error = null
        ShieldState.stats = null
        var filter = 0L
        var tun: ParcelFileDescriptor? = null
        var upstream: UpstreamDns? = null
        var current: NativeTunnel? = null
        var poller: ScheduledExecutorService? = null
        try {
            filter = loadFilter()
            val servers = AtomicReference<List<String>>(emptyList())
            upstream = UpstreamDns(this, onServers = { list ->
                servers.set(list)
                tunnel?.setUpstream(list)
            }, onPrivateDns = { ShieldState.privateDnsStrict = it })
            if (stopping) return
            tun = establish(fullTunnel, upstream.hasIpv6) ?: throw IOException(getString(R.string.error_no_permission))
            // The tunnel takes over the filter handle.
            current = NativeTunnel(filter, tun.fd, INTERCEPTED).also { filter = 0L }
            // Published before the first push, so a network change in between is not lost.
            tunnel = current
            current.setUpstream(servers.get())
            if (stopping) return
            poller = Executors.newSingleThreadScheduledExecutor().apply {
                scheduleWithFixedDelay({ ShieldState.stats = current.stats() }, 0, STATS_INTERVAL_MS, TimeUnit.MILLISECONDS)
            }
            ShieldState.phase = ShieldState.Phase.RUNNING
            val failure = current.run()
            if (failure.isNotEmpty() && !stopping) throw IOException(failure)
        } catch (e: Exception) {
            if (!stopping) {
                Log.e(TAG, "VPN stopped", e)
                ShieldState.error = e.message ?: e.javaClass.simpleName
            }
        } finally {
            poller?.shutdownNow()
            runCatching { poller?.awaitTermination(2, TimeUnit.SECONDS) }
            tunnel = null
            // run() has returned (or never started), so nothing else uses the native tunnel.
            current?.close()
            if (filter != 0L) NativeCore.nativeDestroy(filter)
            upstream?.close()
            runCatching { tun?.close() }
            ShieldState.phase = ShieldState.Phase.STOPPED
            if (!stopping) stopSelf()
        }
    }

    /** Separate frame so the list text (~17 MB as UTF-16) is collectable once compiled. */
    private fun loadFilter(): Long {
        val lists = ListRepository(this).load()
        ShieldState.lists = lists.status
        val handle = NativeCore.nativeCreate(lists.texts.toTypedArray())
        ShieldState.rules = NativeCore.nativeRuleCount(handle)
        return handle
    }

    private fun establish(fullTunnel: Boolean, hasIpv6: Boolean): ParcelFileDescriptor? {
        val builder = Builder()
            .setSession(getString(R.string.app_name))
            .setMtu(1500)
            .addAddress(CLIENT_V4, 32)
            .addDnsServer(DNS_V4)
            .addRoute(DNS_V4, 32)
            .addAddress(CLIENT_V6, 128)
            .addDnsServer(DNS_V6)
            .addRoute(DNS_V6, 128)
            .setBlocking(false)
            .setConfigureIntent(
                PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
            )
        PUBLIC_RESOLVERS_V4.forEach { builder.addRoute(it, 32) }
        PUBLIC_RESOLVERS_V6.forEach { builder.addRoute(it, 128) }
        if (fullTunnel) {
            Routes.fullV4.forEach { builder.addRoute(it.address, it.prefix) }
            // Without IPv6 upstream, routing ::/0 would make apps try IPv6 first and fail.
            if (hasIpv6) Routes.FULL_V6.forEach { builder.addRoute(it.address, it.prefix) }
        }
        // Our own list downloads, DNS forwarding and relay sockets must not loop back.
        builder.addDisallowedApplication(packageName)
        // VPNs are metered by default since Android 10, which makes streaming apps lower quality.
        if (Build.VERSION.SDK_INT >= 29) builder.setMetered(false)
        return builder.establish()
    }
}
