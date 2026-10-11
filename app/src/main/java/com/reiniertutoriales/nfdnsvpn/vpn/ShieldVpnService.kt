package com.reiniertutoriales.nfdnsvpn.vpn

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.Process
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import com.reiniertutoriales.nfdnsvpn.R
import com.reiniertutoriales.nfdnsvpn.core.ConnectionOwner
import com.reiniertutoriales.nfdnsvpn.core.NativeCore
import com.reiniertutoriales.nfdnsvpn.core.NativeTunnel
import com.reiniertutoriales.nfdnsvpn.lists.ListRepository
import com.reiniertutoriales.nfdnsvpn.ui.MainActivity
import java.io.IOException
import java.net.Inet4Address
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
        /** Applies a mode or app-exclusion change: stops the running tunnel and starts a new one. */
        const val ACTION_RESTART = "com.reiniertutoriales.nfdnsvpn.RESTART"
        /** Applies a list or allowlist change without dropping connections. */
        const val ACTION_RELOAD = "com.reiniertutoriales.nfdnsvpn.RELOAD"
        /** Applies a blocked-app change at once (no filter rebuild). Watched apps need a restart. */
        const val ACTION_BLOCKED_APPS = "com.reiniertutoriales.nfdnsvpn.BLOCKED_APPS"
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

        /** How often due lists are looked for; each list is still downloaded at most once a day. */
        private const val LIST_CHECK_HOURS = 6L

        private val virtualAddresses = listOf(DNS_V4, DNS_V6, CLIENT_V4, CLIENT_V6).map(InetAddress::getByName)

        fun isVirtualAddress(address: InetAddress) = address in virtualAddresses

        /**
         * Uids of installed packages. Uids below the first app uid are shared by system
         * components and never get a rule.
         */
        fun appUids(context: Context, packages: Collection<String>): IntArray = packages.mapNotNull { app ->
            try {
                context.packageManager.getApplicationInfo(app, 0).uid.takeIf { it >= Process.FIRST_APPLICATION_UID }
            } catch (e: PackageManager.NameNotFoundException) {
                null
            }
        }.distinct().toIntArray()

        fun start(context: Context) = send(context, ACTION_START)
        fun stop(context: Context) = send(context, ACTION_STOP)
        fun restart(context: Context) = send(context, ACTION_RESTART)
        fun reload(context: Context) = send(context, ACTION_RELOAD)
        fun applyBlockedApps(context: Context) = send(context, ACTION_BLOCKED_APPS)

        private fun send(context: Context, action: String) {
            context.startService(Intent(context, ShieldVpnService::class.java).setAction(action))
        }

        /** From the background (boot, app update): only a foreground service may start there. */
        fun startFromBackground(context: Context) {
            ContextCompat.startForegroundService(context, Intent(context, ShieldVpnService::class.java).setAction(ACTION_START))
        }
    }

    @Volatile private var stopping = false
    @Volatile private var tunnel: NativeTunnel? = null
    /** Daily list checks and filter rebuilds, one at a time, for the running tunnel. */
    @Volatile private var maintenance: ScheduledExecutorService? = null
    private var worker: Thread? = null

    override fun onCreate() {
        super.onCreate()
        if (Build.VERSION.SDK_INT >= 29) {
            val connectivity = getSystemService(ConnectivityManager::class.java)
            ConnectionOwner.lookup = { protocol, local, remote -> connectivity.getConnectionOwnerUid(protocol, local, remote) }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                ShieldSettings.setWantRunning(this, false)
                shutdown()
                stopSelf()
                return START_NOT_STICKY
            }
            ACTION_RESTART -> shutdown()
            ACTION_RELOAD, ACTION_BLOCKED_APPS -> {
                val jobs = maintenance
                val reload = intent.action == ACTION_RELOAD
                val job = Runnable { if (reload) reloadFilter() else tunnel?.let(::applyAppRules) }
                when {
                    jobs != null -> jobs.execute(job)
                    // Not running: the next start loads the current settings anyway. Do not leave
                    // behind a service that this intent alone created.
                    worker == null -> stopSelf(startId)
                }
                // The latest return value decides whether Android restarts a killed service.
                return if (worker != null) START_STICKY else START_NOT_STICKY
            }
        }
        ShieldSettings.setWantRunning(this, true)
        // ACTION_START from the UI, or SERVICE_INTERFACE when Android starts an always-on VPN.
        promoteToForeground()
        if (worker == null) {
            stopping = false
            worker = Thread(::run, "shield-tunnel").also { it.start() }
        }
        return START_STICKY
    }

    /** Another VPN took over, or the user revoked consent: do not come back on the next boot. */
    override fun onRevoke() {
        ShieldSettings.setWantRunning(this, false)
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
        var filter = 0L
        var tun: ParcelFileDescriptor? = null
        var upstream: UpstreamDns? = null
        var current: NativeTunnel? = null
        var jobs: ScheduledExecutorService? = null
        try {
            filter = loadFilter()
            val servers = AtomicReference<List<String>>(emptyList())
            upstream = UpstreamDns(this, onServers = { list ->
                servers.set(list)
                tunnel?.setUpstream(list)
            }, onPrivateDns = { ShieldState.privateDnsStrict = it })
            if (stopping) return
            tun = establish(fullTunnel, upstream.hasIpv6, upstream.initialServers) ?: throw IOException(getString(R.string.error_no_permission))
            // Without "Block connections without VPN", traffic flows unfiltered whenever this
            // service is not running (crash, update, low memory kill): the screen warns about it.
            ShieldState.lockdown = Build.VERSION.SDK_INT < 29 || isLockdownEnabled
            // The tunnel takes over the filter handle.
            current = NativeTunnel(filter, tun.fd, INTERCEPTED).also { filter = 0L }
            // Published before the first push, so a network change in between is not lost.
            tunnel = current
            ShieldState.tunnel = current
            current.setUpstream(servers.get())
            applyAppRules(current)
            if (stopping) return
            jobs = Executors.newSingleThreadScheduledExecutor().apply {
                scheduleWithFixedDelay(::refreshDueLists, LIST_CHECK_HOURS, LIST_CHECK_HOURS, TimeUnit.HOURS)
            }
            maintenance = jobs
            ShieldState.phase = ShieldState.Phase.RUNNING
            val failure = current.run()
            if (failure.isNotEmpty() && !stopping) throw IOException(failure)
        } catch (e: Exception) {
            if (!stopping) {
                Log.e(TAG, "VPN stopped", e)
                ShieldState.error = e.message ?: e.javaClass.simpleName
            }
        } finally {
            maintenance = null
            ShieldState.tunnel = null
            jobs?.shutdownNow()
            // A rebuild in progress hands its filter to the tunnel or frees it (NativeTunnel.setFilter).
            runCatching { jobs?.awaitTermination(10, TimeUnit.SECONDS) }
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

    private fun refreshDueLists() {
        if (ListRepository(this).isDue(ShieldSettings.enabledLists(this))) reloadFilter()
    }

    /** Builds a filter from the current lists and settings and swaps it into the running tunnel. */
    private fun reloadFilter() {
        try {
            val filter = loadFilter()
            tunnel?.setFilter(filter) ?: NativeCore.nativeDestroy(filter)
        } catch (e: Exception) {
            Log.e(TAG, "Filter reload failed; the previous filter stays in use", e)
        }
    }

    /**
     * Blocked apps lose every new connection; watched apps keep only readable, allowed names and
     * addresses our DNS gave out. Needs Android 10+ (to learn who owns a connection) and the full
     * mode (all their traffic reaches the tunnel).
     */
    private fun applyAppRules(target: NativeTunnel) {
        if (Build.VERSION.SDK_INT < 29) return
        target.setBlockedApps(appUids(this, ShieldSettings.blockedApps(this)))
        target.setWatchedApps(appUids(this, ShieldSettings.watchedApps(this)))
    }

    /** Compiles the enabled lists straight from their files; returns a filter handle. */
    private fun loadFilter(): Long {
        val repository = ListRepository(this)
        val lists = repository.load(ShieldSettings.enabledLists(this))
        ShieldState.lists = lists.status
        val builder = NativeCore.nativeBuilderNew()
        try {
            NativeCore.nativeBuilderAddText(builder, repository.bundledRules())
            NativeCore.nativeBuilderAddText(builder, ShieldSettings.allowlistRules(ShieldSettings.allowedDomains(this)))
            NativeCore.nativeBuilderAddText(builder, ShieldSettings.blocklistRules(ShieldSettings.blockedDomains(this)))
            for (file in lists.files) {
                if (!NativeCore.nativeBuilderAddFile(builder, file.absolutePath)) Log.w(TAG, "Unreadable list ${file.name}")
            }
        } catch (e: RuntimeException) {
            NativeCore.nativeBuilderDestroy(builder)
            throw e
        }
        val handle = NativeCore.nativeBuilderBuild(builder)
        ShieldState.rules = NativeCore.nativeRuleCount(handle)
        return handle
    }

    private fun establish(fullTunnel: Boolean, hasIpv6: Boolean, networkResolvers: List<InetAddress>): ParcelFileDescriptor? {
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
        // The router's DNS is on the LAN, which the full tunnel leaves out: route just that
        // address, so DNS sent straight to it is filtered while the rest of the LAN stays direct.
        for (resolver in networkResolvers) {
            runCatching { builder.addRoute(resolver, if (resolver is Inet4Address) 32 else 128) }
                .onFailure { Log.w(TAG, "Cannot route resolver ${resolver.hostAddress}", it) }
        }
        if (fullTunnel) {
            Routes.fullV4.forEach { builder.addRoute(it.address, it.prefix) }
            // Without IPv6 upstream, routing ::/0 would make apps try IPv6 first and fail.
            if (hasIpv6) Routes.FULL_V6.forEach { builder.addRoute(it.address, it.prefix) }
        }
        // Our own list downloads, DNS forwarding and relay sockets must not loop back.
        builder.addDisallowedApplication(packageName)
        // A blocked or watched app must stay in the tunnel, or its rule could not apply.
        for (app in ShieldSettings.excludedApps(this) - ShieldSettings.blockedApps(this) - ShieldSettings.watchedApps(this)) {
            try {
                builder.addDisallowedApplication(app)
            } catch (e: PackageManager.NameNotFoundException) {
                Log.i(TAG, "Excluded app $app is no longer installed")
            }
        }
        // VPNs are metered by default since Android 10, which makes streaming apps lower quality.
        if (Build.VERSION.SDK_INT >= 29) builder.setMetered(false)
        return builder.establish()
    }
}
