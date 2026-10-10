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
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import com.reiniertutoriales.nfdnsvpn.R
import com.reiniertutoriales.nfdnsvpn.core.NativeCore
import com.reiniertutoriales.nfdnsvpn.core.PacketAction
import com.reiniertutoriales.nfdnsvpn.lists.ListRepository
import com.reiniertutoriales.nfdnsvpn.ui.MainActivity
import java.io.FileDescriptor
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit

/**
 * Light mode (phase 1): only DNS reaches the TUN. The device resolver points at a virtual
 * address inside the tunnel, and the well-known public resolvers are routed into it as well, so
 * apps that hardcode 8.8.8.8 or 1.1.1.1 are filtered too. Everything else goes out directly.
 */
class ShieldVpnService : VpnService() {
    companion object {
        private const val TAG = "ShieldVpn"
        const val ACTION_START = "com.reiniertutoriales.nfdnsvpn.START"
        const val ACTION_STOP = "com.reiniertutoriales.nfdnsvpn.STOP"
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

        private const val DNS_PORT = 53
        private const val UPSTREAM_TIMEOUT_MS = 2500
        private const val MAX_PACKET = 32767
        private const val MAX_DNS_MESSAGE = 65535
        private const val POLL_MS = 500

        private val virtualAddresses = listOf(DNS_V4, DNS_V6, CLIENT_V4, CLIENT_V6).map(InetAddress::getByName)

        fun isVirtualAddress(address: InetAddress) = address in virtualAddresses

        fun start(context: Context) {
            context.startService(Intent(context, ShieldVpnService::class.java).setAction(ACTION_START))
        }

        fun stop(context: Context) {
            context.startService(Intent(context, ShieldVpnService::class.java).setAction(ACTION_STOP))
        }
    }

    @Volatile private var stopping = false
    private var worker: Thread? = null
    /** Guards TUN writes against close: a closed fd number can be reused by another file. */
    private val tunLock = Any()
    private var tunClosed = true

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            shutdown()
            stopSelf()
            return START_NOT_STICKY
        }
        // ACTION_START from the UI, or SERVICE_INTERFACE when Android starts an always-on VPN.
        promoteToForeground()
        if (worker == null) {
            stopping = false
            worker = Thread(::run, "shield-tun").also { it.start() }
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
        ShieldState.phase = ShieldState.Phase.STARTING
        ShieldState.error = null
        var handle = 0L
        var tun: ParcelFileDescriptor? = null
        var upstream: UpstreamDns? = null
        val forwarders = ThreadPoolExecutor(2, 16, 30, TimeUnit.SECONDS, ArrayBlockingQueue(256), ThreadPoolExecutor.DiscardPolicy())
        try {
            handle = loadFilter()
            upstream = UpstreamDns(this) { ShieldState.privateDnsStrict = it }
            if (stopping) return
            tun = establish() ?: throw IOException(getString(R.string.error_no_permission))
            synchronized(tunLock) { tunClosed = false }
            ShieldState.resetCounters()
            ShieldState.phase = ShieldState.Phase.RUNNING
            loop(tun.fileDescriptor, handle, upstream, forwarders)
        } catch (e: Exception) {
            if (!stopping) {
                Log.e(TAG, "VPN stopped", e)
                ShieldState.error = e.message ?: e.javaClass.simpleName
            }
        } finally {
            forwarders.shutdownNow()
            runCatching { forwarders.awaitTermination(3, TimeUnit.SECONDS) }
            synchronized(tunLock) {
                tunClosed = true
                runCatching { tun?.close() }
            }
            upstream?.close()
            // Forward tasks never touch the filter handle, so it can go once the loop ended.
            if (handle != 0L) NativeCore.nativeDestroy(handle)
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

    private fun establish(): ParcelFileDescriptor? {
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
        // Our own list downloads and upstream queries must not loop back into the tunnel.
        builder.addDisallowedApplication(packageName)
        // VPNs are metered by default since Android 10, which makes streaming apps lower quality.
        if (Build.VERSION.SDK_INT >= 29) builder.setMetered(false)
        return builder.establish()
    }

    private fun loop(fd: FileDescriptor, handle: Long, upstream: UpstreamDns, forwarders: ThreadPoolExecutor) {
        val buffer = ByteArray(MAX_PACKET)
        val poll = arrayOf(StructPollfd().apply { this.fd = fd; events = OsConstants.POLLIN.toShort() })
        while (!stopping) {
            // A timed poll instead of a blocking read: closing a TUN fd does not wake a blocked read.
            val length = try {
                if (Os.poll(poll, POLL_MS) == 0) continue
                Os.read(fd, buffer, 0, buffer.size)
            } catch (e: ErrnoException) {
                if (e.errno == OsConstants.EAGAIN || e.errno == OsConstants.EINTR) continue
                throw e
            }
            if (length <= 0) continue
            val packet = buffer.copyOf(length)
            when (val action = PacketAction.decode(NativeCore.nativeHandle(handle, packet))) {
                is PacketAction.Blocked -> {
                    ShieldState.queries.incrementAndGet()
                    ShieldState.recordBlocked(action.name)
                    write(fd, action.packet)
                }
                is PacketAction.Reset -> write(fd, action.packet)
                is PacketAction.Forward -> {
                    ShieldState.queries.incrementAndGet()
                    forwarders.execute { forward(fd, packet, action.query, upstream) }
                }
                PacketAction.Ignore -> Unit
            }
        }
    }

    private fun forward(fd: FileDescriptor, request: ByteArray, query: ByteArray, upstream: UpstreamDns) {
        for (server in upstream.servers().take(2)) {
            try {
                DatagramSocket().use { socket ->
                    protect(socket)
                    socket.soTimeout = UPSTREAM_TIMEOUT_MS
                    socket.connect(InetSocketAddress(server, DNS_PORT))
                    socket.send(DatagramPacket(query, query.size))
                    val answer = ByteArray(MAX_DNS_MESSAGE)
                    while (true) {
                        val received = DatagramPacket(answer, answer.size)
                        socket.receive(received)
                        // Same transaction ID as the query, or it is not our answer.
                        if (received.length >= 2 && answer[0] == query[0] && answer[1] == query[1]) {
                            val reply = NativeCore.nativeWrapReply(request, answer.copyOf(received.length))
                            if (reply.isNotEmpty()) write(fd, reply)
                            return
                        }
                    }
                }
            } catch (e: IOException) {
                Log.d(TAG, "Upstream $server failed: ${e.message}")
            }
        }
    }

    private fun write(fd: FileDescriptor, packet: ByteArray) {
        try {
            synchronized(tunLock) {
                if (!tunClosed) Os.write(fd, packet, 0, packet.size)
            }
        } catch (e: ErrnoException) {
            Log.d(TAG, "TUN write failed: ${e.message}")
        }
    }
}
