package com.reiniertutoriales.nfdnsvpn.core

import java.io.Closeable

/** JNI entry points of native/nfdns-core. */
object NativeCore {
    /** JVM unit tests point this property at a host build of the same library. */
    private const val HOST_LIBRARY_PROPERTY = "nfdns.hostLib"

    init {
        val hostLibrary = System.getProperty(HOST_LIBRARY_PROPERTY)
        if (hostLibrary.isNullOrEmpty()) System.loadLibrary("nfdns") else System.load(hostLibrary)
    }

    /** Compiles the lists into a filter; free it with [nativeDestroy] or hand it to [nativeTunnelCreate]. */
    @JvmStatic external fun nativeCreate(lists: Array<String>): Long
    @JvmStatic external fun nativeDestroy(handle: Long)
    @JvmStatic external fun nativeRuleCount(handle: Long): Int

    /** Takes ownership of [filter]. [intercepted]: comma-separated resolver addresses. */
    @JvmStatic external fun nativeTunnelCreate(filter: Long, fd: Int, intercepted: String): Long
    /** Comma-separated resolvers of the real network; a bare IP means port 53. */
    @JvmStatic external fun nativeTunnelSetUpstream(tunnel: Long, servers: String)
    /** Blocks until [nativeTunnelStop]; empty string, or the error that ended the tunnel. */
    @JvmStatic external fun nativeTunnelRun(tunnel: Long): String
    @JvmStatic external fun nativeTunnelStop(tunnel: Long)
    /** `queries,blocked,tcp,udp,quic_refused` followed by recently blocked names, one per line. */
    @JvmStatic external fun nativeTunnelStats(tunnel: Long): String
    @JvmStatic external fun nativeTunnelFree(tunnel: Long)
}

class TunnelStats(
    val queries: Long,
    val blocked: Long,
    val tcp: Long,
    val udp: Long,
    /** QUIC flows without a readable server name, refused so the app falls back to TCP. */
    val quicRefused: Long,
    val recent: List<String>,
) {
    companion object {
        fun parse(encoded: String): TunnelStats? {
            val lines = encoded.split('\n')
            val numbers = lines.first().split(',').mapNotNull(String::toLongOrNull)
            if (numbers.size != 5) return null
            return TunnelStats(numbers[0], numbers[1], numbers[2], numbers[3], numbers[4], lines.drop(1).filter(String::isNotEmpty))
        }
    }
}

/**
 * Owns a native tunnel. [run] blocks on the caller's thread; [stop], [setUpstream] and [stats]
 * may be called from any thread until [close], which must come after [run] has returned.
 */
class NativeTunnel(filter: Long, fd: Int, intercepted: List<String>) : Closeable {
    private var handle = NativeCore.nativeTunnelCreate(filter, fd, intercepted.joinToString(","))

    fun run(): String = NativeCore.nativeTunnelRun(handle)

    @Synchronized fun stop() {
        if (handle != 0L) NativeCore.nativeTunnelStop(handle)
    }

    @Synchronized fun setUpstream(servers: List<String>) {
        if (handle != 0L) NativeCore.nativeTunnelSetUpstream(handle, servers.joinToString(","))
    }

    @Synchronized fun stats(): TunnelStats? =
        if (handle != 0L) TunnelStats.parse(NativeCore.nativeTunnelStats(handle)) else null

    @Synchronized override fun close() {
        val freed = handle
        handle = 0L
        if (freed != 0L) NativeCore.nativeTunnelFree(freed)
    }
}
