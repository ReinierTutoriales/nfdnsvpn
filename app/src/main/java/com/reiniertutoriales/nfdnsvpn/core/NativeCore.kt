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

    /** Filter built list by list from files on disk: no list text goes through Java memory. */
    @JvmStatic external fun nativeBuilderNew(): Long
    /** Reads a list file line by line; false if it cannot be read. */
    @JvmStatic external fun nativeBuilderAddFile(builder: Long, path: String): Boolean
    /** For small inputs only (the bundled list, the allowlist). */
    @JvmStatic external fun nativeBuilderAddText(builder: Long, text: String)
    /** Consumes the builder; returns a filter handle like [nativeCreate]. */
    @JvmStatic external fun nativeBuilderBuild(builder: Long): Long
    @JvmStatic external fun nativeBuilderDestroy(builder: Long)
    @JvmStatic external fun nativeRuleCount(handle: Long): Int

    /** Takes ownership of [filter]. [intercepted]: comma-separated resolver addresses. */
    @JvmStatic external fun nativeTunnelCreate(filter: Long, fd: Int, intercepted: String): Long
    /** Takes ownership of [filter] and puts it in use at once (list update, allowlist change). */
    @JvmStatic external fun nativeTunnelSetFilter(tunnel: Long, filter: Long)
    /** Comma-separated resolvers of the real network; a bare IP means port 53. */
    @JvmStatic external fun nativeTunnelSetUpstream(tunnel: Long, servers: String)
    /** Apps (uids) cut off the network entirely; asks [ConnectionOwner] who owns each new flow. */
    @JvmStatic external fun nativeTunnelSetBlockedApps(tunnel: Long, uids: IntArray)
    /** Watched apps (uids): only readable, allowed names or addresses our DNS gave out. */
    @JvmStatic external fun nativeTunnelSetWatchedApps(tunnel: Long, uids: IntArray)
    /** Recent destinations of a watched app, one per line: `1<TAB>name` refused, `0<TAB>name` allowed. */
    @JvmStatic external fun nativeTunnelAppActivity(tunnel: Long, uid: Int): String
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

/** A server name (or a bare address) a watched app reached, or tried to reach and was refused. */
data class Destination(val name: String, val refused: Boolean) {
    companion object {
        fun parse(encoded: String): List<Destination> = encoded.lineSequence().mapNotNull { line ->
            val (flag, name) = line.split('\t', limit = 2).takeIf { it.size == 2 } ?: return@mapNotNull null
            Destination(name, flag == "1")
        }.toList()
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

    /** Takes ownership of [filter], also when the tunnel is already closed. */
    @Synchronized fun setFilter(filter: Long) {
        if (handle != 0L) NativeCore.nativeTunnelSetFilter(handle, filter) else NativeCore.nativeDestroy(filter)
    }

    @Synchronized fun setUpstream(servers: List<String>) {
        if (handle != 0L) NativeCore.nativeTunnelSetUpstream(handle, servers.joinToString(","))
    }

    @Synchronized fun setBlockedApps(uids: IntArray) {
        if (handle != 0L) NativeCore.nativeTunnelSetBlockedApps(handle, uids)
    }

    @Synchronized fun setWatchedApps(uids: IntArray) {
        if (handle != 0L) NativeCore.nativeTunnelSetWatchedApps(handle, uids)
    }

    /** Where a watched app went, most recent first. */
    @Synchronized fun appActivity(uid: Int): List<Destination> =
        if (handle != 0L) Destination.parse(NativeCore.nativeTunnelAppActivity(handle, uid)) else emptyList()

    @Synchronized fun stats(): TunnelStats? =
        if (handle != 0L) TunnelStats.parse(NativeCore.nativeTunnelStats(handle)) else null

    @Synchronized override fun close() {
        val freed = handle
        handle = 0L
        if (freed != 0L) NativeCore.nativeTunnelFree(freed)
    }
}
