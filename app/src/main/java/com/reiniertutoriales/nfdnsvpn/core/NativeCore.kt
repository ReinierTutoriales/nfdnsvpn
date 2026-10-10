package com.reiniertutoriales.nfdnsvpn.core

/** JNI entry points of native/nfdns-core. */
object NativeCore {
    /** JVM unit tests point this property at a host build of the same library. */
    private const val HOST_LIBRARY_PROPERTY = "nfdns.hostLib"

    init {
        val hostLibrary = System.getProperty(HOST_LIBRARY_PROPERTY)
        if (hostLibrary.isNullOrEmpty()) System.loadLibrary("nfdns") else System.load(hostLibrary)
    }

    /** Compiles the lists into a filter; free it with [nativeDestroy]. */
    @JvmStatic external fun nativeCreate(lists: Array<String>): Long
    @JvmStatic external fun nativeDestroy(handle: Long)
    @JvmStatic external fun nativeRuleCount(handle: Long): Int
    /** Encoded [PacketAction] for one packet read from the TUN. */
    @JvmStatic external fun nativeHandle(handle: Long, packet: ByteArray): ByteArray
    /** IP/UDP packet carrying [answer] back to the sender of [request]; empty if invalid. */
    @JvmStatic external fun nativeWrapReply(request: ByteArray, answer: ByteArray): ByteArray
}

/** Decoded result of [NativeCore.nativeHandle]: `[kind][name length: u16][name][data]`. */
sealed class PacketAction {
    object Ignore : PacketAction()
    /** Blocked name answered locally: write [packet] to the TUN. */
    class Blocked(val name: String, val packet: ByteArray) : PacketAction()
    /** TCP to an intercepted resolver refused: write [packet] to the TUN. */
    class Reset(val packet: ByteArray) : PacketAction()
    /** Allowed: send [query] upstream, then wrap the answer with [NativeCore.nativeWrapReply]. */
    class Forward(val name: String, val query: ByteArray) : PacketAction()

    companion object {
        private const val KIND_BLOCKED = 1
        private const val KIND_RESET = 2
        private const val KIND_FORWARD = 3

        fun decode(encoded: ByteArray): PacketAction {
            if (encoded.size < 3) return Ignore
            val nameLength = ((encoded[1].toInt() and 0xFF) shl 8) or (encoded[2].toInt() and 0xFF)
            val dataStart = 3 + nameLength
            if (dataStart > encoded.size) return Ignore
            val name = String(encoded, 3, nameLength, Charsets.US_ASCII)
            val data = encoded.copyOfRange(dataStart, encoded.size)
            return when (encoded[0].toInt()) {
                KIND_BLOCKED -> Blocked(name, data)
                KIND_RESET -> Reset(data)
                KIND_FORWARD -> Forward(name, data)
                else -> Ignore
            }
        }
    }
}
