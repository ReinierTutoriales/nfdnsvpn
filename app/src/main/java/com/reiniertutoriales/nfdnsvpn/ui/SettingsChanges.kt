package com.reiniertutoriales.nfdnsvpn.ui

/** Coalesces edits without losing a filter reload when app/DNS rules change too. */
class SettingsChanges {
    enum class Change { FILTER, RULES, RESTART }
    private val pending = mutableSetOf<Change>()
    val isPending get() = pending.isNotEmpty()
    val requiresRestart get() = Change.RESTART in pending
    fun add(change: Change) { pending += change }
    fun clear() { pending.clear() }

    /** A restart loads every saved setting; a stopped VPN loads them on its next activation. */
    fun actions(running: Boolean): List<Change> = when {
        !running -> emptyList()
        requiresRestart -> listOf(Change.RESTART)
        else -> listOf(Change.FILTER, Change.RULES).filter { it in pending }
    }
}
