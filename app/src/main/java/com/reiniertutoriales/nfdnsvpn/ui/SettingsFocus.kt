package com.reiniertutoriales.nfdnsvpn.ui

/** Stable row keys survive rebuilds; deleting a row selects its neighbour, not the page top. */
class SettingsFocus {
    data class Target(val key: String?, val scroll: Int)
    private data class Position(val key: String?, val index: Int, val scroll: Int)
    private val pages = mutableMapOf<String, Position>()

    fun remember(page: String, key: String?, keys: List<String>, scroll: Int) {
        pages[page] = Position(key, keys.indexOf(key).coerceAtLeast(0), scroll)
    }

    fun restore(page: String, keys: List<String>): Target {
        val position = pages[page] ?: return Target(keys.firstOrNull(), 0)
        val key = position.key?.takeIf { it in keys }
            ?: keys.getOrNull(position.index.coerceAtMost(keys.lastIndex))
        return Target(key, position.scroll)
    }
}
