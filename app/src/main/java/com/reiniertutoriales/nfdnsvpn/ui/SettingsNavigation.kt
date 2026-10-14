package com.reiniertutoriales.nfdnsvpn.ui

/** Keeps Back predictable even when a detail page links directly to another section. */
class SettingsNavigation {
    enum class Page { HOME, PROTECTION, APPS, APP, DOMAINS, DNS, STATUS }
    var current = Page.HOME
        private set
    private val previous = mutableListOf<Page>()
    val history: List<Page> get() = previous.toList()

    fun open(page: Page) {
        if (page == current) return
        previous += current
        current = page
    }

    /** False at the root: the activity may finish without an exit confirmation. */
    fun back(): Boolean {
        if (previous.isEmpty()) return false
        current = previous.removeAt(previous.lastIndex)
        return true
    }

    fun restore(page: Page, history: List<Page>) {
        current = page
        previous.clear()
        previous += history
    }
}
