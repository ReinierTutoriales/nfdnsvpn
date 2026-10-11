package com.reiniertutoriales.nfdnsvpn.vpn

import com.reiniertutoriales.nfdnsvpn.core.NativeCore
import com.reiniertutoriales.nfdnsvpn.lists.ListRepository
import org.junit.Assert.assertEquals
import org.junit.Test

class ShieldSettingsTest {
    @Test
    fun allowlistBecomesExceptionRulesThatBeatTheLists() {
        val rules = ShieldSettings.allowlistRules(setOf("tracker.example.org", "ads.example.com"))
        assertEquals("@@||ads.example.com^\n@@||tracker.example.org^\n", rules)
        // The core counts blocking rules only; the exceptions must parse without adding any.
        val handle = NativeCore.nativeCreate(arrayOf("||example.com^\n", rules))
        try {
            assertEquals(1, NativeCore.nativeRuleCount(handle))
        } finally {
            NativeCore.nativeDestroy(handle)
        }
    }

    @Test
    fun defaultListsAreTheDocumentedOnes() {
        val defaults = ListRepository.ALL_LISTS.filter { it.enabledByDefault }.map { it.id }
        assertEquals(listOf("adguard-dns", "hagezi-pro", "hagezi-doh", "doh-ips"), defaults)
        assertEquals(listOf("oisd-small"), ListRepository.selected(setOf("oisd-small", "unknown")).map { it.id })
    }
}
