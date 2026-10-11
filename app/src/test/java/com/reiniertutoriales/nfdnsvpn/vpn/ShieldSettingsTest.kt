package com.reiniertutoriales.nfdnsvpn.vpn

import com.reiniertutoriales.nfdnsvpn.core.NativeCore
import com.reiniertutoriales.nfdnsvpn.lists.ListRepository
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
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
    fun userBlocklistBecomesDomainRules() {
        val rules = ShieldSettings.blocklistRules(setOf("log.app.example", "metrics.example.com"))
        assertEquals("||log.app.example^\n||metrics.example.com^\n", rules)
        val handle = NativeCore.nativeCreate(arrayOf(rules))
        try {
            assertEquals(2, NativeCore.nativeRuleCount(handle))
        } finally {
            NativeCore.nativeDestroy(handle)
        }
    }

    @Test
    fun aCutDownloadDoesNotReplaceTheList() {
        assertEquals(null, ListRepository.rejection(rules = 300_000, minRules = 100, previousRules = 0))
        assertEquals(null, ListRepository.rejection(rules = 290_000, minRules = 100, previousRules = 300_000))
        assertTrue(ListRepository.rejection(rules = 50, minRules = 100, previousRules = 0) != null)
        assertTrue(ListRepository.rejection(rules = 120_000, minRules = 100, previousRules = 300_000) != null)
    }

    @Test
    fun defaultListsAreTheDocumentedOnes() {
        val defaults = ListRepository.ALL_LISTS.filter { it.enabledByDefault }.map { it.id }
        assertEquals(listOf("adguard-dns", "hagezi-ultimate", "hagezi-native", "hagezi-doh", "doh-ips"), defaults)
        assertEquals(listOf("oisd-small"), ListRepository.selected(setOf("oisd-small", "unknown")).map { it.id })
    }
}
