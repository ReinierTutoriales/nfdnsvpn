package com.reiniertutoriales.nfdnsvpn.ui

import com.reiniertutoriales.nfdnsvpn.ui.SettingsNavigation.Page
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SettingsNavigationTest {
    @Test
    fun protectionShortcutReturnsToTheAppThenTheListAndTheMenu() {
        val navigation = SettingsNavigation()
        listOf(Page.APPS, Page.APP, Page.PROTECTION).forEach(navigation::open)
        for (expected in listOf(Page.APP, Page.APPS, Page.HOME)) {
            assertTrue(navigation.back())
            assertEquals(expected, navigation.current)
        }
        assertFalse("Back at the menu exits", navigation.back())
    }

    @Test
    fun openingTheCurrentPageDoesNotTrapBack() {
        val navigation = SettingsNavigation()
        navigation.open(Page.DNS)
        navigation.open(Page.DNS)
        assertTrue(navigation.back())
        assertEquals(Page.HOME, navigation.current)
        assertFalse(navigation.back())
    }

    @Test
    fun recreatingTheScreenPreservesItsReturnDestination() {
        val before = SettingsNavigation()
        listOf(Page.APPS, Page.APP, Page.PROTECTION).forEach(before::open)
        val restored = SettingsNavigation()
        restored.restore(before.current, before.history)
        assertTrue(restored.back())
        assertEquals(Page.APP, restored.current)
    }
}
