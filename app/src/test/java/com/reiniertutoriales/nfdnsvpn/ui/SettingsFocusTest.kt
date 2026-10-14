package com.reiniertutoriales.nfdnsvpn.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class SettingsFocusTest {
    @Test
    fun rebuildingAndReturningToAnAppKeepTheSelectedRowAndScroll() {
        val focus = SettingsFocus()
        focus.remember("APPS", "app.b", listOf("app.a", "app.b", "app.c"), 200)
        focus.remember("APP:app.b", "watched", listOf("excluded", "blocked", "watched"), 80)
        assertEquals(SettingsFocus.Target("app.b", 200), focus.restore("APPS", listOf("app.a", "app.b", "app.c")))
        assertEquals(SettingsFocus.Target("watched", 80), focus.restore("APP:app.b", listOf("excluded", "blocked", "watched", "activity")))
    }

    @Test
    fun removingTheFocusedDomainSelectsTheNextOrPreviousRow() {
        val focus = SettingsFocus()
        focus.remember("DOMAINS", "b", listOf("a", "b", "c"), 100)
        assertEquals("c", focus.restore("DOMAINS", listOf("a", "c")).key)
        focus.remember("DOMAINS", "c", listOf("a", "c"), 100)
        assertEquals("a", focus.restore("DOMAINS", listOf("a")).key)
        assertNull(focus.restore("DOMAINS", emptyList()).key)
    }

    @Test
    fun newPagesStartOnAnActualControl() {
        assertEquals(SettingsFocus.Target("protection", 0), SettingsFocus().restore("HOME", listOf("protection", "apps")))
    }
}
