package com.reiniertutoriales.nfdnsvpn.ui

import com.reiniertutoriales.nfdnsvpn.ui.SettingsChanges.Change
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SettingsChangesTest {
    @Test
    fun filterAndDnsChangesAreBothAppliedWithoutRestart() {
        val changes = SettingsChanges()
        changes.add(Change.RULES)
        changes.add(Change.FILTER)
        changes.add(Change.FILTER)
        assertEquals(listOf(Change.FILTER, Change.RULES), changes.actions(running = true))
        assertFalse(changes.requiresRestart)
    }

    @Test
    fun aRestartLoadsAllSavedChangesAndRunsOnlyOnce() {
        val changes = SettingsChanges()
        Change.entries.forEach(changes::add)
        assertEquals(listOf(Change.RESTART), changes.actions(running = true))
        assertTrue(changes.requiresRestart)
        changes.clear()
        assertFalse(changes.isPending)
        assertEquals(emptyList<Change>(), changes.actions(running = true))
    }

    @Test
    fun stoppedProtectionIsNotStartedByEditingSettings() {
        val changes = SettingsChanges()
        Change.entries.forEach(changes::add)
        assertEquals(emptyList<Change>(), changes.actions(running = false))
        assertTrue("saved edits remain pending until acknowledged", changes.isPending)
    }
}
