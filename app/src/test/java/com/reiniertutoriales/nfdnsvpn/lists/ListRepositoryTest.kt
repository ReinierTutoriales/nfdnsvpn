package com.reiniertutoriales.nfdnsvpn.lists

import java.nio.file.Files
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ListRepositoryTest {
    @Test fun startupUsesEveryAvailableCopyWithoutRequiringAllSources() {
        val directory = Files.createTempDirectory("nfdns-list-cache").toFile()
        try {
            val saved = directory.resolve("hagezi-native-0.txt")
            saved.writeText("||telemetry.example^")
            val loaded = ListRepository.cachedLists(setOf("hagezi-native", "hagezi-doh"), directory)

            assertEquals(listOf(saved), loaded.files)
            assertEquals(2, loaded.status.size)
            assertTrue(loaded.status[0].available)
            assertTrue(loaded.status[0].updatedAt > 0L)
            assertFalse(loaded.status[1].available)
            assertEquals(0L, loaded.status[1].updatedAt)
        } finally {
            directory.deleteRecursively()
        }
    }
}
