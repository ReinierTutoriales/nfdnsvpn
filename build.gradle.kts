// Kotlin is built into AGP 9; the classpath entry only pins the Kotlin compiler version.
buildscript {
    dependencies {
        classpath(libs.kotlin.gradle.plugin)
    }
}

plugins {
    alias(libs.plugins.android.application) apply false
}
