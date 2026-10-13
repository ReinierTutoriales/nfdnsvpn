import java.io.File
import org.gradle.process.ExecOperations
import javax.inject.Inject

plugins {
    alias(libs.plugins.android.application)
}

/** ABIs shipped with the Rust core. 32-bit x86 Android TV hardware does not exist. */
val rustAbis = listOf("arm64-v8a", "armeabi-v7a", "x86_64")

/** Compiles native/nfdns-core with the NDK toolchain. */
abstract class BuildRustCore : DefaultTask() {
    @get:InputFiles
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val sources: ConfigurableFileCollection

    @get:Internal
    abstract val crateDir: DirectoryProperty

    /** Unset when the SDK has no NDK: the host build does not need one. */
    @get:Internal
    abstract val ndkDirectory: DirectoryProperty

    @get:Input
    abstract val minSdk: Property<Int>

    @get:Input
    abstract val abis: ListProperty<String>

    /** Android libraries by ABI; when [hostLibrary] is set, only the host build runs. */
    @get:OutputDirectory
    abstract val outputDir: DirectoryProperty

    @get:Input
    abstract val hostLibrary: Property<Boolean>

    @get:Inject
    abstract val execOperations: ExecOperations

    @TaskAction
    fun build() {
        val script = crateDir.file("build.sh").get().asFile.absolutePath
        val out = outputDir.get().asFile.absolutePath
        val args = if (hostLibrary.get()) listOf(script, "-", "/dev/null", out, minSdk.get().toString())
            else listOf(script, ndk(), out, "-", minSdk.get().toString()) + abis.get()
        execOperations.exec { commandLine(args) }
    }

    /** The NDK AGP resolves, else the one preinstalled on CI runners. */
    private fun ndk(): String = ndkDirectory.orNull?.asFile?.absolutePath
        ?: listOf("ANDROID_NDK_HOME", "ANDROID_NDK_LATEST_HOME", "ANDROID_NDK_ROOT")
            .firstNotNullOfOrNull { name -> System.getenv(name)?.takeIf { File(it).isDirectory } }
        ?: throw GradleException("NDK not found: install the version in gradle/libs.versions.toml (android-ndk) with sdkmanager or set ANDROID_NDK_HOME")
}

android {
    namespace = "com.reiniertutoriales.nfdnsvpn"
    compileSdk {
        version = release(libs.versions.android.compileSdk.get().toInt()) {
            minorApiLevel = libs.versions.android.compileSdkMinor.get().toInt()
        }
    }
    ndkVersion = libs.versions.android.ndk.get()

    defaultConfig {
        applicationId = "com.reiniertutoriales.nfdnsvpn"
        minSdk = libs.versions.android.minSdk.get().toInt()
        targetSdk = libs.versions.android.targetSdk.get().toInt()
        // Each CI build is newer than the last, so it installs over it as an update.
        versionCode = System.getenv("GITHUB_RUN_NUMBER")?.toIntOrNull() ?: 1
        versionName = "0.1.0"
        ndk {
            abiFilters += rustAbis
        }
    }

    // The release key never enters the repository (it is public): CI decodes it from the
    // repository's Actions secrets into a temporary file and passes it through these variables.
    val releaseKeystore = System.getenv("RELEASE_KEYSTORE_PATH")?.takeIf { it.isNotEmpty() }
    signingConfigs {
        if (releaseKeystore != null) {
            create("release") {
                storeFile = file(releaseKeystore)
                storePassword = System.getenv("RELEASE_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("RELEASE_KEY_ALIAS")
                keyPassword = System.getenv("RELEASE_KEY_PASSWORD")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            signingConfig = when {
                releaseKeystore != null -> signingConfigs.getByName("release")
                // Without the secrets (forks, pull requests) CI still checks the release build.
                System.getenv("CI_SIGN_RELEASE_WITH_DEBUG_KEY") == "true" -> signingConfigs.getByName("debug")
                else -> null
            }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        buildConfig = true
    }

    // Cases the app's and the core's checks must agree on (DnsProvidersTest, upstream::tests).
    sourceSets.getByName("test").resources.directories += rootProject.file("testdata").path

    lint {
        abortOnError = true
        warningsAsErrors = true
    }
}

kotlin {
    compilerOptions {
        allWarningsAsErrors = true
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.activity.ktx)

    testImplementation(libs.junit)
}

val rustCrate = rootProject.layout.projectDirectory.dir("native/nfdns-core")
fun BuildRustCore.configureCrate() {
    crateDir.set(rustCrate)
    sources.from(rustCrate.file("Cargo.toml"), rustCrate.file("Cargo.lock"), rustCrate.file("build.sh"), rustCrate.dir("src"))
    val ndk = androidComponents.sdkComponents.ndkDirectory
    ndkDirectory.set(providers.provider { runCatching { ndk.get() }.getOrNull() })
    minSdk.set(libs.versions.android.minSdk.get().toInt())
    abis.set(rustAbis)
}

val buildRustCore by tasks.registering(BuildRustCore::class) {
    configureCrate()
    hostLibrary.set(false)
    outputDir.set(layout.buildDirectory.dir("rust/jniLibs"))
}

// Host build of the same core: JVM unit tests load it instead of a fake.
val buildRustCoreHost by tasks.registering(BuildRustCore::class) {
    configureCrate()
    hostLibrary.set(true)
    outputDir.set(layout.buildDirectory.dir("rust/host"))
}

androidComponents {
    onVariants { variant ->
        variant.sources.jniLibs?.addGeneratedSourceDirectory(buildRustCore, BuildRustCore::outputDir)
    }
}

tasks.withType<Test>().configureEach {
    dependsOn(buildRustCoreHost)
    val hostLib = buildRustCoreHost.flatMap { it.outputDir.file("libnfdns.so") }
    inputs.files(hostLib)
    doFirst { systemProperty("nfdns.hostLib", hostLib.get().asFile.absolutePath) }
}
