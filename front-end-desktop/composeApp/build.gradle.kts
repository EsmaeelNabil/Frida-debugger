import org.jetbrains.compose.desktop.application.dsl.TargetFormat

plugins {
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.jetbrainsCompose)
    alias(libs.plugins.compose.compiler)
    kotlin("plugin.serialization") version "1.9.22"
}

kotlin {
    jvm("desktop")

    sourceSets {
        val desktopMain by getting

        desktopMain.dependencies {
            implementation(compose.desktop.currentOs)
        }

        commonMain.dependencies {
            implementation(compose.runtime)
            implementation(compose.foundation)
            implementation(compose.material3)
            implementation(compose.preview)
            implementation(compose.materialIconsExtended)
            implementation(compose.components.resources)
            implementation("io.github.dokar3:quickjs-kt:1.0.0-alpha13")
            implementation("io.socket:socket.io-client:2.1.0")
            implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.6.2")

        }
    }
}


compose.desktop {
    application {
        mainClass = "MainKt"

        nativeDistributions {
            modules("jdk.crypto.ec", "java.instrument", "jdk.unsupported")
            includeAllModules = true
            targetFormats(TargetFormat.Dmg, TargetFormat.Msi, TargetFormat.Deb)
            packageName = "com.sam.godfather_ui"
            packageVersion = "1.0.0"


            macOS {
                packageName = "GodfatherUI"

            }
        }
    }
}

compose.resources {
    publicResClass = true
    packageOfResClass = "com.sam.godfather.resources"
    generateResClass = always
}


tasks.register<Copy>("copyNodeBundle") {
    from("backend/dist/bundle.js")
    into("$buildDir/processedResources/js")
}