plugins {
    // this is necessary to avoid the plugins to be loaded multiple times
    // in each subproject's classloader
    alias(libs.plugins.jetbrainsCompose) apply false
    alias(libs.plugins.kotlinMultiplatform) apply false
    id("org.jetbrains.dokka") version "1.9.20"
}

subprojects {
    apply(plugin = "org.jetbrains.dokka")
}


tasks.dokkaHtmlMultiModule {
    outputDirectory.set(file("../docs"))
    includes.from(project.layout.projectDirectory.file("../README.md"))
}