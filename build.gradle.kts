import com.novoda.gradle.release.PublishExtension
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

buildscript {
    repositories {
        jcenter()
    }
    dependencies {
        classpath("com.novoda:bintray-release:0.9")
    }
}

apply {
    plugin("com.novoda.bintray-release")
}

plugins {
    kotlin("jvm") version "1.3.21"
}

val siteUrl = "https://github.com/Tlaster/KotlinPGP"
val gitUrl = "https://github.com/Tlaster/KotlinPGP.git"
val issueUrl = "https://github.com/Tlaster/KotlinPGP/issues"
val groupID = "moe.tlaster"
val artifactID = "kotlinpgp"
val buildNum = System.getenv("TRAVIS_BUILD_NUMBER") ?: 0
group = groupID
version = "1.0.$buildNum"

repositories {
    mavenCentral()
}

dependencies {
    implementation(kotlin("stdlib-jdk8"))
    implementation("org.bouncycastle:bcpg-jdk15on:1.61")
    implementation("org.bouncycastle:bcprov-jdk15on:1.61")
    testImplementation("io.kotlintest:kotlintest-runner-junit5:3.3.2")
    testImplementation(group = "org.slf4j", name = "slf4j-simple", version = "1.7.26")
    testImplementation("com.google.guava:guava:27.1-jre")
}

tasks.withType<KotlinCompile> {
    kotlinOptions.jvmTarget = "1.8"
}

val test by tasks.getting(Test::class) {
    useJUnitPlatform { }
}

configure<PublishExtension> {
    userOrg = "tlaster"
    repoName = "KotlinPGP"
    groupId = "moe.tlaster"
    artifactId = "KotlinPGP"
    publishVersion = version.toString()
    desc = "Kotlin PGP"
    website = "https://github.com/Tlaster/KotlinPGP"
}
