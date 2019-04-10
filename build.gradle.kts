import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    kotlin("jvm") version "1.3.21"
    `maven-publish`
    id("com.jfrog.bintray") version("1.8.4")
}

val groupID = "moe.tlaster"
val artifactID = "kotlinpgp"
val buildNum = System.getenv("TRAVIS_BUILD_NUMBER")
group = groupID
version = "1.0.$buildNum"

repositories {
    mavenCentral()
    jcenter()
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

