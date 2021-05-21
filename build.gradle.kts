import org.jetbrains.compose.compose
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    kotlin("jvm") version "1.4.32"
    id("org.jetbrains.compose") version "0.4.0-build182"
}

group = "org.semou"
version = "1.0"

//repositories {
//    jcenter()
//    mavenCentral()
//    maven { url = uri("https://maven.pkg.jetbrains.space/public/p/compose/dev") }
//}


//dependencies {
//    implementation(compose.desktop.currentOs)
//    testImplementation(kotlin("test"))
//    implementation("org.junit.jupiter:junit-jupiter:5.4.2")
//    implementation(kotlin("stdlib-jdk8"))
//}

repositories {
    mavenCentral()
    maven("https://maven.pkg.jetbrains.space/public/p/compose/dev")
}

dependencies {
    implementation(compose.desktop.currentOs)
}

tasks.withType<KotlinCompile> {
    kotlinOptions.jvmTarget = "11"
}

compose.desktop {
    application {
        mainClass = "org.semou.security_unit_frame_analyse.MainKt"
//        nativeDistributions {
//            targetFormats(TargetFormat.Dmg, TargetFormat.Msi, TargetFormat.Deb,TargetFormat.AppImage)
//            packageName = "SecurityUnitFrameAnalyse"
//        }
    }
}

tasks.test {
    useJUnitPlatform()
}
val compileKotlin: KotlinCompile by tasks
compileKotlin.kotlinOptions {
    jvmTarget = "1.8"
}
val compileTestKotlin: KotlinCompile by tasks
compileTestKotlin.kotlinOptions {
    jvmTarget = "1.8"
}