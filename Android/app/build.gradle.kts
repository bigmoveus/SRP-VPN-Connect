plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "tr.com.srp.vpn"
    compileSdk = 36
    ndkVersion = "28.2.13676358"

    defaultConfig {
        applicationId = "tr.com.srp.vpn"
        minSdk = 26
        targetSdk = 36
        versionCode = 5
        versionName = "1.2.0"
        ndk {
            abiFilters += "arm64-v8a"
        }
        externalNativeBuild {
            cmake {
                // Debug would turn on asserts meant for upstream's tests; iOS also runs a Release build.
                arguments += "-DCMAKE_BUILD_TYPE=Release"
                targets += listOf("waterwall", "srpsstp", "srpse", "srpopenconnect", "srpssh", "srpopenvpn", "wg-go")
            }
        }
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "4.1.2"
        }
    }

    buildFeatures {
        compose = true
    }

    sourceSets {
        getByName("main") {
            // The bundled country database, which both apps ship.
            assets.srcDir("../../WaterWall/GeoIP")
            // libopenconnect's Java binding (LibOpenConnect), beside the C sources both apps build
            java.srcDir("../../iOS/OpenConnect/upstream/java/src")
        }
    }

    // A release is signed only where these are set: the key and its password stay out of this repository.
    System.getenv("SRP_ANDROID_KEYSTORE")?.let { keystore ->
        signingConfigs.create("release") {
            storeFile = file(keystore)
            storePassword = System.getenv("SRP_ANDROID_KEYSTORE_PASSWORD")
            keyAlias = "srp-vpn-connect"
            keyPassword = storePassword
        }
        buildTypes.getByName("release").signingConfig = signingConfigs.getByName("release")
    }
}

dependencies {
    implementation(platform("androidx.compose:compose-bom:2026.03.01"))
    implementation("androidx.compose.material3:material3")
    implementation("androidx.activity:activity-compose:1.12.4")
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20250517")
}
