plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
}

// The version is gpn's, which mise sets and release-please bumps, such as "0.3.0".
val gpnVersion = System.getenv("VERSION") ?: "0.0.0"
val (major, minor, patch) = gpnVersion.substringBefore('-').split('.').map(String::toInt)

// Release builds are signed with the keystore these name, when they are set, as on CI.
val keystore = System.getenv("GPN_KEYSTORE")

android {
    namespace = "dev.dvjn.gpn"
    compileSdk = 37

    defaultConfig {
        applicationId = "dev.dvjn.gpn"
        minSdk = 29
        targetSdk = 37
        versionCode = major * 10000 + minor * 100 + patch
        versionName = gpnVersion
    }

    signingConfigs {
        if (keystore != null) {
            create("release") {
                storeFile = file(keystore)
                storePassword = System.getenv("GPN_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("GPN_KEY_ALIAS")
                keyPassword = System.getenv("GPN_KEY_PASSWORD")
            }
        }
    }

    buildTypes {
        release {
            signingConfig = signingConfigs.findByName("release")
        }
    }

    buildFeatures {
        compose = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    // The Go core, built by `mise run android:core`.
    implementation(files("libs/core.aar"))

    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.browser)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.compose)
}
