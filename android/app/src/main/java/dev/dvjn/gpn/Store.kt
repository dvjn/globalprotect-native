package dev.dvjn.gpn

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.security.KeyStore
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Store keeps the settings in the app's preferences, and the portal login encrypted with a key
 * that never leaves the Android Keystore.
 */
class Store(context: Context) {
    private val preferences = context.getSharedPreferences("gpn", Context.MODE_PRIVATE)

    var portal: String by preference("portal", "")
    /** gateway is a gateway's name, or "" for the fastest. */
    var gateway: String by preference("gateway", "")
    var sslOnly: Boolean by preference("ssl_only", false)
    /** includeOnly sends only includeDomains and includeRoutes through the VPN; otherwise
     * everything goes, but excludeDomains. */
    var includeOnly: Boolean by preference("include_only", false)
    var sendHIP: Boolean by preference("send_hip", true)
    /** The lists hold one entry per line. */
    var includeDomains: String by preference("include_domains", "")
    var includeRoutes: String by preference("include_routes", "")
    var excludeDomains: String by preference("exclude_domains", "")
    /** hipProfile is a HIP profile, exported by any client, to report instead of this phone. */
    var hipProfile: String by preference("hip_profile", "")

    /** hostID identifies this device to the portal, as the official client's host ID does. */
    val hostID: String
        get() = preferences.getString("host_id", null)
            ?: UUID.randomUUID().toString().also { preferences.edit().putString("host_id", it).apply() }

    /** credential is the JSON that Login.finish returned, for the portal it was saved for. */
    var credential: String?
        get() {
            if (preferences.getString("credential_portal", null) != portal) return null
            return preferences.getString("credential", null)?.let(::decrypt)
        }
        set(value) {
            preferences.edit()
                .putString("credential", value?.let(::encrypt))
                .putString("credential_portal", value?.let { portal })
                .apply()
        }

    /** username is who the saved login belongs to, or null without one. */
    val username: String?
        get() = credential?.let { runCatching { JSONObject(it).getString("username") }.getOrNull() }

    /** signOut forgets the login and the portal, to start over with onboarding. */
    fun signOut() {
        credential = null
        portal = ""
        gateway = ""
    }

    fun identityJSON(): String = JSONObject()
        .put("host_id", hostID)
        .put("computer", Build.MODEL)
        .put("os_version", "Android ${Build.VERSION.RELEASE}")
        .put("client_version", CLIENT_VERSION)
        .toString()

    /**
     * settingsJSON is what Mobile.start takes, or null before the first login. Without
     * needsLogin it describes the device even then, for exporting and previewing HIP.
     */
    fun settingsJSON(needsLogin: Boolean = true): String? {
        val saved = credential ?: if (needsLogin) return null else "{}"
        val settings = JSONObject()
            .put("portal", portal)
            .put("gateway", gateway)
            .put("ssl_only", sslOnly)
            .put("send_hip", sendHIP)
            .put("credential", JSONObject(saved))
            .put("identity", JSONObject(identityJSON()))
            .put("include_domains", if (includeOnly) lines(includeDomains) else JSONArray())
            .put("include_routes", if (includeOnly) lines(includeRoutes) else JSONArray())
            .put("exclude_domains", if (includeOnly) JSONArray() else lines(excludeDomains))
        if (hipProfile.isNotBlank()) {
            val profile = runCatching { JSONObject(hipProfile) }
                .getOrElse { throw IllegalArgumentException("the HIP profile is not valid JSON: ${it.message}") }
            settings.put("hip_profile", profile)
        }
        return settings.toString()
    }

    private fun lines(text: String) = JSONArray(text.lines().map(String::trim).filter(String::isNotEmpty))

    private fun key(): SecretKey {
        val keyStore = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        (keyStore.getKey(KEY_ALIAS, null) as SecretKey?)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .build(),
        )
        return generator.generateKey()
    }

    private fun encrypt(text: String): String {
        val cipher = Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, key()) }
        return Base64.encodeToString(cipher.iv + cipher.doFinal(text.toByteArray()), Base64.NO_WRAP)
    }

    /** decrypt returns null for what it cannot read, such as after the key was wiped. */
    private fun decrypt(text: String): String? = runCatching {
        val sealed = Base64.decode(text, Base64.NO_WRAP)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, sealed, 0, IV_LENGTH))
        String(cipher.doFinal(sealed, IV_LENGTH, sealed.size - IV_LENGTH))
    }.getOrNull()

    @Suppress("UNCHECKED_CAST")
    private fun <T> preference(name: String, default: T) = object : kotlin.properties.ReadWriteProperty<Any?, T> {
        override fun getValue(thisRef: Any?, property: kotlin.reflect.KProperty<*>): T = when (default) {
            is Boolean -> preferences.getBoolean(name, default) as T
            else -> (preferences.getString(name, default as String) ?: default) as T
        }

        override fun setValue(thisRef: Any?, property: kotlin.reflect.KProperty<*>, value: T) {
            preferences.edit().apply {
                when (value) {
                    is Boolean -> putBoolean(name, value)
                    else -> putString(name, value as String)
                }
            }.apply()
        }
    }

    private companion object {
        /** CLIENT_VERSION is the official client version gpn reports, as on Linux without it. */
        const val CLIENT_VERSION = "6.2.8-1057"
        const val KEYSTORE = "AndroidKeyStore"
        const val KEY_ALIAS = "credential"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val IV_LENGTH = 12
    }
}
