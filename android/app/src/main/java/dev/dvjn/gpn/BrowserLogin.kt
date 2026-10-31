package dev.dvjn.gpn

import android.content.Context
import android.net.Uri
import android.os.Handler
import android.os.Looper
import android.util.Log
import androidx.browser.customtabs.CustomTabsIntent
import dev.dvjn.gpn.mobile.App
import dev.dvjn.gpn.mobile.Login
import dev.dvjn.gpn.mobile.Mobile
import dev.dvjn.gpn.mobile.TunnelConfig
import kotlin.concurrent.thread

/**
 * BrowserLogin runs the portal's SAML login: the Go core serves the login form on localhost, a
 * Custom Tab opens it, and the portal's globalprotectcallback: link comes back to MainActivity.
 */
object BrowserLogin {
    @Volatile private var pending: Login? = null
    private val main = Handler(Looper.getMainLooper())

    /** start opens the login page, or calls failed on the main thread with why it could not. */
    fun start(context: Context, failed: (String) -> Unit) {
        val store = Gpn.store
        val app = LoginApp(context.applicationContext)
        thread(name = "gpn-login") {
            runCatching { Mobile.startLogin(store.settingsJSON(needsLogin = false), app) }
                .onSuccess { login ->
                    pending?.close()
                    pending = login
                    main.post { CustomTabsIntent.Builder().build().launchUrl(context, Uri.parse(login.url())) }
                }
                .onFailure { main.post { failed(it.message ?: it.toString()) } }
        }
    }

    /**
     * finish exchanges the callback for the portal's login cookies and saves them, then calls
     * done on the main thread with null, or with why it failed.
     */
    fun finish(callbackURI: String, done: (String?) -> Unit) {
        val login = pending ?: return done("no login is waiting; log in again")
        pending = null
        thread(name = "gpn-login") {
            val result = runCatching { Gpn.store.credential = login.finish(callbackURI) }
            main.post { done(result.exceptionOrNull()?.let { it.message ?: it.toString() }) }
        }
    }

    /** LoginApp lets the core reach the portal before the VPN is up, so no socket needs protecting. */
    class LoginApp(private val context: Context) : App {
        override fun protect(fd: Long) = true
        override fun establish(config: TunnelConfig): Long = throw UnsupportedOperationException("a login opens no VPN")
        override fun dnsServer(): String = dnsServer(context, null)
        override fun hipProfile(): String = hipProfile(context)
        override fun log(message: String) {
            Log.i("gpn", message)
        }
    }
}
