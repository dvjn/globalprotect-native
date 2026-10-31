package dev.dvjn.gpn

import android.app.Notification
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.IpPrefix
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.util.Log
import dev.dvjn.gpn.mobile.App
import dev.dvjn.gpn.mobile.Listener
import dev.dvjn.gpn.mobile.Mobile
import dev.dvjn.gpn.mobile.Status
import dev.dvjn.gpn.mobile.Tunnel
import dev.dvjn.gpn.mobile.TunnelConfig
import java.net.InetAddress
import kotlin.concurrent.thread

/**
 * TunnelService runs the Go core's tunnel as the device's VPN. It gives the core sockets that
 * bypass the VPN, the VPN device and the network's DNS server, and restarts the tunnel when the
 * device moves to another network.
 */
class TunnelService : VpnService(), App, Listener {
    private val store get() = Gpn.store
    @Volatile private var tunnel: Tunnel? = null

    /** network is the one outside the VPN that the tunnel runs over. */
    @Volatile private var network: Network? = null
    @Volatile private var networkProperties: LinkProperties? = null
    private val connectivity by lazy { getSystemService(ConnectivityManager::class.java) }
    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(available: Network) {
            val moved = network != null && network != available
            network = available
            if (moved) {
                log("Moved to another network; rebuilding the tunnel.")
                tunnel?.restart()
            }
        }

        override fun onLinkPropertiesChanged(changed: Network, properties: LinkProperties) {
            if (changed == network) networkProperties = properties
        }

        override fun onLost(lost: Network) {
            if (lost == network) network = null
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_DISCONNECT) {
            disconnect()
            return START_NOT_STICKY
        }
        startForeground(NOTIFICATION_ID, notification(State(State.CONNECTING)), ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED)
        if (tunnel == null) {
            runCatching { connect() }.onFailure { onStatus(State.FAILED, it.message ?: it.toString()) }
        }
        return START_STICKY
    }

    private fun connect() {
        val settings = runCatching { store.settingsJSON() }.getOrElse {
            onStatus(State.FAILED, it.message ?: it.toString())
            return
        }
        if (settings == null) {
            onStatus(State.NEEDS_LOGIN, "not logged in to ${store.portal}")
            return
        }
        // The default request asks for a network that is not a VPN, so this one is outside it.
        connectivity.requestNetwork(
            NetworkRequest.Builder().addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET).build(),
            networkCallback,
        )
        tunnel = runCatching { Mobile.start(settings, this, this) }
            .onFailure { onStatus(State.FAILED, it.message ?: it.toString()) }
            .getOrNull()
    }

    /** disconnect stops the tunnel, which logs out of the gateway, away from the main thread. */
    private fun disconnect() {
        val running = tunnel ?: return finish()
        tunnel = null
        thread(name = "gpn-disconnect") { running.stop() }
    }

    private fun finish() {
        runCatching { connectivity.unregisterNetworkCallback(networkCallback) }
        network = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    /** onRevoke means another VPN took over or the user switched this one off in Settings. */
    override fun onRevoke() {
        disconnect()
    }

    override fun onDestroy() {
        tunnel?.let { running -> thread(name = "gpn-disconnect") { running.stop() } }
        tunnel = null
        super.onDestroy()
    }

    // App, called by the Go core on its own threads.

    override fun protect(fd: Long): Boolean = protect(fd.toInt())

    override fun establish(config: TunnelConfig): Long {
        val builder = Builder()
            .setSession(store.portal)
            .setMtu(config.getMTU().toInt())
            .addAddress(config.getClientIP(), 32)
            .setConfigureIntent(
                PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE),
            )
        for ((address, length) in prefixes(config.getRoutes())) builder.addRoute(address, length)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            for ((address, length) in prefixes(config.getExcludeRoutes())) {
                builder.excludeRoute(IpPrefix(InetAddress.getByName(address), length))
            }
        }
        for (server in list(config.getDNSServers())) builder.addDnsServer(server)
        for (domain in list(config.getSearchDomains())) builder.addSearchDomain(domain)
        network?.let { builder.setUnderlyingNetworks(arrayOf(it)) }
        val device = builder.establish() ?: throw IllegalStateException("the VPN permission was revoked")
        return device.detachFd().toLong()
    }

    override fun dnsServer(): String = dnsServer(this, networkProperties)

    override fun hipProfile(): String = hipProfile(this)

    override fun log(message: String) {
        Log.i(TAG, message)
        TunnelState.log(message)
    }

    // Listener.

    override fun onStatus(status: Status) {
        onStatus(State(status.getState(), status.getGateway(), status.getClientIP(), status.getTransport(), status.getError()))
    }

    private fun onStatus(state: String, error: String) = onStatus(State(state = state, error = error))

    private fun onStatus(state: State) {
        TunnelState.set(state)
        if (state.running) {
            getSystemService(android.app.NotificationManager::class.java).notify(NOTIFICATION_ID, notification(state))
            return
        }
        tunnel = null
        if (state.state == State.NEEDS_LOGIN) {
            getSystemService(android.app.NotificationManager::class.java).notify(LOGIN_NOTIFICATION_ID, notification(state))
        }
        finish()
    }

    private fun notification(state: State): Notification {
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        val builder = Notification.Builder(this, Gpn.NOTIFICATION_CHANNEL)
            .setSmallIcon(R.drawable.ic_shield)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(state.summary)
            .setContentIntent(open)
            .setOngoing(state.running)
        if (state.running) {
            val stop = PendingIntent.getService(this, 1, disconnectIntent(this), PendingIntent.FLAG_IMMUTABLE)
            builder.addAction(Notification.Action.Builder(null, getString(R.string.disconnect), stop).build())
        }
        return builder.build()
    }

    companion object {
        private const val TAG = "gpn"
        private const val NOTIFICATION_ID = 1
        private const val LOGIN_NOTIFICATION_ID = 2
        private const val ACTION_CONNECT = "dev.dvjn.gpn.CONNECT"
        private const val ACTION_DISCONNECT = "dev.dvjn.gpn.DISCONNECT"

        fun connectIntent(context: Context) = Intent(context, TunnelService::class.java).setAction(ACTION_CONNECT)
        fun disconnectIntent(context: Context) = Intent(context, TunnelService::class.java).setAction(ACTION_DISCONNECT)

        private fun list(text: String) = text.split(',').map(String::trim).filter(String::isNotEmpty)

        private fun prefixes(text: String) = list(text).map {
            val (address, length) = it.split('/')
            address to length.toInt()
        }
    }
}
