package dev.dvjn.gpn

import android.app.admin.DevicePolicyManager
import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import org.json.JSONArray
import org.json.JSONObject
import java.net.Inet4Address

/**
 * dnsServer is a DNS server of the network outside the VPN: the one in properties, or else the
 * active network's, preferring IPv4. "" when there is none.
 */
fun dnsServer(context: Context, properties: LinkProperties?): String {
    val connectivity = context.getSystemService(ConnectivityManager::class.java)
    val servers = (properties ?: connectivity.getLinkProperties(connectivity.activeNetwork))?.dnsServers.orEmpty()
    return (servers.firstOrNull { it is Inet4Address } ?: servers.firstOrNull())?.hostAddress ?: ""
}

/** hipProfile is what the app detects for the HIP report: whether the storage is encrypted. */
fun hipProfile(context: Context): String {
    val status = context.getSystemService(DevicePolicyManager::class.java).storageEncryptionStatus
    val encrypted = status == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE ||
        status == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_PER_USER ||
        status == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_DEFAULT_KEY
    val data = JSONObject().put("name", "/data").put("encrypted", encrypted)
    return JSONObject().put("os_vendor", "Google").put("drives", JSONArray().put(data)).toString()
}
