package dev.dvjn.gpn

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager

class Gpn : Application() {
    override fun onCreate() {
        super.onCreate()
        store = Store(this)
        getSystemService(NotificationManager::class.java).createNotificationChannel(
            NotificationChannel(NOTIFICATION_CHANNEL, getString(R.string.notification_channel), NotificationManager.IMPORTANCE_LOW),
        )
    }

    companion object {
        const val NOTIFICATION_CHANNEL = "tunnel"
        lateinit var store: Store
            private set
    }
}
