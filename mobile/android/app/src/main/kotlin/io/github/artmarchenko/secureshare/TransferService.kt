package io.github.artmarchenko.secureshare

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.wifi.WifiManager
import android.os.Build
import android.os.IBinder
import android.os.PowerManager

/**
 * Foreground service for the duration of a transfer: keeps the process (and
 * the Dart code doing the transfer) alive with the screen off or the app in
 * the background, and shows progress with a Cancel button.
 */
class TransferService : Service() {
    private var wakeLock: PowerManager.WakeLock? = null
    private var wifiLock: WifiManager.WifiLock? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CANCEL -> onCancel?.invoke()
            ACTION_STOP -> {
                stopForegroundCompat()
                stopSelf()
            }
            else -> {
                val n = lastNotification ?: return START_NOT_STICKY.also { stopSelf() }
                if (Build.VERSION.SDK_INT >= 29) {
                    startForeground(NOTIFICATION_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
                } else {
                    startForeground(NOTIFICATION_ID, n)
                }
                acquireLocks()
            }
        }
        // not restarted by the system: a killed transfer resumes from the UI
        return START_NOT_STICKY
    }

    /** Android 15+: a dataSync service may run 6 h a day; stop instead of crashing. */
    override fun onTimeout(startId: Int, fgsType: Int) {
        onCancel?.invoke()
        stopForegroundCompat()
        stopSelf()
    }

    override fun onDestroy() {
        releaseLocks()
        running = false
        super.onDestroy()
    }

    private fun acquireLocks() {
        if (wakeLock == null) {
            val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
            wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "SecureShare:transfer").apply {
                setReferenceCounted(false)
                acquire(6 * 60 * 60 * 1000L)
            }
        }
        if (wifiLock == null) {
            val wm = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
            @Suppress("DEPRECATION")
            wifiLock = wm.createWifiLock(WifiManager.WIFI_MODE_FULL_HIGH_PERF, "SecureShare:transfer").apply {
                setReferenceCounted(false)
                acquire()
            }
        }
    }

    private fun releaseLocks() {
        wakeLock?.takeIf { it.isHeld }?.release()
        wifiLock?.takeIf { it.isHeld }?.release()
        wakeLock = null
        wifiLock = null
    }

    private fun stopForegroundCompat() {
        stopForeground(STOP_FOREGROUND_REMOVE)
    }

    companion object {
        const val CHANNEL_ID = "transfers"
        const val NOTIFICATION_ID = 1
        private const val ACTION_CANCEL = "io.github.artmarchenko.secureshare.CANCEL"
        private const val ACTION_STOP = "io.github.artmarchenko.secureshare.STOP"

        /** Called (on any thread) when the user taps Cancel in the notification. */
        @Volatile var onCancel: (() -> Unit)? = null
        @Volatile private var running = false
        @Volatile private var lastNotification: Notification? = null

        /** Start the service (start = true) or just update its notification. */
        fun show(context: Context, title: String, text: String, progress: Int, cancelLabel: String, upload: Boolean,
                 start: Boolean) {
            val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            if (Build.VERSION.SDK_INT >= 26 && nm.getNotificationChannel(CHANNEL_ID) == null) {
                nm.createNotificationChannel(
                    NotificationChannel(CHANNEL_ID, "Transfers", NotificationManager.IMPORTANCE_LOW))
            }
            val open = PendingIntent.getActivity(context, 0,
                Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
            val cancel = PendingIntent.getService(context, 1,
                Intent(context, TransferService::class.java).setAction(ACTION_CANCEL),
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
            @Suppress("DEPRECATION")
            val builder = if (Build.VERSION.SDK_INT >= 26) Notification.Builder(context, CHANNEL_ID)
                          else Notification.Builder(context)
            val n = builder
                .setSmallIcon(if (upload) android.R.drawable.stat_sys_upload else android.R.drawable.stat_sys_download)
                .setContentTitle(title)
                .setContentText(text)
                .setContentIntent(open)
                .setOngoing(true)
                .setOnlyAlertOnce(true)
                .setProgress(1000, progress.coerceIn(0, 1000), progress < 0)
                .addAction(Notification.Action.Builder(null, cancelLabel, cancel).build())
                .build()
            lastNotification = n
            if (start && !running) {
                running = true
                val intent = Intent(context, TransferService::class.java)
                if (Build.VERSION.SDK_INT >= 26) context.startForegroundService(intent) else context.startService(intent)
            } else if (running) {
                nm.notify(NOTIFICATION_ID, n)
            }
        }

        fun stop(context: Context) {
            if (!running) return
            running = false
            context.startService(Intent(context, TransferService::class.java).setAction(ACTION_STOP))
        }
    }
}
