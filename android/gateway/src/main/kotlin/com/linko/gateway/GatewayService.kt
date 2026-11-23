package com.linko.gateway

import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Owns the foreground lifetime of a Phone A gateway session.
 *
 * Session secrets are deliberately not accepted in Intent extras. The
 * registered GatewayEngineFactory is responsible for resolving an approved
 * session through the secure app layer.
 */
class GatewayService : Service() {
    private val gatewayExecutor = Executors.newSingleThreadExecutor { task ->
        Thread(task, "linko-gateway").apply { isDaemon = true }
    }
    private val mainHandler = Handler(Looper.getMainLooper())
    private val destroyed = AtomicBoolean(false)

    // Accessed only on gatewayExecutor.
    private var activeGateway: GatewayEngine? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> startSharing(startId)
            ACTION_STOP -> stopSharing(startId)
            else -> stopSelfResult(startId)
        }

        // A session is never restarted without a fresh, visible user action.
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        destroyed.set(true)

        gatewayExecutor.execute {
            closeActiveGateway()
        }
        gatewayExecutor.shutdown()

        super.onDestroy()
    }

    private fun startSharing(startId: Int) {
        if (!GatewayNotificationPermission.isGranted(this)) {
            stopSelfResult(startId)
            return
        }

        GatewayNotification.createChannel(this)

        try {
            val notification = GatewayNotification.build(
                this,
                getString(R.string.gateway_notification_starting)
            )

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                startForeground(
                    GatewayNotification.NOTIFICATION_ID,
                    notification,
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
                )
            } else {
                startForeground(GatewayNotification.NOTIFICATION_ID, notification)
            }
        } catch (_: SecurityException) {
            stopSelfResult(startId)
            return
        }

        gatewayExecutor.execute {
            if (activeGateway != null || destroyed.get()) return@execute

            var candidate: GatewayEngine? = null
            try {
                candidate = GatewayEngineRegistry.create(applicationContext)
                candidate.start()

                if (destroyed.get()) {
                    candidate.stop()
                    return@execute
                }

                activeGateway = candidate
                mainHandler.post {
                    if (!destroyed.get()) {
                        val notificationManager =
                            getSystemService(NotificationManager::class.java)
                        runCatching {
                            notificationManager.notify(
                                GatewayNotification.NOTIFICATION_ID,
                                GatewayNotification.build(
                                    this,
                                    getString(R.string.gateway_notification_active)
                                )
                            )
                        }
                    }
                }
            } catch (_: Exception) {
                runCatching { candidate?.stop() }
                activeGateway = null

                mainHandler.post {
                    if (!destroyed.get()) {
                        stopForeground(STOP_FOREGROUND_REMOVE)
                        stopSelfResult(startId)
                    }
                }
            }
        }
    }

    private fun stopSharing(startId: Int) {
        gatewayExecutor.execute {
            closeActiveGateway()

            mainHandler.post {
                if (!destroyed.get()) {
                    stopForeground(STOP_FOREGROUND_REMOVE)
                    stopSelfResult(startId)
                }
            }
        }
    }

    private fun closeActiveGateway() {
        val gateway = activeGateway ?: return
        activeGateway = null
        runCatching { gateway.stop() }
    }

    companion object {
        internal const val ACTION_START = "com.linko.gateway.action.START"
        internal const val ACTION_STOP = "com.linko.gateway.action.STOP"
    }
}
