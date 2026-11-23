package com.linko.gateway

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build

internal object GatewayNotification {
    const val CHANNEL_ID = "linko_gateway_status"
    const val NOTIFICATION_ID = 4101

    private const val STOP_REQUEST_CODE = 4102

    fun createChannel(context: Context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return

        val channel = NotificationChannel(
            CHANNEL_ID,
            context.getString(R.string.gateway_channel_name),
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = context.getString(R.string.gateway_channel_description)
            setShowBadge(false)
        }

        context.getSystemService(NotificationManager::class.java)
            .createNotificationChannel(channel)
    }

    fun build(context: Context, status: String): Notification {
        val stopIntent = Intent(context, GatewayService::class.java).apply {
            action = GatewayService.ACTION_STOP
        }
        val stopAction = PendingIntent.getService(
            context,
            STOP_REQUEST_CODE,
            stopIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        return Notification.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_linko_notification)
            .setContentTitle(context.getString(R.string.gateway_notification_title))
            .setContentText(status)
            .setCategory(Notification.CATEGORY_SERVICE)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setShowWhen(false)
            .setLocalOnly(true)
            .addAction(
                0,
                context.getString(R.string.gateway_notification_stop),
                stopAction
            )
            .build()
    }
}
