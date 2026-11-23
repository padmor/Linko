package com.linko.gateway

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build

enum class GatewayStartRequestResult {
    REQUESTED,
    NOTIFICATION_PERMISSION_REQUIRED
}

/**
 * Entry point for the future app UI.
 *
 * Call startFromVisibleUi only in response to a user action while the app is
 * visible. On Android 13+, the app must request POST_NOTIFICATIONS before
 * calling it.
 */
object GatewayServiceController {
    fun startFromVisibleUi(context: Context): GatewayStartRequestResult {
        if (!GatewayNotificationPermission.isGranted(context)) {
            return GatewayStartRequestResult.NOTIFICATION_PERMISSION_REQUIRED
        }

        val intent = Intent(context, GatewayService::class.java).apply {
            action = GatewayService.ACTION_START
        }
        context.startForegroundService(intent)
        return GatewayStartRequestResult.REQUESTED
    }

    fun stopSharing(context: Context) {
        val intent = Intent(context, GatewayService::class.java).apply {
            action = GatewayService.ACTION_STOP
        }
        context.startService(intent)
    }
}

internal object GatewayNotificationPermission {
    fun isGranted(context: Context): Boolean {
        return Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU ||
            context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) ==
            PackageManager.PERMISSION_GRANTED
    }
}
