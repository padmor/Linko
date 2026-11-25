package com.linko.gatewayexpo

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.PowerManager
import android.provider.Settings
import com.linko.gateway.GatewayServiceController
import expo.modules.interfaces.permissions.PermissionsStatus
import expo.modules.kotlin.Promise
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition

class LinkoGatewayModule : Module() {
  override fun definition() = ModuleDefinition {
    Name("LinkoGateway")

    AsyncFunction("requestNotificationPermission") { promise: Promise ->
      val context = appContext.reactContext
        ?: throw IllegalStateException("Linko app context is unavailable")

      if (
        Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU ||
        context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) ==
        PackageManager.PERMISSION_GRANTED
      ) {
        promise.resolve(true)
        return@AsyncFunction
      }

      val permissions = appContext.permissions
        ?: throw IllegalStateException("Expo permissions module is unavailable")

      permissions.askForPermissions({ permissionResults ->
        val granted = permissionResults[Manifest.permission.POST_NOTIFICATIONS]?.status ==
          PermissionsStatus.GRANTED
        promise.resolve(granted)
      }, Manifest.permission.POST_NOTIFICATIONS)
    }

    Function("isBatteryOptimizationExempt") {
      val context = appContext.reactContext
        ?: throw IllegalStateException("Linko app context is unavailable")

      if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
        return@Function true
      }

      val powerManager = context.getSystemService(Context.POWER_SERVICE) as? PowerManager
        ?: throw IllegalStateException("Android power service is unavailable")

      powerManager.isIgnoringBatteryOptimizations(context.packageName)
    }

    Function("openBatteryOptimizationSettings") {
      val context = appContext.reactContext
        ?: throw IllegalStateException("Linko app context is unavailable")

      val intent = Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)
        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)

      context.startActivity(intent)
    }

    Function("startSharing") {
      val context = appContext.reactContext
        ?: throw IllegalStateException("Linko app context is unavailable")

      GatewayServiceController.startFromVisibleUi(context).name
    }

    Function("stopSharing") {
      val context = appContext.reactContext
        ?: throw IllegalStateException("Linko app context is unavailable")

      GatewayServiceController.stopSharing(context)
    }
  }
}
