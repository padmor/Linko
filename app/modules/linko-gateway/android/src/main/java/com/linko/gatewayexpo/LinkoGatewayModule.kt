package com.linko.gatewayexpo

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
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
