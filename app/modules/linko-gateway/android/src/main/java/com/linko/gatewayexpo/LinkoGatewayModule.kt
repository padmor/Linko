package com.linko.gatewayexpo

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts
import com.linko.gateway.GatewayServiceController
import expo.modules.kotlin.Promise
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition

class LinkoGatewayModule : Module() {
  private var permissionPromise: Promise? = null
  private lateinit var notificationPermissionLauncher: ActivityResultLauncher<String>

  override fun definition() = ModuleDefinition {
    Name("LinkoGateway")

    RegisterActivityContracts {
      notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
      ) { _, granted ->
        permissionPromise?.resolve(granted)
        permissionPromise = null
      }
    }

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

      if (permissionPromise != null) {
        promise.reject(
          "E_PERMISSION_PENDING",
          "A notification permission request is already active",
          null
        )
        return@AsyncFunction
      }

      permissionPromise = promise
      notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
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
