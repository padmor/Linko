import { requireNativeModule } from "expo";

type GatewayStartResult =
  | "REQUESTED"
  | "NOTIFICATION_PERMISSION_REQUIRED";

interface LinkoGatewayNativeModule {
  requestNotificationPermission(): Promise<boolean>;
  isBatteryOptimizationExempt(): boolean;
  openBatteryOptimizationSettings(): void;
  startSharing(): GatewayStartResult;
  stopSharing(): void;
}

const nativeGateway =
  requireNativeModule<LinkoGatewayNativeModule>("LinkoGateway");

export async function startSharing(): Promise<GatewayStartResult | "PERMISSION_DENIED"> {
  const permissionGranted =
    await nativeGateway.requestNotificationPermission();

  if (!permissionGranted) {
    return "PERMISSION_DENIED";
  }

  return nativeGateway.startSharing();
}

export function isBatteryOptimizationExempt(): boolean {
  return nativeGateway.isBatteryOptimizationExempt();
}

export function openBatteryOptimizationSettings(): void {
  nativeGateway.openBatteryOptimizationSettings();
}

export function stopSharing(): void {
  nativeGateway.stopSharing();
}
