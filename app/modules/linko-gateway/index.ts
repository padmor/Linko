import { requireNativeModule } from "expo";

type GatewayStartResult =
  | "REQUESTED"
  | "NOTIFICATION_PERMISSION_REQUIRED";

interface LinkoGatewayNativeModule {
  requestNotificationPermission(): Promise<boolean>;
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

export function stopSharing(): void {
  nativeGateway.stopSharing();
}
