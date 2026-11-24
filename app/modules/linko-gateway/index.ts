import { requireNativeModule } from "expo";

type GatewayStartResult =
  | "REQUESTED"
  | "NOTIFICATION_PERMISSION_REQUIRED";

interface LinkoGatewayNativeModule {
  requestNotificationPermission(): Promise<boolean>;
  startSharing(): GatewayStartResult;
  stopSharing(): void;
}

export default requireNativeModule<LinkoGatewayNativeModule>("LinkoGateway");
