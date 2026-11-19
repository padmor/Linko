# Linko

Share one phone's internet with another device over any distance, breaking the WiFi and hotspot range limit.

Phone B sends encrypted traffic through a relay to Phone A, which opens the real connections on its own internet. Planning lives in Notion.

## Layout

| Folder | Contents |
| --- | --- |
| `protocol/` | Shared packet envelope used by core and relay |
| `relay/` | Go relay and control API |
| `core/` | Go engine: WireGuard, gateway, client, transport |
| `core/integrationtest/` | Test-only end-to-end WireGuard and relay tests |
| `android/` | Kotlin: VpnService, foreground service, Keystore, native module |
| `app/` | Expo (React Native) UI |
| `scripts/` | Build, deploy and test helpers |

## Status

Planning done. Building starts with the desktop prototype in Go.
