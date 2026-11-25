#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NDK_VERSION="27.2.12479018"
GOBIND_VERSION="v0.0.0-20261117202452-47699113848a"
ARTIFACT_VERSION="0.1.0"
ARTIFACT_DIR="$ROOT_DIR/android/mobile-repo/com/linko/mobile/mobile/$ARTIFACT_VERSION"
ARTIFACT_FILE="$ARTIFACT_DIR/mobile-$ARTIFACT_VERSION.aar"

ANDROID_HOME="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
if [[ -z "$ANDROID_HOME" ]]; then
  echo "ANDROID_HOME or ANDROID_SDK_ROOT must point to the Android SDK." >&2
  exit 1
fi

export ANDROID_HOME
export ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-$ANDROID_HOME}"
export ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-$ANDROID_HOME/ndk/$NDK_VERSION}"
export ANDROID_NDK_ROOT="${ANDROID_NDK_ROOT:-$ANDROID_NDK_HOME}"

if [[ ! -d "$ANDROID_NDK_HOME" ]]; then
  echo "Android NDK $NDK_VERSION was not found at $ANDROID_NDK_HOME." >&2
  echo "Install it with Android Studio SDK Manager or sdkmanager." >&2
  exit 1
fi

if ! command -v go >/dev/null 2>&1; then
  echo "Go is required to build the Linko Android binding." >&2
  exit 1
fi

GOBIN="$(go env GOPATH)/bin"
mkdir -p "$GOBIN"
go install "golang.org/x/mobile/cmd/gobind@$GOBIND_VERSION"
export PATH="$GOBIN:$PATH"

mkdir -p "$ARTIFACT_DIR"
(
  cd "$ROOT_DIR/core/mobile"
  go tool gomobile bind \
    -androidapi=26 \
    -target=android/arm64 \
    -javapkg=com.linko.mobile \
    -o "$ARTIFACT_FILE" \
    .
)

cat > "$ARTIFACT_DIR/mobile-$ARTIFACT_VERSION.pom" <<POM
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.linko.mobile</groupId>
  <artifactId>mobile</artifactId>
  <version>$ARTIFACT_VERSION</version>
  <packaging>aar</packaging>
</project>
POM

echo "Built Go Android binding: $ARTIFACT_FILE"
