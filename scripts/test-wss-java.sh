#!/usr/bin/env bash
# Type-check injected Android helpers against the real SDK; Telegram surfaces are stubs.
set -euo pipefail
cd "$(dirname "$0")/.."
sdk="${ANDROID_HOME:-${ANDROID_SDK_ROOT:?Set ANDROID_HOME or ANDROID_SDK_ROOT}}"
jar="$sdk/platforms/android-35/android.jar"
test -s "$jar"
build="$(mktemp -d)"
trap 'rm -rf "$build"' EXIT
mapfile -t stubs < <(find tests/fixtures/wss/stubs -name '*.java' -print)
javac -source 8 -target 8 -cp "$jar" -d "$build" "${stubs[@]}" \
  features/server-switch/files/java/org/telegram/messenger/server_switch/{ServerSwitchConfig,WssUrl,WssWire,WssBridge,WssRsa,WssTls}.java
