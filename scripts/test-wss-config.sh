#!/usr/bin/env bash
# Host schema test: actual org.json, Android Base64 replaced with equivalent JDK Base64.
set -euo pipefail
cd "$(dirname "$0")/.."
json="$(realpath "${1:?Pass an org.json jar (CI uses json-20250517.jar)}")"
sdk="${ANDROID_HOME:-${ANDROID_SDK_ROOT:?Set ANDROID_HOME or ANDROID_SDK_ROOT}}"
jar="$sdk/platforms/android-35/android.jar"
build="$(mktemp -d)"
trap 'rm -rf "$build"' EXIT
mkdir -p "$build/src/android/util"
cat > "$build/src/android/util/Base64.java" <<'JAVA'
package android.util; public class Base64 {
    public static final int DEFAULT=0;
    public static byte[] decode(String s,int flags){return java.util.Base64.getDecoder().decode(s);}
}
JAVA
mapfile -t stubs < <(find tests/fixtures/wss/stubs -name '*.java' -print)
javac -cp "$jar" -d "$build/classes" "${stubs[@]}" "$build/src/android/util/Base64.java" \
  features/server-switch/files/java/org/telegram/messenger/server_switch/{ServerSwitchConfig,WssUrl}.java \
  features/server-switch/files/java/org/telegram/messenger/server_switch/WssRsa.java tests/fixtures/wss/ConfigHarness.java
java -cp "$build/classes:$json:$jar" ConfigHarness examples/crossgram-wss-test.json
