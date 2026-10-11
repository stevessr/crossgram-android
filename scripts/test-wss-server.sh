#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
server="$(cd "${1:?Pass local std-microblock/crossgram checkout with test dependencies}" && pwd)"
build="$(mktemp -d)"
fixture="$(mktemp "$server/packages/mtproto/src/transport/android-wss-XXXXXX.e2e.test.ts")"
trap 'rm -f "$fixture"; rm -rf "$build"' EXIT
source="$root/features/server-switch/files/java/org/telegram/messenger/server_switch"
javac -d "$build" "$source"/{WssUrl,WssWire,WssTls}.java "$root/tests/fixtures/wss/ReqPqHarness.java"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=localhost.localdomain \
  -addext subjectAltName=DNS:localhost.localdomain -keyout "$build/key.pem" -out "$build/cert.pem" 2>/dev/null
keytool -importcert -noprompt -alias fixture -file "$build/cert.pem" -keystore "$build/trust.p12" -storepass changeit >/dev/null
printf '#!/usr/bin/env bash\nexec java -Djavax.net.ssl.trustStore=%q -Djavax.net.ssl.trustStorePassword=changeit -cp %q ReqPqHarness "$1" "$3"\n' "$build/trust.p12" "$build" > "$build/client"
chmod +x "$build/client"
cp "$root/tests/fixtures/wss/server.e2e.ts.fixture" "$fixture"
export WSS_FIXTURE_CERT="$build/cert.pem" WSS_FIXTURE_KEY="$build/key.pem" WSS_FIXTURE_BINARY="$build/client"
cd "$server"
"$server/node_modules/.bin/vitest" run --config vitest.mtproto-e2e.config.mts "$fixture" --maxWorkers=1
