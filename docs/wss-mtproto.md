# Android WSS MTProto through Cloudflare

## Import

Use an **empty account slot** → login screen → Server → Add JSON. Old TCP JSON
and untouched official accounts still use the original native TCP transport.
WSS requires Android 7 / API 24 or newer; older Android can still use TCP.

```json
{
  "name": "My CrossGram",
  "transport": "websocket",
  "websocket_url": "wss://x.wmc.de5.net/mtproto",
  "enable_special_config": false,
  "rsa_key": "-----BEGIN RSA PUBLIC KEY-----\nYOUR_ACTUAL_SERVER_PUBLIC_KEY\n-----END RSA PUBLIC KEY-----"
}
```

The PKCS#1 RSA public key must be a valid 2048-bit key belonging to the origin.
Never import a private key or change the existing origin RSA key/auth store just
to match a client example. `examples/crossgram-wss-test.json` uses an actual
**test-only public key** and cannot authenticate the existing production origin.
Generate a real configuration from your public key:

```sh
node scripts/wss-config.mjs server-public.pem wss://x.wmc.de5.net/mtproto > server.json
```

WSS URL: strict `wss://`, DNS hostname (no literal IP, userinfo, fragment,
backslash, whitespace, malformed escapes), explicit path, optional port 1–65535
and query. TLS uses platform trust, DNS hostname verification, explicit SNI,
TLS 1.2/1.3; never ignore certificate failures. Query parameters are transmitted
unchanged and never logged. Non-ASCII paths must be percent-encoded. JSON is
limited to 1 MiB, URLs to 4096 characters. WSS forbids TCP host/port fields and
requires literal `enable_special_config: false`.

Absent `dcs` maps DC 1–5 to the top-level URL. An explicit `dcs` replaces this
map, requires DC 2, unique integer IDs 1–1000, and permits `websocket_url` per DC;
no DC IP/port fields. An unmapped DC (including a CDN DC) fails closed instead
of connecting to Telegram. The native address placeholders are **never** used
as TCP destinations in WSS mode. Example:

```json
"dcs": [
  {"id": 1},
  {"id": 2, "websocket_url": "wss://x.wmc.de5.net/mtproto?dc=2"}
]
```

## Transport and isolation

The persistent server-switch patch installs Java WSS helpers, JNI callback,
private AF_UNIX socketpair, and native tgnet hooks. No local listening TCP proxy,
HTTP CONNECT, MTProxy, Spectrum, or fixed Cloudflare IP is involved. Java owns
one socketpair endpoint; the original epoll socket owns the other. Native
MTProto RSA/DH/authentication, AES and obfuscated abridged framing remain in
tgnet. Binary WebSocket frames carry this byte stream; neither send nor receive
assumes WebSocket frame/message boundaries equal MTProto packet boundaries.
Global MTProxy secrets are not mixed into WSS framing. TCP paths remain unchanged.

Backpressure is blocking, not an unbounded Java queue: 16 KiB chunks, 64 KiB
requested kernel send buffers per socketpair endpoint, native outgoing cap
8 MiB / 4096 entries, WebSocket message cap 8 MiB, native MTProto packet cap
2 MiB, HTTP upgrade header cap 16 KiB. At most 32 bridges exist process-wide,
including pending DNS operations. No WebSocket extensions or compression are
negotiated. Masked client binary frames and fragmented server binary messages,
interleaved ping/pong, close, invalid flags/lengths and text rejection are handled.

Open/upgrade timeout: 15 s; stalled network write/local delivery: 30 s; TLS read
idle: 120 s. Existing native connection/request timers can close earlier. A
shared watchdog closes descriptors on timeout. Each native reconnect gets a
new WSS/TLS connection and fresh obfuscation state; no encrypted bytes are
replayed into a different stream. Native tgnet owns retry/backoff; the bridge
does not add a second retry loop. DNS calls cannot always be interrupted by the
platform; the global slot cap prevents unbounded stuck DNS worker growth.

WSS identity is SHA-256 of length-delimited transport, RSA public key, canonical
base URL and sorted DC/URL map, independent of display name and imported ID.
A magic-tagged optional extension in **the same account's tgnet.dat key file**
binds its native keys to that identity. It does not change the existing Android
key-file encryption policy. Existing official/TCP records without extension
retain legacy behavior. WSS never adopts unbound existing keys. Identity
mismatch, a corrupted extension/store, or a missing selected configuration keeps
the slot offline and preserves its key file; no official/TCP fallback occurs.
Signed-in slots cannot switch server (including switching to official). Use a
new empty slot. Changing URL/RSA/DC routing of a signed-in WSS slot requires a
new slot or explicit logout first. Do not downgrade an active WSS account to an
old client that does not enforce this binding.

Redacted errors use `crossgram_wss=` with categories for binding/configuration,
capacity, DNS/connect, TLS validation, upgrade, frame/protocol/size violations,
remote close and timeout. No URL query, RSA/private key or MTProto payload is
logged. Host tests substitute Android/Telegram classes and are not device proof.

## Origin and Cloudflare (instructions only)

No production machine or Cloudflare account is modified by this patch.
For `std-microblock/crossgram`, use MTProto service `wsPort` / `wsPath` to mount
`/mtproto` on the existing shared HTTP server, retaining its existing RSA key and
authentication data. `/api` belongs to WebUI management RPC and is **not** the
MTProto transport. Keep existing management protection unchanged.

A typical origin route is a TLS reverse proxy on 8443, forwarding only
`/mtproto` to the shared HTTP listener at `127.0.0.1:3140`, with HTTP/1.1 and
`Upgrade`/`Connection` headers and an appropriately long read timeout. Do not
send HTTPS directly to a plaintext listener or route WSS into MTProto TCP 4430.
Use orange-cloud DNS for `x.wmc.de5.net`, edge HTTPS 443, Full (strict) TLS,
a valid origin certificate for the hostname, and a hostname/path-scoped Origin
Rule overriding destination port to the TLS proxy's 8443. Enable WebSockets.
Avoid challenge/Access login redirects on the dedicated transport path; keep
those controls on the management path. Neither clients nor operators should
pin Cloudflare IPs. See the Desktop repository's server-switch/WSS.md for the
expanded nginx/Origin Rule example; adjust to your actual installation.

## Verification and build

- `yarn check`: TypeScript, patch fixtures, Java URL/upgrade/binary streaming,
  real loopback trusted/untrusted TLS/hostname/SNI, production C++ binding gate.
- `scripts/test-wss-java.sh`: compile Android helpers against Android SDK 35
  (Telegram interfaces stubbed), not a full APK build.
- `scripts/test-wss-config.sh /path/to/org-json.jar`: real JSON schema/identity
  harness, with equivalent JDK Base64 and Telegram stubs. CI pins JSON jar SHA256.
- `scripts/test-wss-server.sh /path/to/local/crossgram`: actual local CrossGram
  pre-auth req_pq/resPQ, nonce and RSA fingerprint, generated temporary keys and
  loopback TLS only. Does not validate RSA/DH completion, login or chats.
- Full APK: Actions → Build and publish Crossgram APKs, `client=telegram`,
  `publish=false`. Without signing secrets, build-only mode uses a temporary
  test keystore. Test APKs cannot update production-signed installations. No
  private key is uploaded. Scheduled/publishing runs still require real secrets.

Do not equate patch applicability, native syntax checking, host tests, or a
queued build with a compiled APK, Android device acceptance or public CDN
end-to-end verification. Six upstream default-branch source patch/idempotence
checks are not proof that all six latest release APKs build.
