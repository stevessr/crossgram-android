package org.telegram.messenger.server_switch;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;

/** RFC 6455 subset: binary byte stream, no extensions or message buffering. */
public final class WssWire {
    public static final int MAX_MESSAGE = 8 * 1024 * 1024;
    private final InputStream input;
    private final OutputStream output;
    private final SecureRandom random = new SecureRandom();
    public WssWire(InputStream input, OutputStream output) { this.input = input; this.output = output; }
    static String base64(byte[] data) {
        String a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        StringBuilder s = new StringBuilder();
        for (int i = 0; i < data.length; i += 3) {
            int n = (data[i] & 255) << 16 | (i+1 < data.length ? (data[i+1] & 255) << 8 : 0)
                    | (i+2 < data.length ? data[i+2] & 255 : 0);
            s.append(a.charAt(n >>> 18)).append(a.charAt(n >>> 12 & 63));
            s.append(i+1 < data.length ? a.charAt(n >>> 6 & 63) : '=');
            s.append(i+2 < data.length ? a.charAt(n & 63) : '=');
        }
        return s.toString();
    }
    public void handshake(WssUrl url) throws Exception {
        byte[] nonce = new byte[16]; random.nextBytes(nonce);
        String key = base64(nonce);
        output.write(("GET " + url.resource + " HTTP/1.1\r\nHost: " + url.authority
                + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13"
                + "\r\nSec-WebSocket-Key: " + key + "\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
        output.flush();
        ByteArrayOutputStream headers = new ByteArrayOutputStream();
        int tail = 0;
        while (headers.size() < 16384) {
            int b = readByte(); headers.write(b); tail = tail << 8 | b;
            if (tail == 0x0d0a0d0a) break;
        }
        if (tail != 0x0d0a0d0a) throw new IOException("wss_upgrade_headers_limit");
        String[] lines = new String(headers.toByteArray(), StandardCharsets.US_ASCII).split("\r\n");
        if (!lines[0].matches("HTTP/1\\.1 101(?: .*)?")) throw new IOException("wss_upgrade_status");
        Map<String,String> fields = new HashMap<>();
        for (int i = 1; i < lines.length; i++) {
            int colon = lines[i].indexOf(':');
            if (colon <= 0) throw new IOException("wss_upgrade_header");
            String name = lines[i].substring(0, colon).toLowerCase(Locale.ROOT);
            String value = lines[i].substring(colon+1).trim();
            if (fields.containsKey(name)) {
                // HTTP permits repeated extension/metadata fields such as Cloudflare's
                // Server-Timing. Reject ambiguity only for fields that affect upgrade
                // validation; ignore duplicate unrelated metadata.
                if (name.equals("connection") || name.equals("upgrade")
                        || name.startsWith("sec-websocket-")) throw new IOException("wss_upgrade_duplicate");
                continue;
            }
            fields.put(name, value);
        }
        String accept = base64(MessageDigest.getInstance("SHA-1").digest((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").getBytes(StandardCharsets.US_ASCII)));
        if (!accept.equals(fields.get("sec-websocket-accept"))
                || !"websocket".equalsIgnoreCase(fields.get("upgrade"))
                || !Arrays.asList(fields.getOrDefault("connection", "").toLowerCase(Locale.ROOT).split("\\s*,\\s*")).contains("upgrade")
                || fields.containsKey("sec-websocket-extensions") || fields.containsKey("sec-websocket-protocol"))
            throw new IOException("wss_upgrade_validation");
    }
    private int readByte() throws IOException { int b = input.read(); if (b < 0) throw new EOFException("wss_remote_close"); return b; }
    private void readFully(byte[] bytes, int size) throws IOException {
        int p = 0; while (p < size) { int n = input.read(bytes, p, size-p); if (n < 0) throw new EOFException("wss_remote_close"); p += n; }
    }
    public synchronized void send(int opcode, byte[] bytes, int count) throws IOException {
        if (count < 0 || count > 16384 || count > bytes.length) throw new IOException("wss_output_limit");
        byte[] frame = new byte[count + (count < 126 ? 6 : 8)]; int p = 0;
        frame[p++] = (byte)(128 | opcode);
        if (count < 126) frame[p++] = (byte)(128 | count);
        else { frame[p++] = (byte)254; frame[p++] = (byte)(count >>> 8); frame[p++] = (byte)count; }
        byte[] mask = new byte[4]; random.nextBytes(mask);
        for (byte b : mask) frame[p++] = b;
        for (int i = 0; i < count; i++) frame[p++] = (byte)(bytes[i] ^ mask[i%4]);
        output.write(frame); output.flush();
    }
    public void receive(OutputStream sink) throws IOException {
        boolean fragmented = false; long message = 0;
        byte[] chunk = new byte[16384];
        for (;;) {
            int a = readByte(), b = readByte(), op = a & 15; boolean fin = (a & 128) != 0;
            if ((a & 112) != 0 || (b & 128) != 0) throw new IOException("wss_frame_flags");
            long len = b & 127;
            if (len == 126) { len = readByte() * 256L + readByte(); if (len < 126) throw new IOException("wss_frame_length"); }
            else if (len == 127) {
                len = 0; for (int i = 0; i < 8; i++) { int v = readByte(); if (i == 0 && v > 127) throw new IOException("wss_frame_length"); len = len << 8 | v; }
                if (len < 65536) throw new IOException("wss_frame_length");
            }
            if (op >= 8) {
                if (!fin || len > 125 || (op != 8 && op != 9 && op != 10)) throw new IOException("wss_control");
                byte[] control = new byte[(int)len]; readFully(control, (int)len);
                if (op == 8) {
                    if (len == 1) throw new IOException("wss_close_format");
                    if (len >= 2) {
                        int code = (control[0] & 255) * 256 + (control[1] & 255);
                        if (!(code >= 1000 && code <= 1014 && code != 1004 && code != 1005 && code != 1006 || code >= 3000 && code <= 4999)) throw new IOException("wss_close_code");
                        StandardCharsets.UTF_8.newDecoder().onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                                .decode(java.nio.ByteBuffer.wrap(control, 2, control.length-2));
                    }
                    send(8, control, control.length);
                    throw new EOFException("wss_remote_close");
                }
                if (op == 9) send(10, control, control.length);
                continue;
            }
            if (op != 2 && op != 0 || op == 0 && !fragmented || op == 2 && fragmented) throw new IOException("wss_binary_required");
            message += len;
            if (len > MAX_MESSAGE || message > MAX_MESSAGE) throw new IOException("wss_input_limit");
            fragmented = !fin;
            while (len > 0) { int n = (int)Math.min(len, chunk.length); readFully(chunk, n); sink.write(chunk, 0, n); len -= n; }
            sink.flush(); if (fin) message = 0;
        }
    }
}
