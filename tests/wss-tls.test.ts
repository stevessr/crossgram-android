import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { createServer } from "node:tls";
import { promisify } from "node:util";
import { expect, it } from "vitest";
const exec = promisify(execFile);
it("checks real trusted/untrusted TLS, SNI, hostname and WSS binary stream on loopback", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "crossgram-wss-tls-"));
  const source = "features/server-switch/files/java/org/telegram/messenger/server_switch";
  const sockets = new Set<import("node:tls").TLSSocket>();
  let requests = 0;
  try {
    await exec("javac", ["-d", dir, ...["WssUrl", "WssWire", "WssTls"].map(n => `${source}/${n}.java`), "tests/fixtures/wss/WssHarness.java"]);
    for (const [name, host] of [["good", "localhost.localdomain"], ["wrong", "wrong.example"]]) {
      await exec("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", `/CN=${host}`, "-addext", `subjectAltName=DNS:${host}`, "-keyout", `${dir}/${name}.key`, "-out", `${dir}/${name}.pem`]);
      await exec("keytool", ["-importcert", "-noprompt", "-alias", name!, "-file", `${dir}/${name}.pem`, "-keystore", `${dir}/trust.p12`, "-storepass", "changeit"]);
    }
    async function run(name: string, trusted: boolean) {
      const server = createServer({ cert: await readFile(`${dir}/${name}.pem`), key: await readFile(`${dir}/${name}.key`) }, socket => {
        sockets.add(socket); socket.on("close", () => sockets.delete(socket)); socket.on("error", () => {});
        let pending = Buffer.alloc(0), upgraded = false;
        socket.on("data", data => {
          pending = Buffer.concat([pending, data]);
          if (!upgraded) {
            const end = pending.indexOf("\r\n\r\n"); if (end < 0) return;
            const request = pending.subarray(0, end).toString(); pending = pending.subarray(end+4);
            expect(socket.servername).toBe("localhost.localdomain");
            expect(request).toContain("GET /mtproto?fixture=1 HTTP/1.1"); requests++;
            const key = /Sec-WebSocket-Key: ([^\r]+)/.exec(request)![1]!;
            const accept = createHash("sha1").update(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest("base64");
            socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);
            upgraded = true;
          }
          if (pending.length >= 10 && pending[0] === 130) {
            expect(pending[1]).toBe(132);
            const payload = [...pending.subarray(6, 10)].map((b,i) => b ^ pending[2+i%4]!);
            expect(payload).toEqual([1,2,3,4]); pending = pending.subarray(10);
            // Two fragments, coalesced into one TLS write; no MTProto packet boundary assumptions.
            socket.end(Buffer.from([2,1,1,128,3,2,3,4,136,0]));
          }
        });
      });
      server.on("tlsClientError", () => {});
      await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
      try {
        const port = (server.address() as import("node:net").AddressInfo).port;
        return await exec("java", [...(trusted ? [`-Djavax.net.ssl.trustStore=${dir}/trust.p12`, "-Djavax.net.ssl.trustStorePassword=changeit"] : []), "-cp", dir, "WssHarness", `wss://localhost.localdomain:${port}/mtproto?fixture=1`], { timeout: 10000 });
      } finally {
        for (const socket of sockets) socket.destroy();
        await new Promise<void>(resolve => server.close(() => resolve()));
      }
    }
    expect((await run("good", true)).stdout).toContain("Trusted TLS");
    await expect(run("good", false)).rejects.toThrow();
    await expect(run("wrong", true)).rejects.toThrow();
    expect(requests).toBe(1);
  } finally { await rm(dir, { recursive: true, force: true }); }
}, 30000);
