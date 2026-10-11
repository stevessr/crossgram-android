import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { expect, it } from "vitest";
import { patchWss } from "../features/server-switch/wss-patch.js";
it("persists native routing, key-file binding and bounded socketpair patches idempotently", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "crossgram-wss-patch-"));
  const fixtures: Record<string, string> = {
    "src/main/java/org/telegram/tgnet/ConnectionsManager.java": "    public static native void native_setServerConfig();\n",
    "jni/TgNetWrapper.cpp": "jlong getFreeBuffer() {}\n",
    "jni/tgnet/ConnectionsManager.h": "    bool hasCustomServer() const;\n",
    "jni/tgnet/ConnectionsManager.cpp": `void ConnectionsManager::loadConfig() {\n        buffer->reuse();\n}
void ConnectionsManager::saveConfig() { save(); }
void ConnectionsManager::saveConfigInternal(Buffer *buffer) { save(); }
void ConnectionsManager::setServerConfig() {\n        currentDatacenterId = 2;\n}`,
    "jni/tgnet/Connection.cpp": `void Connection::connect() {\n    openConnection(hostAddress, hostPort, secret, false, 1);\n}
void send() {\n        if (useSecret != 0) {\n            std::string *currentSecret = getCurrentSecret(useSecret);\n        }\n}`,
    "jni/tgnet/ByteStream.h": "    bool hasData();\n",
    "jni/tgnet/ByteStream.cpp": "bool ByteStream::hasData() { return false; }\n",
    "jni/tgnet/ConnectionSocket.cpp": `void ConnectionSocket::openConnection() {\n    memset(&socketAddress, 0, sizeof(sockaddr_in));\n}
void ConnectionSocket::writeBuffer(uint8_t *data, uint32_t size) { send(); }
void ConnectionSocket::writeBuffer(NativeByteBuffer *buffer) { send(); }`,
  };
  try {
    for (const [file, text] of Object.entries(fixtures)) {
      const p = path.join(dir, "TMessagesProj", file); await mkdir(path.dirname(p), { recursive: true }); await writeFile(p, text);
    }
    const first: string[] = []; await patchWss(dir, first); expect(first.length).toBeGreaterThan(10);
    const second: string[] = []; await patchWss(dir, second); expect(second).toEqual([]);
    const read = (f: string) => readFile(path.join(dir, "TMessagesProj/jni/tgnet", f), "utf8");
    expect(await read("Connection.cpp")).toContain("crossgramServerBlocked) return;");
    expect(await read("Connection.cpp")).toContain('hostAddress = "wss:"');
    expect(await read("ConnectionSocket.cpp")).toContain("socketpair(AF_UNIX");
    expect(await read("ConnectionSocket.cpp")).toContain("crossgramQueuedBytes() + buffer->remaining() > 8 * 1024 * 1024");
    const manager = await read("ConnectionsManager.cpp");
    expect(manager).toContain("crossgramWssBindingBlocked(customServerId");
    expect(manager).toContain("if (crossgramServerBlocked) return;");
    expect(manager).toContain("buffer->writeInt32(0x43575331)");
    expect(manager).toContain("buffer->readString(&error)");
    expect(manager).toContain("suspendConnections(true)");
  } finally { await rm(dir, { recursive: true, force: true }); }
});
