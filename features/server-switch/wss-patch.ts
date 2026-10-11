import path from "node:path";
import { fileURLToPath } from "node:url";
import { readUtf8, writeUtf8IfChanged } from "../../src/core/files.js";
import { editDeclarationBody, PatchError } from "../../src/core/text-edit.js";
const root = path.dirname(fileURLToPath(import.meta.url));
function insert(s: string, anchor: string, value: string, marker: string, file: string): string {
  if (s.includes(marker)) return s;
  if (s.split(anchor).length !== 2) throw new PatchError(file, `WSS anchor missing or ambiguous: ${anchor}`);
  return s.replace(anchor, value + anchor);
}
export async function patchWss(sourceRoot: string, changed: string[]): Promise<void> {
  async function edit(file: string, fn: (s: string) => string) {
    if (await writeUtf8IfChanged(path.join(sourceRoot, file), fn(await readUtf8(path.join(sourceRoot, file))))) changed.push(file);
  }
  for (const name of ["WssUrl", "WssWire", "WssBridge", "WssRsa", "WssTls"]) {
    const relative = `TMessagesProj/src/main/java/org/telegram/messenger/server_switch/${name}.java`;
    if (await writeUtf8IfChanged(path.join(sourceRoot, relative), await readUtf8(path.join(root, "files/java/org/telegram/messenger/server_switch", `${name}.java`)))) changed.push(relative);
  }
  const binding = "TMessagesProj/jni/tgnet/CrossgramWssBinding.h";
  if (await writeUtf8IfChanged(path.join(sourceRoot, binding), await readUtf8(path.join(root, "files/native/wss-binding.h")))) changed.push(binding);
  await edit("TMessagesProj/src/main/java/org/telegram/tgnet/ConnectionsManager.java", s => insert(s
    .replace("openCrossgramWss(int account, int dc, int fd)", "openCrossgramWss(int account, int dc, int fd, String identity)")
    .replace("WssBridge.open(account, dc, fd);", "WssBridge.open(account, dc, fd, identity);"),
    "    public static native void native_setServerConfig(",
    "    public static boolean openCrossgramWss(int account, int dc, int fd, String identity) {\n        return org.telegram.messenger.server_switch.WssBridge.open(account, dc, fd, identity);\n    }\n\n",
    "boolean openCrossgramWss(", "ConnectionsManager.java"));
  const wrapper = await readUtf8(path.join(root, "files/native/wss-wrapper.cpp"));
  await edit("TMessagesProj/jni/TgNetWrapper.cpp", s => {
    s = insert(s, "jlong getFreeBuffer(", wrapper + "\n", "bool crossgramOpenWss(", "TgNetWrapper.cpp");
    return editDeclarationBody(s, /bool\s+crossgramOpenWss\s*\(/, "TgNetWrapper.cpp", "pin WSS native identity",
      () => wrapper.slice(wrapper.indexOf("{") + 1, wrapper.lastIndexOf("}")));
  });
  await edit("TMessagesProj/jni/tgnet/ConnectionsManager.h", s => insert(insert(s, "    bool hasCustomServer() const;",
    "    const std::string &getWssServerIdentity() const { return customServerId; }\n",
    "getWssServerIdentity() const", "ConnectionsManager.h"), "    bool hasCustomServer() const;",
    "    bool isWssServer() const { return customServerId.compare(0, 4, \"wss:\") == 0; }\n    bool crossgramServerBlocked = false;\n    std::string crossgramKeyIdentity;\n",
    "bool isWssServer() const", "ConnectionsManager.h"));
  await edit("TMessagesProj/jni/tgnet/ConnectionsManager.cpp", s => {
    if (!s.includes('#include "CrossgramWssBinding.h"')) s = '#include "CrossgramWssBinding.h"\n' + s;
    s = editDeclarationBody(s, /void\s+ConnectionsManager::loadConfig\s*\(/, "ConnectionsManager.cpp", "WSS binding load", body => {
      if (body.includes("crossgram-wss-binding-load")) return body;
      body = body.replace("        buffer->reuse();", `        // crossgram-wss-binding-load: extension is part of the same key file.
        if (buffer->remaining() > 0) {
            bool error = false;
            uint32_t magic = buffer->readUint32(&error);
            if (magic == 0x43575331 && !error) crossgramKeyIdentity = buffer->readString(&error);
            if (error || magic != 0x43575331 || buffer->remaining() != 0) crossgramServerBlocked = true;
        }
        buffer->reuse();`);
      return body + `
    bool hasKeys = currentUserId != 0;
    for (auto &item : datacenters) hasKeys = hasKeys || item.second->hasPermanentAuthKey()
            || item.second->hasAuthKey(ConnectionTypeGeneric, 1)
            || item.second->hasAuthKey(ConnectionTypeDownload, 1);
    crossgramServerBlocked = crossgramWssBindingBlocked(customServerId, crossgramKeyIdentity,
            hasKeys, crossgramServerBlocked);
    if (crossgramServerBlocked && LOGS_ENABLED) DEBUG_E("crossgram_wss=account_binding_mismatch");
`;
    });
    s = editDeclarationBody(s, /void\s+ConnectionsManager::saveConfig\s*\(/, "ConnectionsManager.cpp", "preserve blocked key file", body => body.includes("crossgramServerBlocked") ? body : "\n    if (crossgramServerBlocked) return;\n" + body);
    s = editDeclarationBody(s, /void\s+ConnectionsManager::saveConfigInternal\s*\(/, "ConnectionsManager.cpp", "WSS binding save", body => body.includes("crossgram-wss-binding-save") ? body : body + `
    // crossgram-wss-binding-save: append only; official/legacy TCP files unchanged.
    if (!crossgramKeyIdentity.empty()) {
        buffer->writeInt32(0x43575331);
        buffer->writeString(crossgramKeyIdentity);
    }
`);
    s = editDeclarationBody(s, /void\s+ConnectionsManager::setServerConfig\s*\(/, "ConnectionsManager.cpp", "WSS binding reset", body => {
      if (body.includes("crossgram-wss-binding-reset")) return body;
      return body.replace("        currentDatacenterId = 2;", `        // crossgram-wss-binding-reset: only an empty account may switch via Java.
        for (auto &item : datacenters) item.second->suspendConnections(true);
        crossgramKeyIdentity = isWssServer() ? customServerId : "";
        crossgramServerBlocked = customServerId == "wss:invalid";
        currentDatacenterId = 2;`);
    });
    return s;
  });
  await edit("TMessagesProj/jni/tgnet/Connection.cpp", s => {
    s = editDeclarationBody(s, /void\s+Connection::connect\s*\(/, "Connection.cpp", "WSS fail closed", body => {
      if (body.includes("crossgram-wss-route")) return body;
      body = `\n    // crossgram-wss-route: blocked slots never open official or custom sockets.\n    if (ConnectionsManager::getInstance(currentDatacenter->instanceNum).crossgramServerBlocked) return;\n` + body;
      return insert(body, "    openConnection(hostAddress, hostPort, secret,", `    if (ConnectionsManager::getInstance(currentDatacenter->instanceNum).isWssServer()) {
        hostAddress = "wss:" + std::to_string(currentDatacenter->getDatacenterId());
        secret.clear();
    }
`, 'hostAddress = "wss:"', "Connection.cpp");
    });
    s = insert(s, "        if (useSecret != 0) {\n            std::string *currentSecret = getCurrentSecret(useSecret);", `        // WSS carries unmodified obfuscated abridged, never MTProxy secrets.
        if (ConnectionsManager::getInstance(currentDatacenter->instanceNum).isWssServer()) useSecret = 0;
`, "isWssServer()) useSecret = 0", "Connection.cpp");
    return s;
  });
  await edit("TMessagesProj/jni/tgnet/ByteStream.h", s => insert(s, "    bool hasData();", "    uint64_t crossgramQueuedBytes();\n", "crossgramQueuedBytes", "ByteStream.h"));
  await edit("TMessagesProj/jni/tgnet/ByteStream.cpp", s => insert(s, "bool ByteStream::hasData()", `uint64_t ByteStream::crossgramQueuedBytes() {
    if (buffersQueue.size() >= 4096) return 8 * 1024 * 1024;
    uint64_t size = 0;
    for (auto buffer : buffersQueue) if (buffer) size += buffer->remaining();
    return size;
}

`, "ByteStream::crossgramQueuedBytes", "ByteStream.cpp"));
  const open = await readUtf8(path.join(root, "files/native/wss-open.cpp"));
  await edit("TMessagesProj/jni/tgnet/ConnectionSocket.cpp", s => {
    s = editDeclarationBody(s, /void\s+ConnectionSocket::openConnection\s*\(/, "ConnectionSocket.cpp", "WSS socket", body => insert(body,
      "    memset(&socketAddress,", open + "\n", "crossgram-wss-socketpair", "ConnectionSocket.cpp"));
    // Bound the existing native queue as well as the kernel/Java bridge buffers.
    s = editDeclarationBody(s, /void\s+ConnectionSocket::writeBuffer\s*\(uint8_t/, "ConnectionSocket.cpp", "WSS raw output bound", body => body.includes("crossgramQueuedBytes") ? body : `
    if (ConnectionsManager::getInstance(instanceNum).isWssServer() && outgoingByteStream->crossgramQueuedBytes() + size > 8 * 1024 * 1024) {
        closeSocket(1, -1); return;
    }
` + body);
    s = editDeclarationBody(s, /void\s+ConnectionSocket::writeBuffer\s*\(NativeByteBuffer/, "ConnectionSocket.cpp", "WSS output bound", body => body.includes("crossgramQueuedBytes") ? body : `
    if (ConnectionsManager::getInstance(instanceNum).isWssServer() && buffer && outgoingByteStream->crossgramQueuedBytes() + buffer->remaining() > 8 * 1024 * 1024) {
        buffer->reuse(); closeSocket(1, -1); return;
    }
` + body);
    return s;
  });
}
