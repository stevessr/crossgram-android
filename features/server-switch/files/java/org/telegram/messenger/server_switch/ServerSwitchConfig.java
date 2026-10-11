package org.telegram.messenger.server_switch;

import android.util.AtomicFile;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.telegram.messenger.ApplicationLoader;
import org.telegram.messenger.FileLog;
import org.telegram.messenger.UserConfig;
import org.telegram.tgnet.ConnectionsManager;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

public final class ServerSwitchConfig {
    private static final int FILE_VERSION = 1;
    private static final Object LOCK = new Object();

    private static Store cachedStore;

    private ServerSwitchConfig() {
    }

    public static final class Dc {
        public final int id;
        public final String ip;
        public final int port;
        public final String websocketUrl;

        private Dc(int id, String ip, int port) {
            this.id = id;
            this.ip = ip;
            this.port = port;
            this.websocketUrl = "";
        }

        private Dc(int id, String url) {
            this.id = id; this.ip = "127.0.0.1"; this.port = 443;
            this.websocketUrl = new WssUrl(url).value;
        }

        private static Dc fromJson(JSONObject json) throws JSONException {
            return new Dc(json.getInt("id"), json.getString("ip").trim(), json.getInt("port"));
        }

        private JSONObject toJson() throws JSONException {
            return websocketUrl.isEmpty() ? new JSONObject().put("id", id).put("ip", ip).put("port", port)
                    : new JSONObject().put("id", id).put("websocket_url", websocketUrl);
        }
    }

    public static final class Server {
        public final String id;
        public final String name;
        public final boolean enableSpecialConfig;
        public final String host;
        public final int port;
        public final String rsaKey;
        public final List<Dc> dcs;
        public final String transport, websocketUrl;

        private Server(String id, String name, boolean enableSpecialConfig, String host, int port,
                       String rsaKey, List<Dc> dcs, String transport, String websocketUrl) {
            this.id = id;
            this.name = name;
            this.enableSpecialConfig = enableSpecialConfig;
            this.host = host;
            this.port = port;
            this.rsaKey = rsaKey;
            this.dcs = dcs; this.transport = transport; this.websocketUrl = websocketUrl;
        }

        public static Server parseUserInput(String value) throws JSONException {
            if (value.length() > 1024 * 1024) throw new JSONException("Configuration exceeds 1 MiB");
            JSONObject json = new JSONObject(value);
            json.remove("id"); // Imported configurations cannot alias an existing stored selection.
            return fromJson(json, UUID.randomUUID().toString());
        }

        private static Server fromJson(JSONObject json, String fallbackId) throws JSONException {
            String id = json.optString("id", fallbackId);
            String name = json.getString("name").trim();
            boolean enableSpecialConfig = json.optBoolean("enable_special_config", true);
            String transport = json.optString("transport", "tcp");
            boolean wss = transport.equals("websocket");
            if (!wss && !transport.equals("tcp")) throw new JSONException("Unknown transport");
            String url = "";
            if (wss) {
                if (!Boolean.FALSE.equals(json.opt("enable_special_config")) || enableSpecialConfig || json.has("host") || json.has("port")) throw new JSONException("WSS requires enable_special_config=false and no host/port");
                url = new WssUrl(json.getString("websocket_url")).value;
            } else if (json.has("websocket_url")) throw new JSONException("TCP cannot specify websocket_url");
            String host = wss ? "127.0.0.1" : json.getString("host").trim();
            int port = wss ? 443 : json.getInt("port");
            String rsaKey = json.getString("rsa_key").trim();
            JSONArray dcArray = json.optJSONArray("dcs");
            if (wss && json.has("dcs") && dcArray == null) throw new JSONException("dcs must be an array");
            ArrayList<Dc> dcs = new ArrayList<>();
            Set<Integer> configuredDcIds = new HashSet<>();
            if (dcArray != null) {
                for (int i = 0; i < dcArray.length(); i++) {
                    JSONObject item = dcArray.getJSONObject(i);
                    if (wss && !item.get("id").toString().matches("[1-9][0-9]{0,3}")) throw new JSONException("DC id must be an integer");
                    if (wss && (item.has("ip") || item.has("port"))) throw new JSONException("WSS DC cannot contain IP/port");
                    Dc dc = wss ? new Dc(item.getInt("id"), item.optString("websocket_url", url)) : Dc.fromJson(item);
                    dcs.add(dc);
                    configuredDcIds.add(dc.id);
                }
            }
            for (int dcId = 1; dcId <= 5 && (!wss || dcArray == null); dcId++) {
                if (!configuredDcIds.contains(dcId)) {
                    dcs.add(wss ? new Dc(dcId, url) : new Dc(dcId, host, port));
                }
            }
            if (wss && !dcs.stream().anyMatch(dc -> dc.id == 2)) throw new JSONException("WSS DC map must include DC 2");
            Server server = new Server(id, name, enableSpecialConfig, host, port, rsaKey, dcs, transport, url);
            server.validate();
            return server;
        }

        private void validate() throws JSONException {
            if (id.isEmpty() || name.isEmpty()) {
                throw new JSONException("name must not be empty");
            }
            if (host.isEmpty() || !isValidPort(port)) {
                throw new JSONException("host or port is invalid");
            }
            if (!rsaKey.startsWith("-----BEGIN RSA PUBLIC KEY-----")
                    || !rsaKey.endsWith("-----END RSA PUBLIC KEY-----")) {
                throw new JSONException("rsa_key must be a PEM encoded RSA public key");
            }
            if (transport.equals("websocket")) WssRsa.validate(rsaKey);
            Set<Integer> ids = new HashSet<>();
            for (Dc dc : dcs) {
                if (dc.id <= 0 || (transport.equals("websocket") && dc.id > 1000) || dc.ip.isEmpty() || !isValidPort(dc.port) || !ids.add(dc.id)) {
                    throw new JSONException("dcs contains an invalid or duplicate entry");
                }
            }
        }

        public String nativeIdentity() {
            if (!transport.equals("websocket")) return id;
            try {
                java.io.ByteArrayOutputStream bytes = new java.io.ByteArrayOutputStream();
                java.io.DataOutputStream out = new java.io.DataOutputStream(bytes);
                out.writeUTF(transport); out.writeUTF(rsaKey); out.writeUTF(websocketUrl);
                ArrayList<Dc> sorted = new ArrayList<>(dcs);
                java.util.Collections.sort(sorted, (a, b) -> Integer.compare(a.id, b.id));
                for (Dc dc : sorted) { out.writeInt(dc.id); out.writeUTF(dc.websocketUrl); }
                byte[] hash = java.security.MessageDigest.getInstance("SHA-256").digest(bytes.toByteArray());
                StringBuilder hex = new StringBuilder("wss:");
                for (byte b : hash) hex.append(String.format(java.util.Locale.ROOT, "%02x", b & 255));
                return hex.toString();
            } catch (Exception e) { throw new IllegalArgumentException("Cannot derive server identity"); }
        }

        private JSONObject toJson() throws JSONException {
            JSONArray dcArray = new JSONArray();
            for (Dc dc : dcs) {
                dcArray.put(dc.toJson());
            }
            JSONObject result = new JSONObject()
                    .put("id", id)
                    .put("name", name)
                    .put("enable_special_config", enableSpecialConfig)
                    .put("host", host)
                    .put("port", port)
                    .put("rsa_key", rsaKey)
                    .put("dcs", dcArray);
            if (transport.equals("websocket")) { result.remove("host"); result.remove("port"); result.put("transport", transport).put("websocket_url", websocketUrl); }
            return result;
        }
    }

    private static final class Store {
        final ArrayList<Server> servers = new ArrayList<>();
        final JSONObject accountSelections = new JSONObject();
        boolean invalid;

        static Store fromJson(JSONObject json) throws JSONException {
            Store store = new Store();
            JSONArray array = json.optJSONArray("servers");
            if (array != null) {
                Set<String> seen = new HashSet<>();
                Set<String> duplicates = new HashSet<>();
                for (int i = 0; i < array.length(); i++) {
                    try {
                        JSONObject item = array.getJSONObject(i);
                        Server server = Server.fromJson(item, UUID.randomUUID().toString());
                        if (!seen.add(server.id)) duplicates.add(server.id);
                        else store.servers.add(server);
                    } catch (JSONException | IllegalArgumentException invalid) {
                        // Missing selections fail closed below; unrelated valid slots survive.
                        FileLog.e("crossgram_server_record=invalid");
                    }
                }
                for (int i = store.servers.size()-1; i >= 0; i--) {
                    if (duplicates.contains(store.servers.get(i).id)) store.servers.remove(i);
                }
            }
            JSONObject selections = json.optJSONObject("account_selections");
            if (selections != null) {
                JSONArray names = selections.names();
                if (names != null) {
                    for (int i = 0; i < names.length(); i++) {
                        String name = names.getString(i);
                        store.accountSelections.put(name, selections.getString(name));
                    }
                }
            }
            return store;
        }

        JSONObject toJson() throws JSONException {
            JSONArray array = new JSONArray();
            for (Server server : servers) {
                array.put(server.toJson());
            }
            return new JSONObject()
                    .put("version", FILE_VERSION)
                    .put("servers", array)
                    .put("account_selections", accountSelections);
        }
    }

    public static List<Server> getServers() {
        synchronized (LOCK) {
            return new ArrayList<>(getStore().servers);
        }
    }

    public static String getSelectedServerId(int account) {
        synchronized (LOCK) {
            return getStore().accountSelections.optString(Integer.toString(account), "");
        }
    }

    public static boolean isSpecialConfigEnabled(int account) {
        synchronized (LOCK) {
            Server server = findSelectedServer(getStore(), account);
            return server == null || server.enableSpecialConfig;
        }
    }

    public static void selectOfficial(int account) throws Exception {
        if (UserConfig.getInstance(account).isClientActivated()) throw new IllegalStateException("Use an empty account slot to switch servers");
        synchronized (LOCK) {
            Store store = getStore();
            store.accountSelections.remove(Integer.toString(account));
            save(store);
            applyLocked(store, account, true);
        }
    }

    public static void select(int account, String serverId) throws Exception {
        if (UserConfig.getInstance(account).isClientActivated()) throw new IllegalStateException("Use an empty account slot to switch servers");
        synchronized (LOCK) {
            Store store = getStore();
            if (findServer(store, serverId) == null) {
                throw new IllegalArgumentException("Unknown server configuration");
            }
            store.accountSelections.put(Integer.toString(account), serverId);
            save(store);
            applyLocked(store, account, true);
        }
    }

    public static Server addAndSelect(int account, String json) throws Exception {
        if (UserConfig.getInstance(account).isClientActivated()) throw new IllegalStateException("Use an empty account slot to switch servers");
        Server server = Server.parseUserInput(json);
        synchronized (LOCK) {
            Store store = getStore();
            store.servers.add(server);
            store.accountSelections.put(Integer.toString(account), server.id);
            save(store);
            applyLocked(store, account, true);
        }
        return server;
    }

    public static void applyForInitialization(int account) {
        synchronized (LOCK) {
            applyLocked(getStore(), account, false);
        }
    }

    private static void applyLocked(Store store, int account, boolean resetDatacenters) {
        Server server = findSelectedServer(store, account);
        if (store.invalid || (server == null && !store.accountSelections.optString(Integer.toString(account), "").isEmpty())) {
            ConnectionsManager.native_setServerConfig(account, "wss:invalid", "", false, resetDatacenters);
            return;
        }
        if (server == null) {
            ConnectionsManager.native_setServerConfig(account, "", "", true, resetDatacenters);
            return;
        }
        ConnectionsManager.native_setServerConfig(account, server.nativeIdentity(), server.rsaKey,
                server.enableSpecialConfig, resetDatacenters);
        for (Dc dc : server.dcs) {
            ConnectionsManager.native_applyDatacenterAddress(account, dc.id, dc.ip, dc.port);
        }
    }

    public static WssUrl wssUrl(int account, int dc, String expectedIdentity) {
        synchronized (LOCK) {
            Store store = getStore();
            Server server = findSelectedServer(store, account);
            if (store.invalid || server == null || !server.transport.equals("websocket")) throw new IllegalStateException("WSS configuration unavailable");
            if (!server.nativeIdentity().equals(expectedIdentity)) throw new IllegalStateException("WSS selection changed during connection setup");
            for (Dc entry : server.dcs) if (entry.id == dc) return new WssUrl(entry.websocketUrl);
            throw new IllegalArgumentException("Unmapped WSS DC");
        }
    }

    private static Store getStore() {
        if (cachedStore != null) {
            return cachedStore;
        }
        AtomicFile file = getFile();
        try (FileInputStream stream = file.openRead()) {
            if (stream.getChannel().size() > 1024 * 1024) throw new IllegalArgumentException("Server store too large");
            byte[] bytes = new byte[(int) stream.getChannel().size()];
            int offset = 0;
            while (offset < bytes.length) {
                int read = stream.read(bytes, offset, bytes.length - offset);
                if (read < 0) break;
                offset += read;
            }
            cachedStore = Store.fromJson(new JSONObject(new String(bytes, 0, offset,
                    StandardCharsets.UTF_8)));
        } catch (Exception e) {
            cachedStore = new Store();
            if (file.getBaseFile().exists()) {
                cachedStore.invalid = true;
                FileLog.e("crossgram_server_store=invalid");
            }
        }
        return cachedStore;
    }

    private static void save(Store store) throws Exception {
        AtomicFile file = getFile();
        File parent = file.getBaseFile().getParentFile();
        if (parent != null && !parent.exists() && !parent.mkdirs()) {
            throw new IllegalStateException("Cannot create server-switch storage directory");
        }
        FileOutputStream stream = null;
        try {
            stream = file.startWrite();
            stream.write(store.toJson().toString(2).getBytes(StandardCharsets.UTF_8));
            file.finishWrite(stream);
        } catch (Exception e) {
            if (stream != null) file.failWrite(stream);
            throw e;
        }
    }

    private static AtomicFile getFile() {
        File directory = new File(ApplicationLoader.getFilesDirFixed(), "server-switch");
        return new AtomicFile(new File(directory, "servers.json"));
    }

    private static Server findSelectedServer(Store store, int account) {
        return findServer(store, store.accountSelections.optString(Integer.toString(account), ""));
    }

    private static Server findServer(Store store, String id) {
        if (id == null || id.isEmpty()) return null;
        for (Server server : store.servers) {
            if (id.equals(server.id)) return server;
        }
        return null;
    }

    private static boolean isValidPort(int port) {
        return port > 0 && port <= 65535;
    }
}
