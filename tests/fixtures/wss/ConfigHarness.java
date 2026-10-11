import org.telegram.messenger.server_switch.ServerSwitchConfig;
import org.telegram.messenger.UserConfig;
import org.json.*;
import java.nio.file.*;

public class ConfigHarness {
    static int checks;
    static void check(boolean b) { if (!b) throw new AssertionError("check " + checks); checks++; }
    static ServerSwitchConfig.Server parse(JSONObject json) throws Exception { return ServerSwitchConfig.Server.parseUserInput(json.toString()); }
    static void bad(JSONObject json) throws Exception {
        try { parse(json); throw new AssertionError("accepted " + json); }
        catch (JSONException | IllegalArgumentException expected) { checks++; }
    }
    static JSONObject copy(JSONObject json) throws Exception {return new JSONObject(json.toString());}
    public static void main(String[] args) throws Exception {
        JSONObject json = new JSONObject(new String(Files.readAllBytes(Paths.get(args[0])), "UTF-8"));
        ServerSwitchConfig.Server wss=parse(json);
        check(wss.dcs.size()==5 && wss.transport.equals("websocket"));
        check(wss.nativeIdentity().startsWith("wss:") && wss.nativeIdentity().length()==68);
        JSONObject renamed=copy(json).put("name","different display name");
        check(parse(renamed).nativeIdentity().equals(wss.nativeIdentity()));
        JSONObject changed=copy(json).put("websocket_url","wss://example.com/other?x=1");
        check(!parse(changed).nativeIdentity().equals(wss.nativeIdentity()));
        JSONObject explicit=copy(json).put("dcs",new JSONArray().put(new JSONObject().put("id",2)).put(new JSONObject().put("id",1)));
        ServerSwitchConfig.Server a=parse(explicit);
        explicit.put("dcs",new JSONArray().put(new JSONObject().put("id",1)).put(new JSONObject().put("id",2)));
        check(a.nativeIdentity().equals(parse(explicit).nativeIdentity()));
        bad(copy(json).put("host","1.2.3.4")); bad(copy(json).put("port",443));
        bad(copy(json).put("enable_special_config",true)); bad(copy(json).put("enable_special_config","false"));
        JSONObject missing=copy(json); missing.remove("enable_special_config"); bad(missing);
        bad(copy(json).put("transport","ws")); bad(copy(json).put("websocket_url","wss://1.2.3.4/mtproto"));
        bad(copy(json).put("rsa_key","-----BEGIN RSA PUBLIC KEY-----\nAAAA\n-----END RSA PUBLIC KEY-----"));
        bad(copy(json).put("dcs",new JSONArray()));
        bad(copy(json).put("dcs",new JSONArray().put(new JSONObject().put("id",1))));
        bad(copy(json).put("dcs",new JSONArray().put(new JSONObject().put("id",2)).put(new JSONObject().put("id",2))));
        bad(copy(json).put("dcs",new JSONArray().put(new JSONObject().put("id",2).put("ip","1.2.3.4"))));
        bad(copy(json).put("dcs",new JSONArray().put(new JSONObject().put("id",2.5))));
        JSONObject tcp=new JSONObject().put("name","legacy").put("host","127.0.0.1").put("port",4430).put("rsa_key",wss.rsaKey);
        check(parse(tcp).transport.equals("tcp") && parse(tcp).dcs.size()==5);
        UserConfig.active=true;
        try {ServerSwitchConfig.selectOfficial(0); throw new AssertionError();} catch(IllegalStateException expected){checks++;}
        try {ServerSwitchConfig.select(0,"x"); throw new AssertionError();} catch(IllegalStateException expected){checks++;}
        try {ServerSwitchConfig.addAndSelect(0,json.toString()); throw new AssertionError();} catch(IllegalStateException expected){checks++;}
        UserConfig.active=false;
        JSONObject store=new JSONObject().put("servers",new JSONArray().put(copy(json).put("id","good"))
                .put(copy(json).put("id","bad").put("websocket_url","ws://example.com/x")))
                .put("account_selections",new JSONObject().put("0","good").put("1","bad"));
        Class<?> type=Class.forName("org.telegram.messenger.server_switch.ServerSwitchConfig$Store");
        java.lang.reflect.Method load=type.getDeclaredMethod("fromJson",JSONObject.class); load.setAccessible(true);
        java.lang.reflect.Method apply=ServerSwitchConfig.class.getDeclaredMethod("applyLocked",type,int.class,boolean.class); apply.setAccessible(true);
        Object loaded=load.invoke(null,store);
        java.lang.reflect.Field cache=ServerSwitchConfig.class.getDeclaredField("cachedStore"); cache.setAccessible(true); cache.set(null,loaded);
        check(ServerSwitchConfig.wssUrl(0,2,wss.nativeIdentity()).value.equals(wss.websocketUrl));
        try {ServerSwitchConfig.wssUrl(0,2,"wss:stale"); throw new AssertionError();} catch(IllegalStateException expected){checks++;}
        apply.invoke(null,loaded,0,false); check(org.telegram.tgnet.ConnectionsManager.lastId.equals(wss.nativeIdentity()));
        apply.invoke(null,loaded,1,false); check(org.telegram.tgnet.ConnectionsManager.lastId.equals("wss:invalid"));
        apply.invoke(null,loaded,2,false); check(org.telegram.tgnet.ConnectionsManager.lastId.equals(""));
        store.put("servers",new JSONArray().put(copy(json).put("id","good")).put(copy(json).put("id","good")));
        loaded=load.invoke(null,store); apply.invoke(null,loaded,0,false);
        check(org.telegram.tgnet.ConnectionsManager.lastId.equals("wss:invalid"));
        System.out.println("Configuration/identity/signed-in isolation checks passed: " + checks);
    }
}
