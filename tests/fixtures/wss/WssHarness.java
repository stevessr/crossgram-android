import org.telegram.messenger.server_switch.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;

public class WssHarness {
    static int checks;
    static void check(boolean b) { checks++; if (!b) throw new AssertionError("check " + checks); }
    static void badUrl(String url) { try { new WssUrl(url); throw new AssertionError(url); } catch (IllegalArgumentException expected) { checks++; } }
    static byte[] bytes(int... values) { byte[] b = new byte[values.length]; for (int i=0; i<b.length; i++) b[i]=(byte)values[i]; return b; }
    static void invalid(int... values) throws Exception {
        try { new WssWire(new ByteArrayInputStream(bytes(values)), new ByteArrayOutputStream()).receive(new ByteArrayOutputStream()); throw new AssertionError(); }
        catch (IOException expected) { check(!(expected instanceof EOFException)); }
    }
    static void unit() throws Exception {
        WssUrl u = new WssUrl("wss://EXAMPLE.com:8443/mtproto?dc=2%20x");
        check(u.host.equals("example.com") && u.port==8443 && u.resource.equals("/mtproto?dc=2%20x"));
        for (String url : new String[]{"ws://example.com/x","https://example.com/x","wss://127.0.0.1/x","wss://[::1]/x","wss://example.com","wss://user@example.com/x","wss://example.com/x#f","wss://example.com:/x","wss://example.com:0/x","wss://example.com:65536/x","wss://bad_.example/x","wss://-bad.example/x","wss://example.com./x","wss://example.com/a b","wss://example.com/x\r\nX:y","wss://example.com/a\\b","wss://example.com/%xy","wss://example.com/中文"}) badUrl(url);
        ByteArrayOutputStream network = new ByteArrayOutputStream(), sink = new ByteArrayOutputStream();
        byte[] frames = bytes(2,2,1,2, 137,1,9, 128,2,3,4, 130,2,5,6);
        InputStream split = new ByteArrayInputStream(frames) { @Override public synchronized int read(byte[] b, int off, int len) { return super.read(b,off,Math.min(len,1)); } };
        try { new WssWire(split, network).receive(sink); } catch (EOFException expected) { }
        check(Arrays.equals(sink.toByteArray(),bytes(1,2,3,4,5,6)));
        byte[] pong = network.toByteArray(); check(pong.length==7 && pong[0]==(byte)138 && (pong[6]^pong[2])==9);
        invalid(129,0); invalid(128,0); invalid(130,128); invalid(194,0); invalid(9,0); invalid(139,0); invalid(130,126,0,1); invalid(130,127,0,0,0,0,1,0,0,0); invalid(136,1,0);
        network.reset(); byte[] payload = new byte[16000]; new Random(1).nextBytes(payload);
        new WssWire(new ByteArrayInputStream(new byte[0]),network).send(2,payload,payload.length);
        byte[] frame = network.toByteArray(); check(frame.length==16008 && frame[0]==(byte)130 && frame[1]==(byte)254);
        for(int i=0;i<payload.length;i++) check((byte)(frame[i+8]^frame[4+i%4])==payload[i]);
        // Upgrade generated against the actual random request key; no buffered reader may eat frame bytes.
        network.reset(); final ByteArrayOutputStream request = network;
        InputStream upgrade = new InputStream() {
            ByteArrayInputStream reply;
            @Override public int read() throws IOException {
                if(reply==null) {
                    String r = new String(request.toByteArray(),StandardCharsets.US_ASCII);
                    check(r.startsWith("GET /mtproto?dc=2%20x HTTP/1.1\r\nHost: example.com:8443\r\n"));
                    String key = r.split("Sec-WebSocket-Key: ")[1].split("\r\n")[0];
                    try { String accept=Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-1").digest((key+"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").getBytes(StandardCharsets.US_ASCII)));
                        reply=new ByteArrayInputStream(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Accept: "+accept+"\r\nServer-Timing: cfCacheStatus;desc=\\\"DYNAMIC\\\"\r\nServer-Timing: cfEdge;dur=10\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
                    } catch(Exception e) {throw new IOException(e);}
                } return reply.read();
            }
        };
        new WssWire(upgrade,network).handshake(u); check(true);
        // Critical WebSocket fields remain strict even though repeated metadata is accepted.
        network.reset();
        InputStream duplicateAccept = new InputStream() {
            ByteArrayInputStream reply;
            @Override public int read() throws IOException {
                if(reply==null) {
                    String r = new String(request.toByteArray(),StandardCharsets.US_ASCII);
                    String key = r.split("Sec-WebSocket-Key: ")[1].split("\r\n")[0];
                    try { String accept=Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-1").digest((key+"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").getBytes(StandardCharsets.US_ASCII)));
                        String response="HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: "+accept+"\r\nSec-WebSocket-Accept: "+accept+"\r\n\r\n";
                        reply=new ByteArrayInputStream(response.getBytes(StandardCharsets.US_ASCII));
                    } catch(Exception e) {throw new IOException(e);}
                } return reply.read();
            }
        };
        try { new WssWire(duplicateAccept,network).handshake(u); throw new AssertionError("duplicate accept accepted"); }
        catch(IOException expected) { checks++; }
        for(String response : new String[]{"HTTP/1.1 403 Forbidden\r\n\r\n", "HTTP/1.1 101 OK\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: wrong\r\n\r\n"}) {
            try { new WssWire(new ByteArrayInputStream(response.getBytes(StandardCharsets.US_ASCII)), new ByteArrayOutputStream()).handshake(u); throw new AssertionError(); }
            catch(IOException expected) {checks++;}
        }
        System.out.println("WSS URL/upgrade/binary streaming checks passed: " + checks);
    }
    public static void main(String[] args) throws Exception {
        if(args.length==0) { unit(); return; }
        WssUrl url=new WssUrl(args[0]);
        java.net.Socket tcp=new java.net.Socket(); tcp.connect(new java.net.InetSocketAddress("127.0.0.1",url.port),3000);
        try(javax.net.ssl.SSLSocket tls=WssTls.create(tcp,url)) {
            tls.setSoTimeout(3000); tls.startHandshake();
            WssWire wire=new WssWire(tls.getInputStream(),tls.getOutputStream()); wire.handshake(url);
            wire.send(2,bytes(1,2,3,4),4);
            ByteArrayOutputStream received=new ByteArrayOutputStream();
            try {wire.receive(received);} catch(EOFException expected) { }
            check(Arrays.equals(received.toByteArray(),bytes(1,2,3,4)));
            System.out.println("Trusted TLS, hostname, SNI, path/query and split/coalesced binary echo passed");
        }
    }
}
