import org.telegram.messenger.server_switch.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.net.ssl.*;
import java.net.*;
import java.io.*;
import java.nio.*;
import java.security.*;
import java.util.*;

/** Pre-auth interoperability only. Never creates an account or sends a chat RPC. */
public class ReqPqHarness {
    static Cipher ctr(byte[] key, byte[] iv) throws Exception {
        Cipher cipher=Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(key,"AES"),new IvParameterSpec(iv)); return cipher;
    }
    static void check(boolean condition) { if(!condition) throw new AssertionError(); }
    public static void main(String[] args) throws Exception {
        WssUrl url=new WssUrl(args[0]);
        // Fixture-only pin: the local test service must never contact a public origin.
        Socket tcp=new Socket(); tcp.connect(new InetSocketAddress("127.0.0.1",url.port),3000);
        try(SSLSocket tls=WssTls.create(tcp,url)) {
            tls.setSoTimeout(5000); tls.startHandshake();
            WssWire wire=new WssWire(tls.getInputStream(),tls.getOutputStream()); wire.handshake(url);
            SecureRandom random=new SecureRandom(); byte[] header=new byte[64]; random.nextBytes(header);
            header[0]=0x42; header[4]=1;
            byte[] reverse=Arrays.copyOfRange(header,8,56);
            for(int i=0;i<24;i++){byte t=reverse[i];reverse[i]=reverse[47-i];reverse[47-i]=t;}
            Cipher send=ctr(Arrays.copyOfRange(header,8,40),Arrays.copyOfRange(header,40,56));
            Cipher receive=ctr(Arrays.copyOfRange(reverse,0,32),Arrays.copyOfRange(reverse,32,48));
            Arrays.fill(header,56,60,(byte)0xef); header[60]=2; header[61]=0;
            byte[] encrypted=send.update(header); System.arraycopy(encrypted,56,header,56,8);
            byte[] nonce=new byte[16]; random.nextBytes(nonce);
            ByteBuffer packet=ByteBuffer.allocate(41).order(ByteOrder.LITTLE_ENDIAN);
            packet.put((byte)10).putLong(0).putLong((System.currentTimeMillis()/1000)<<32).putInt(20).putInt(0x60469778).put(nonce);
            wire.send(2,Arrays.copyOfRange(header,0,17),17);
            wire.send(2,Arrays.copyOfRange(header,17,64),47);
            wire.send(2,send.update(packet.array()),41);
            ByteArrayOutputStream plain=new ByteArrayOutputStream();
            try {wire.receive(new OutputStream(){
                @Override public void write(int b) throws IOException {write(new byte[]{(byte)b},0,1);}
                @Override public void write(byte[] b,int off,int len) throws IOException {
                    byte[] decrypted=receive.update(b,off,len); plain.write(decrypted,0,decrypted.length);
                    byte[] data=plain.toByteArray();
                    if(data.length>0 && (data[0]&255)<127 && data.length>=1+4*(data[0]&255)) throw new EOFException("complete");
                }
            });} catch(EOFException complete){}
            byte[] data=plain.toByteArray(); check(data.length>=81);
            ByteBuffer result=ByteBuffer.wrap(data,1,data.length-1).slice().order(ByteOrder.LITTLE_ENDIAN);
            check(result.getLong(0)==0 && result.getInt(20)==0x05162463);
            check(Arrays.equals(Arrays.copyOfRange(data,25,41),nonce));
            int vector=56+((1+(data[57]&255)+3)&~3);
            check(result.getInt(vector)==0x1cb5c415 && result.getInt(vector+4)>0);
            check(result.getLong(vector+8)==Long.parseUnsignedLong(args[1],16));
            System.out.println("PASS Java WSS -> loopback TLS -> real CrossGram: obfuscated abridged req_pq/resPQ, nonce, RSA fingerprint");
        }
    }
}
