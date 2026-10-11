package org.telegram.messenger.server_switch;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.spec.RSAPublicKeySpec;
import android.util.Base64;

final class WssRsa {
    static void validate(String pem) {
        try {
            String body = pem.replace("-----BEGIN RSA PUBLIC KEY-----", "").replace("-----END RSA PUBLIC KEY-----", "").replaceAll("\\s", "");
            if (!body.matches("[A-Za-z0-9+/]+={0,2}")) throw new IllegalArgumentException();
            Der outer = new Der(Base64.decode(body, Base64.DEFAULT));
            Der sequence = new Der(outer.value(0x30));
            if (outer.pos != outer.data.length) throw new IllegalArgumentException();
            BigInteger n = new BigInteger(sequence.value(2)), e = new BigInteger(sequence.value(2));
            if (sequence.pos != sequence.data.length || n.signum() <= 0 || n.bitLength() != 2048
                    || e.compareTo(BigInteger.valueOf(3)) < 0 || !e.testBit(0)) throw new IllegalArgumentException();
            KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(n, e));
        } catch (Exception ex) { throw new IllegalArgumentException("WSS rsa_key must be a valid 2048-bit PKCS#1 RSA public key"); }
    }
    private static final class Der {
        final byte[] data; int pos;
        Der(byte[] data) { this.data = data; }
        byte[] value(int tag) {
            if ((data[pos++] & 255) != tag) throw new IllegalArgumentException();
            int len = data[pos++] & 255;
            if (len >= 128) {
                int count = len & 127;
                if (count == 0 || count > 3) throw new IllegalArgumentException();
                len = 0; for (int i = 0; i < count; i++) len = len << 8 | data[pos++] & 255;
            }
            if (len < 1 || len > data.length-pos) throw new IllegalArgumentException();
            byte[] value = java.util.Arrays.copyOfRange(data, pos, pos+len); pos += len;
            return value;
        }
    }
}
