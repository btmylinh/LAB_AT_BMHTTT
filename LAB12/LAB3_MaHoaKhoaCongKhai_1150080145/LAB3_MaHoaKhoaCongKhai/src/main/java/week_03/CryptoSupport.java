package week_03;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class CryptoSupport {
    private static final SecureRandom RANDOM = new SecureRandom();

    private CryptoSupport() {
    }

    public static byte[] randomBytes(int n) {
        byte[] b = new byte[n];
        RANDOM.nextBytes(b);
        return b;
    }

    public static String b64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    public static byte[] unb64(String text) {
        try {
            return Base64.getDecoder().decode(text.replaceAll("\\s+", ""));
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException("Dữ liệu không phải Base64 hợp lệ.");
        }
    }

    public static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    public static String text(byte[] b) {
        return new String(b, StandardCharsets.UTF_8);
    }

    public static byte[] concat(byte[]... parts) {
        int n = 0;
        for (byte[] p : parts) {
            n += p.length;
        }
        byte[] out = new byte[n];
        int pos = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, pos, p.length);
            pos += p.length;
        }
        return out;
    }

    public static byte[] slice(byte[] data, int from, int to) {
        if (to > data.length || from > to) {
            throw new IllegalArgumentException("Bản mã quá ngắn hoặc bị hỏng.");
        }
        return Arrays.copyOfRange(data, from, to);
    }

    public static byte[] gcmEncrypt(byte[] key, byte[] nonce, byte[] plain) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        return c.doFinal(plain);
    }

    public static byte[] gcmDecrypt(byte[] key, byte[] nonce, byte[] data) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        return c.doFinal(data);
    }

    public static byte[] hkdf(byte[] secret, byte[] salt, byte[] info) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(salt, "HmacSHA256"));
        byte[] prk = mac.doFinal(secret);
        mac.init(new SecretKeySpec(prk, "HmacSHA256"));
        mac.update(info);
        mac.update((byte) 1);
        return Arrays.copyOf(mac.doFinal(), 32);
    }

    public static String toKeyFile(String publicB64, String privateB64) {
        return "PUBLIC=" + publicB64.trim() + "\n" + "PRIVATE=" + privateB64.trim() + "\n";
    }

    public static String[] fromKeyFile(String content) {
        String pub = null;
        String pri = "";
        for (String line : content.split("\\R")) {
            if (line.startsWith("PUBLIC=")) {
                pub = line.substring(7).trim();
            } else if (line.startsWith("PRIVATE=")) {
                pri = line.substring(8).trim();
            }
        }
        if (pub == null) {
            throw new IllegalArgumentException("Tệp khóa phải có dòng PUBLIC=...");
        }
        return new String[]{pub, pri};
    }
}