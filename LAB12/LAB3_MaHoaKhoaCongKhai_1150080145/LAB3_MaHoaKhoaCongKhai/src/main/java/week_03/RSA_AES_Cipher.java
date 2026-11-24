package week_03;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

public final class RSA_AES_Cipher {
    private static final String RSA = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final OAEPParameterSpec OAEP = new OAEPParameterSpec(
            "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
    private static final int WRAPPED = 256;

    private PublicKey publicKey;
    private PrivateKey privateKey;

    public void generateKeys() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        KeyPair p = gen.generateKeyPair();
        publicKey = p.getPublic();
        privateKey = p.getPrivate();
    }

    public String encrypt(String plaintext) throws Exception {
        if (publicKey == null) {
            throw new IllegalStateException("Chưa có khóa: bấm Generate Keys hoặc Load Keys.");
        }
        byte[] aesKey = CryptoSupport.randomBytes(32);
        byte[] nonce = CryptoSupport.randomBytes(12);
        byte[] data = CryptoSupport.gcmEncrypt(aesKey, nonce, CryptoSupport.utf8(plaintext));
        Cipher rsa = Cipher.getInstance(RSA);
        rsa.init(Cipher.ENCRYPT_MODE, publicKey, OAEP);
        byte[] wrapped = rsa.doFinal(aesKey);
        return CryptoSupport.b64(CryptoSupport.concat(wrapped, nonce, data));
    }

    public String decrypt(String ciphertext) throws Exception {
        if (privateKey == null) {
            throw new IllegalStateException("Chưa có khóa riêng.");
        }
        byte[] all = CryptoSupport.unb64(ciphertext);
        byte[] wrapped = CryptoSupport.slice(all, 0, WRAPPED);
        byte[] nonce = CryptoSupport.slice(all, WRAPPED, WRAPPED + 12);
        byte[] data = CryptoSupport.slice(all, WRAPPED + 12, all.length);
        Cipher rsa = Cipher.getInstance(RSA);
        rsa.init(Cipher.DECRYPT_MODE, privateKey, OAEP);
        byte[] aesKey = rsa.doFinal(wrapped);
        return CryptoSupport.text(CryptoSupport.gcmDecrypt(aesKey, nonce, data));
    }

    public String getPublicKeyBase64() {
        return CryptoSupport.b64(publicKey.getEncoded());
    }

    public String getPrivateKeyBase64() {
        return CryptoSupport.b64(privateKey.getEncoded());
    }

    public void loadKeys(String publicB64, String privateB64) throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        publicKey = kf.generatePublic(new X509EncodedKeySpec(CryptoSupport.unb64(publicB64)));
        privateKey = privateB64.isBlank() ? null
                : kf.generatePrivate(new PKCS8EncodedKeySpec(CryptoSupport.unb64(privateB64)));
    }
}