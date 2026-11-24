package week_03;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public final class ECCSignature {
    private PublicKey publicKey;
    private PrivateKey privateKey;

    public void generateKeys() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair p = gen.generateKeyPair();
        publicKey = p.getPublic();
        privateKey = p.getPrivate();
    }

    public String sign(String message) throws Exception {
        if (privateKey == null) {
            throw new IllegalStateException("Chưa có khóa riêng: bấm Generate Keys hoặc Load Keys.");
        }
        Signature s = Signature.getInstance("SHA256withECDSA");
        s.initSign(privateKey);
        s.update(CryptoSupport.utf8(message));
        return CryptoSupport.b64(s.sign());
    }

    public boolean verify(String message, String signatureB64) throws Exception {
        if (publicKey == null) {
            throw new IllegalStateException("Chưa có khóa công khai.");
        }
        Signature s = Signature.getInstance("SHA256withECDSA");
        s.initVerify(publicKey);
        s.update(CryptoSupport.utf8(message));
        try {
            return s.verify(CryptoSupport.unb64(signatureB64));
        } catch (java.security.SignatureException ex) {
            return false;
        }
    }

    public String getPublicKeyBase64() {
        return CryptoSupport.b64(publicKey.getEncoded());
    }

    public String getPrivateKeyBase64() {
        return CryptoSupport.b64(privateKey.getEncoded());
    }

    public void loadKeys(String publicB64, String privateB64) throws Exception {
        KeyFactory kf = KeyFactory.getInstance("EC");
        publicKey = kf.generatePublic(new X509EncodedKeySpec(CryptoSupport.unb64(publicB64)));
        privateKey = privateB64.isBlank() ? null
                : kf.generatePrivate(new PKCS8EncodedKeySpec(CryptoSupport.unb64(privateB64)));
    }
}