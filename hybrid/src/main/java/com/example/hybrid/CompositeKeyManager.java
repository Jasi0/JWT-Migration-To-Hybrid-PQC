package com.example.hybrid;

import com.example.common.Base64Url;
import com.example.pqc.PqcKeyManager;
import com.example.rsa.RsaKeyManager;

import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * Manager to generate RSA and ML-DSA-44 key pairs and assemble a CompositeKey with a composite kid.
 */
public class CompositeKeyManager {

    /**
     * Generate a composite key (RSA + ML-DSA-44).
     * @param rsaBits RSA modulus size (e.g., 2048)
     * @return CompositeKey containing both key pairs and a composite kid
     */
    public CompositeKey generate(int rsaBits) {
        // Generate RSA
        RsaKeyManager rsaKeyManager = new RsaKeyManager();
        KeyPair rsaPair = rsaKeyManager.generate(rsaBits);
        RSAPublicKey rsaPub = (RSAPublicKey) rsaPair.getPublic();
        RSAPrivateKey rsaPriv = (RSAPrivateKey) rsaPair.getPrivate();

        // Generate ML-DSA-44 (Dilithium2 via BCPQC)
        PqcKeyManager pqcKeyManager = new PqcKeyManager();
        KeyPair pqcPair = pqcKeyManager.generate();
        PublicKey pqcPub = pqcPair.getPublic();
        PrivateKey pqcPriv = pqcPair.getPrivate();

        // Compute composite kid
        String kid = computeCompositeKid(rsaPub, pqcPub);

        return new CompositeKey(rsaPub, rsaPriv, pqcPub, pqcPriv, kid);
    }

    /**
     * kid = base64url(SHA-256( concat(rsaPublic.getEncoded(), pqcPublic.getEncoded()) ))
     */
    public String computeCompositeKid(PublicKey rsaPublic, PublicKey pqcPublic) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(rsaPublic.getEncoded());
            md.update(pqcPublic.getEncoded());
            byte[] digest = md.digest();
            return Base64Url.encode(digest);
        } catch (Exception e) {
            throw new RuntimeException("Failed to compute composite kid", e);
        }
    }
}