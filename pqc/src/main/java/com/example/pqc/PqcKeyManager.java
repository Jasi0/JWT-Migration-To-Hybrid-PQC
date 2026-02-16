package com.example.pqc;

import com.example.common.Base64Url;
import com.example.common.PqcKeyDescriptor;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;

/**
 * Key manager for Dilithium2/ML-DSA keys using Bouncy Castle PQC provider (BCPQC).
 */
public class PqcKeyManager {
    static {
        // Ensure the PQC provider is registered once.
        if (Security.getProvider("BCPQC") == null) {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
    }

    /**
     * Generate a Dilithium2 keypair.
     */
    public KeyPair generate() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DILITHIUM", "BCPQC");
            kpg.initialize(DilithiumParameterSpec.dilithium2, SecureRandom.getInstanceStrong());
            return kpg.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate Dilithium2 keypair", e);
        }
    }

    /**
     * Compute kid as base64url(SHA-256(publicKey.getEncoded())).
     */
    public String computeKid(PublicKey pub) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(pub.getEncoded());
            return Base64Url.encode(digest);
        } catch (Exception e) {
            throw new RuntimeException("Failed to compute PQC kid", e);
        }
    }

    /**
     * Describe the public key in a non-standard PQC descriptor for publishing.
     */
    public PqcKeyDescriptor describe(PublicKey pub, String kid) {
        String pk = Base64Url.encode(pub.getEncoded());
        PqcKeyDescriptor desc = new PqcKeyDescriptor(pk, kid);
        desc.validate();
        return desc;
    }
}