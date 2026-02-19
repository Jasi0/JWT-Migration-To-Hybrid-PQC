package com.example.hybrid;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * Tuple of RSA and ML-DSA-44 key pairs with a composite kid.
 */
public class CompositeKey {
    private RSAPublicKey rsaPublic;
    private RSAPrivateKey rsaPrivate;
    private PublicKey pqcPublic;   // BCPQC Dilithium public key
    private PrivateKey pqcPrivate; // BCPQC Dilithium private key
    private String kid;            // Base64URL(SHA-256(concat(rsaPub.getEncoded(), pqcPub.getEncoded())))

    public CompositeKey() { }

    public CompositeKey(RSAPublicKey rsaPublic,
                        RSAPrivateKey rsaPrivate,
                        PublicKey pqcPublic,
                        PrivateKey pqcPrivate,
                        String kid) {
        this.rsaPublic = rsaPublic;
        this.rsaPrivate = rsaPrivate;
        this.pqcPublic = pqcPublic;
        this.pqcPrivate = pqcPrivate;
        this.kid = kid;
        validate();
    }

    public void validate() {
        if (rsaPublic == null) {
            throw new IllegalArgumentException("rsaPublic must not be null");
        }
        if (rsaPrivate == null) {
            throw new IllegalArgumentException("rsaPrivate must not be null");
        }
        if (pqcPublic == null) {
            throw new IllegalArgumentException("pqcPublic must not be null");
        }
        if (pqcPrivate == null) {
            throw new IllegalArgumentException("pqcPrivate must not be null");
        }
        if (kid == null || kid.isEmpty()) {
            throw new IllegalArgumentException("kid must not be null/empty");
        }
    }

    public RSAPublicKey getRsaPublic() {
        return rsaPublic;
    }

    public void setRsaPublic(RSAPublicKey rsaPublic) {
        this.rsaPublic = rsaPublic;
    }

    public RSAPrivateKey getRsaPrivate() {
        return rsaPrivate;
    }

    public void setRsaPrivate(RSAPrivateKey rsaPrivate) {
        this.rsaPrivate = rsaPrivate;
    }

    public PublicKey getPqcPublic() {
        return pqcPublic;
    }

    public void setPqcPublic(PublicKey pqcPublic) {
        this.pqcPublic = pqcPublic;
    }

    public PrivateKey getPqcPrivate() {
        return pqcPrivate;
    }

    public void setPqcPrivate(PrivateKey pqcPrivate) {
        this.pqcPrivate = pqcPrivate;
    }

    public String getKid() {
        return kid;
    }

    public void setKid(String kid) {
        this.kid = kid;
    }
}