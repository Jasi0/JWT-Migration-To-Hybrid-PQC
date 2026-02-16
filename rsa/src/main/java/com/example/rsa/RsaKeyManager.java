package com.example.rsa;

import com.example.common.Base64Url;
import com.example.common.RsaJwkPublic;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;

/**
 * Key management utilities for RSA keys used with RS256 JWTs.
 */
public class RsaKeyManager {

    public static final int DEFAULT_KEY_SIZE = 3072;

    public KeyPair generate() {
        return generate(DEFAULT_KEY_SIZE);
    }

    public KeyPair generate(int keySize) {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(keySize, SecureRandom.getInstanceStrong());
            return kpg.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate RSA keypair", e);
        }
    }

    /**
     * Compute a simple KID as base64url(SHA-256 of the public modulus).
     */
    public String computeKid(RSAPublicKey pub) {
        try {
            byte[] nBytes = toUnsigned(pub.getModulus());
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(nBytes);
            return Base64Url.encode(digest);
        } catch (Exception e) {
            throw new RuntimeException("Failed to compute RSA kid", e);
        }
    }

    /**
     * Convert an RSA public key into a minimal JWK representation suitable for JWKS.
     */
    public RsaJwkPublic toJwk(RSAPublicKey pub, String kid) {
        byte[] n = toUnsigned(pub.getModulus());
        byte[] e = toUnsigned(pub.getPublicExponent());

        RsaJwkPublic jwk = new RsaJwkPublic(
                Base64Url.encode(n),
                Base64Url.encode(e),
                kid
        );
        jwk.validate();
        return jwk;
    }

    private byte[] toUnsigned(BigInteger bi) {
        byte[] bytes = bi.toByteArray();
        // BigInteger.toByteArray() may produce a leading 0x00 for sign;
        // strip it to get unsigned big-endian representation.
        if (bytes.length > 1 && bytes[0] == 0x00) {
            byte[] trimmed = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, trimmed, 0, trimmed.length);
            return trimmed;
        }
        return bytes;
    }
}