package com.example.pqc;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

import com.example.common.Base64Url;
import com.example.common.JsonUtil;
import com.example.common.JwtClaims;
import com.example.common.TokenHeader;
import com.example.common.VerificationOptions;


 // PQC JWS-compact-like service using Dilithium2 (FIPS) via BouncyCastle PQC provider
public class PqcJwtService {

    static {
        if (Security.getProvider("BCPQC") == null) {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
    }

    /**
     * Create a DILITHIUM2 token with a JWS-compact-like structure.
     * @param claims 
     * @param priv
     * @return 
     */
    public String createToken(JwtClaims claims, PrivateKey privateKey, String kid) {
        Objects.requireNonNull(privateKey, "privateKey must not be null");
        if (claims == null) {
            claims = new JwtClaims();
        }
        claims.validateStructure();

        TokenHeader header = new TokenHeader("DILITHIUM2", "JWT", kid);
        header.validateForPqc();

        String headerJson = JsonUtil.toJson(header);
        String payloadJson = JsonUtil.toJson(flattenClaims(claims));

        String headerB64 = Base64Url.encode(headerJson.getBytes(StandardCharsets.UTF_8));
        String payloadB64 = Base64Url.encode(payloadJson.getBytes(StandardCharsets.UTF_8));

        String signingInput = headerB64 + "." + payloadB64;
        byte[] sig = signMldsa(signingInput.getBytes(StandardCharsets.US_ASCII), privateKey);

        String sigB64 = Base64Url.encode(sig);
        return signingInput + "." + sigB64;
    }

    /**
     * Verify a DILITHIUM2 token and validate temporal claims with skew and optional issuer.
     * Throws RuntimeException/IllegalStateException on verification failure.
     * @param token 
     * @param publicKey 
     * @param opts 
     */
    public void verifyToken(String token, PublicKey publicKey, VerificationOptions opts) {
        Objects.requireNonNull(token, "token must not be null");
        Objects.requireNonNull(publicKey, "publicKey must not be null");
        if (opts == null) {
            opts = new VerificationOptions();
        }
        opts.validate();

        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            throw new IllegalArgumentException("Token must have 3 parts");
        }
        String headerB64 = parts[0];
        String payloadB64 = parts[1];
        String sigB64 = parts[2];

        String headerJson = new String(Base64Url.decode(headerB64), StandardCharsets.UTF_8);
        TokenHeader header = JsonUtil.fromJson(headerJson, TokenHeader.class);
        header.validateForPqc();

        byte[] signature = Base64Url.decode(sigB64);
        String signingInput = headerB64 + "." + payloadB64;

        if (!verifyMldsa(signingInput.getBytes(StandardCharsets.US_ASCII), signature, publicKey)) {
            throw new IllegalStateException("Invalid Dilithium signature");
        }

        // Parse and validate claims
        String payloadJson = new String(Base64Url.decode(payloadB64), StandardCharsets.UTF_8);
        Map<?, ?> map = JsonUtil.fromJson(payloadJson, Map.class);
        JwtClaims claims = toClaims(map);
        claims.validateStructure();

        long nowSec = Instant.now().getEpochSecond();
        if (!claims.isTimeAcceptable(nowSec, opts.getClockSkewSeconds(), opts.isRequireExpiration())) {
            throw new IllegalStateException("Temporal claim validation failed");
        }
        if (opts.getExpectedIssuer() != null) {
            if (claims.getIss() == null || !opts.getExpectedIssuer().equals(claims.getIss())) {
                throw new IllegalStateException("Issuer mismatch");
            }
        }
        if (opts.isValidateIssuedAt() && claims.getIat() != null) {
            if (nowSec < (claims.getIat() - opts.getClockSkewSeconds())) {
                throw new IllegalStateException("Token 'iat' is in the future beyond allowed clock skew");
            }
        }
    }

    private byte[] signMldsa(byte[] message, PrivateKey priv) {
        try {
            Signature sig = Signature.getInstance("DILITHIUM", "BCPQC");
            sig.initSign(priv, SecureRandom.getInstanceStrong());
            sig.update(message);
            return sig.sign();
        } catch (Exception e) {
            throw new RuntimeException("Dilithium signing failed", e);
        }
    }

    private boolean verifyMldsa(byte[] message, byte[] signature, PublicKey pub) {
        try {
            Signature sig = Signature.getInstance("DILITHIUM", "BCPQC");
            sig.initVerify(pub);
            sig.update(message);
            return sig.verify(signature);
        } catch (Exception e) {
            throw new RuntimeException("Dilithium verification error", e);
        }
    }

    private Map<String, Object> flattenClaims(JwtClaims claims) {
        Map<String, Object> out = new HashMap<>();
        if (claims.getIss() != null) out.put("iss", claims.getIss());
        if (claims.getSub() != null) out.put("sub", claims.getSub());
        if (claims.getIat() != null) out.put("iat", claims.getIat());
        if (claims.getExp() != null) out.put("exp", claims.getExp());
        if (claims.getNbf() != null) out.put("nbf", claims.getNbf());
        if (claims.getCustom() != null) out.putAll(claims.getCustom());
        return out;
    }

    private JwtClaims toClaims(Map<?, ?> map) {
        JwtClaims claims = new JwtClaims();
        if (map == null) {
            return claims;
        }
        Object iss = map.get("iss");
        if (iss instanceof String) claims.setIss((String) iss);
        Object sub = map.get("sub");
        if (sub instanceof String) claims.setSub((String) sub);
        Object iat = map.get("iat");
        if (iat instanceof Number) claims.setIat(((Number) iat).longValue());
        Object exp = map.get("exp");
        if (exp instanceof Number) claims.setExp(((Number) exp).longValue());
        Object nbf = map.get("nbf");
        if (nbf instanceof Number) claims.setNbf(((Number) nbf).longValue());

        // Rebuild custom as all non-standard keys
        Map<String, Object> custom = new HashMap<>();
        for (Map.Entry<?, ?> e : map.entrySet()) {
            Object key = e.getKey();
            if (!(key instanceof String)) continue;
            String k = (String) key;
            if ("iss".equals(k) || "sub".equals(k) || "iat".equals(k) || "exp".equals(k) || "nbf".equals(k)) {
                continue;
            }
            custom.put(k, e.getValue());
        }
        if (!custom.isEmpty()) {
            claims.setCustom(custom);
        }
        return claims;
    }
}