package com.example.hybrid;

import com.example.common.Base64Url;
import com.example.common.JsonUtil;
import com.example.common.JwtClaims;
import com.example.common.TokenHeader;
import com.example.common.VerificationOptions;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Composite JWT service that produces and verifies compact JWTs with a composite signature algorithm "RS256+MLDSA44".
 * The composite signature packs two signatures (RS256 and ML-DSA-44) into one Base64URL-encoded blob.
 */
public class CompositeJwtService {

    private static final byte[] MAGIC = new byte[] { 'C', 'M', 'B', '1' };

    /**
     * Create a compact JWT with alg "RS256+MLDSA44".
     * Header: {"alg":"RS256+MLDSA44","typ":"JWT","kid":"<composite-kid>"}
     * Signature: Base64URL(CMB1 || rs_len||rs_sig || pqc_len||pqc_sig) where lengths are 4-byte big-endian.
     */
    public String createCompositeToken(JwtClaims claims, CompositeKey key) {
        Objects.requireNonNull(key, "key must not be null");
        key.validate();
        if (claims == null) {
            claims = new JwtClaims();
        }
        claims.validateStructure();

        TokenHeader header = new TokenHeader("RS256+MLDSA44", "JWT", key.getKid());
        // Will compile after TokenHeader is updated per implementation plan
        headerValidateComposite(header);

        String headerJson = JsonUtil.toJson(header);
        String payloadJson = JsonUtil.toJson(flattenClaims(claims));

        String headerB64 = Base64Url.encode(headerJson.getBytes(StandardCharsets.UTF_8));
        String payloadB64 = Base64Url.encode(payloadJson.getBytes(StandardCharsets.UTF_8));

        byte[] signingInput = (headerB64 + "." + payloadB64).getBytes(StandardCharsets.US_ASCII);

        byte[] rsSig = signRs256(signingInput, key.getRsaPrivate());
        byte[] pqcSig = signMldsa44(signingInput, key.getPqcPrivate());

        byte[] composite = packCompositeSignature(rsSig, pqcSig);
        String sigB64 = Base64Url.encode(composite);

        return headerB64 + "." + payloadB64 + "." + sigB64;
    }

    /**
     * Verify a composite JWT. Applies claim validation and policy checks for the embedded signatures.
     */
    public void verifyCompositeToken(String token, CompositeKey key, VerificationOptions opts, CompositePolicy policy) {
        Objects.requireNonNull(token, "token must not be null");
        Objects.requireNonNull(key, "key must not be null");
        key.validate();
        if (opts == null) {
            opts = new VerificationOptions();
        }
        opts.validate();
        if (policy == null) {
            policy = CompositePolicy.BOTH_REQUIRED;
        }

        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            throw new IllegalArgumentException("Composite token must have 3 parts");
        }
        String headerB64 = parts[0];
        String payloadB64 = parts[1];
        String sigB64 = parts[2];

        // Header
        String headerJson = new String(Base64Url.decode(headerB64), StandardCharsets.UTF_8);
        TokenHeader header = JsonUtil.fromJson(headerJson, TokenHeader.class);
        headerValidateComposite(header);

        // Signing input
        byte[] signingInput = (headerB64 + "." + payloadB64).getBytes(StandardCharsets.US_ASCII);

        // Unpack composite signature and verify
        byte[] compositeSig = Base64Url.decode(sigB64);
        SigPair pair = unpackCompositeSignature(compositeSig);

        boolean rsOk = verifyRs256(signingInput, pair.rsSig, key.getRsaPublic());
        boolean pqcOk = verifyMldsa44(signingInput, pair.pqcSig, key.getPqcPublic());

        switch (policy) {
            case CLASSIC_ONLY:
                if (!rsOk) throw new IllegalStateException("RS256 signature invalid");
                break;
            case PQC_ONLY:
                if (!pqcOk) throw new IllegalStateException("MLDSA44 signature invalid");
                break;
            case BOTH_REQUIRED:
                if (!rsOk || !pqcOk) throw new IllegalStateException("Composite verification failed (both required)");
                break;
            case AT_LEAST_ONE:
                if (!rsOk && !pqcOk) throw new IllegalStateException("Composite verification failed (at least one required)");
                break;
            default:
                throw new IllegalArgumentException("Unsupported policy: " + policy);
        }

        // Claims validation (algorithm-agnostic)
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

    // Header validation bridge until TokenHeader exposes validateComposite()
    private void headerValidateComposite(TokenHeader header) {
        if (header == null) {
            throw new IllegalArgumentException("Header must not be null");
        }
        if (header.getAlg() == null || !"RS256+MLDSA44".equals(header.getAlg())) {
            throw new IllegalArgumentException("For composite tokens, header.alg must be exactly 'RS256+MLDSA44'");
        }
        if (header.getTyp() != null && !"JWT".equals(header.getTyp())) {
            throw new IllegalArgumentException("For composite tokens, header.typ must be 'JWT' if present");
        }
    }

    // Signature packing: CMB1 || rs_len || rs_sig || pqc_len || pqc_sig
    public byte[] packCompositeSignature(byte[] rsSig, byte[] pqcSig) {
        Objects.requireNonNull(rsSig, "rsSig must not be null");
        Objects.requireNonNull(pqcSig, "pqcSig must not be null");
        int capacity = 4 + 4 + rsSig.length + 4 + pqcSig.length;
        ByteBuffer buf = ByteBuffer.allocate(capacity);
        buf.put(MAGIC);
        buf.putInt(rsSig.length);
        buf.put(rsSig);
        buf.putInt(pqcSig.length);
        buf.put(pqcSig);
        return buf.array();
    }

    public SigPair unpackCompositeSignature(byte[] composite) {
        Objects.requireNonNull(composite, "composite signature must not be null");
        if (composite.length < 12) { // magic(4) + rs_len(4) + pqc_len(4) at minimum without payloads
            throw new IllegalArgumentException("Composite signature too short");
        }
        ByteBuffer buf = ByteBuffer.wrap(composite);
        byte[] magic = new byte[4];
        buf.get(magic);
        for (int i = 0; i < 4; i++) {
            if (magic[i] != MAGIC[i]) {
                throw new IllegalArgumentException("Invalid composite signature magic");
            }
        }
        int rsLen = buf.getInt();
        if (rsLen < 0 || rsLen > buf.remaining()) {
            throw new IllegalArgumentException("Invalid RS256 signature length");
        }
        byte[] rsSig = new byte[rsLen];
        buf.get(rsSig);

        if (buf.remaining() < 4) {
            throw new IllegalArgumentException("Composite signature missing PQC length");
        }
        int pqcLen = buf.getInt();
        if (pqcLen < 0 || pqcLen > buf.remaining()) {
            throw new IllegalArgumentException("Invalid MLDSA44 signature length");
        }
        byte[] pqcSig = new byte[pqcLen];
        buf.get(pqcSig);

        if (buf.hasRemaining()) {
            throw new IllegalArgumentException("Trailing bytes in composite signature");
        }
        return new SigPair(rsSig, pqcSig);
    }

    private byte[] signRs256(byte[] message, RSAPrivateKey priv) {
        try {
            Signature s = Signature.getInstance("SHA256withRSA");
            s.initSign(priv, SecureRandom.getInstanceStrong());
            s.update(message);
            return s.sign();
        } catch (Exception e) {
            throw new RuntimeException("RS256 signing failed", e);
        }
    }

    private boolean verifyRs256(byte[] message, byte[] signature, RSAPublicKey pub) {
        try {
            Signature s = Signature.getInstance("SHA256withRSA");
            s.initVerify(pub);
            s.update(message);
            return s.verify(signature);
        } catch (Exception e) {
            throw new RuntimeException("RS256 verification error", e);
        }
    }

    private byte[] signMldsa44(byte[] message, PrivateKey priv) {
        try {
            Signature s = Signature.getInstance("DILITHIUM", "BCPQC");
            s.initSign(priv, SecureRandom.getInstanceStrong());
            s.update(message);
            return s.sign();
        } catch (Exception e) {
            throw new RuntimeException("MLDSA44 signing failed", e);
        }
    }

    private boolean verifyMldsa44(byte[] message, byte[] signature, PublicKey pub) {
        try {
            Signature s = Signature.getInstance("DILITHIUM", "BCPQC");
            s.initVerify(pub);
            s.update(message);
            return s.verify(signature);
        } catch (Exception e) {
            throw new RuntimeException("MLDSA44 verification error", e);
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

    public static final class SigPair {
        public final byte[] rsSig;
        public final byte[] pqcSig;
        public SigPair(byte[] rsSig, byte[] pqcSig) {
            this.rsSig = rsSig;
            this.pqcSig = pqcSig;
        }
    }
}