package com.example.app;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import com.example.common.Base64Url;
import com.example.common.HybridDualSignature;
import com.example.common.HybridPolicy;
import com.example.common.JsonUtil;
import com.example.common.JwtClaims;
import com.example.common.TokenHeader;
import com.example.common.VerificationOptions;

public class HybridService {

    /**
     * Create a dual-signed envelope with RS256 and DILITHIUM2 over the same content.
     * @param claims 
     * @param rsaPriv
     * @param rsaKid 
     * @param pqcPriv 
     * @param pqcKid 
     * @return 
     */
    public HybridDualSignature createHybrid(JwtClaims claims,
                                            RSAPrivateKey rsaPriv, String rsaKid,
                                            PrivateKey pqcPriv, String pqcKid) {
        Objects.requireNonNull(rsaPriv, "rsaPriv must not be null");
        Objects.requireNonNull(pqcPriv, "pqcPriv must not be null");
        if (claims == null) {
            claims = new JwtClaims();
        }
        claims.validateStructure();

        // Build protected header 
        TokenHeader protectedHeader = new TokenHeader();
        protectedHeader.setTyp("JWT");
        protectedHeader.setKid(rsaKid != null && !rsaKid.isEmpty() ? rsaKid : pqcKid);

        String protectedJson = JsonUtil.toJson(protectedHeader);
        String protectedB64 = Base64Url.encode(protectedJson.getBytes(StandardCharsets.UTF_8));

        Map<String, Object> payloadMap = flattenClaims(claims);
        String payloadJson = JsonUtil.toJson(payloadMap);
        String payloadB64 = Base64Url.encode(payloadJson.getBytes(StandardCharsets.UTF_8));

        byte[] signingInput = (protectedB64 + "." + payloadB64).getBytes(StandardCharsets.US_ASCII);

        // RS256 signature 
        String rsSigB64 = base64UrlSignSha256withRsa(signingInput, rsaPriv);

        // DILITHIUM2
        String pqcSigB64 = base64UrlSignDilithium(signingInput, pqcPriv);

        List<HybridDualSignature.SignatureEntry> sigs = new ArrayList<>(2);
        sigs.add(new HybridDualSignature.SignatureEntry("RS256", rsaKid, rsSigB64));
        sigs.add(new HybridDualSignature.SignatureEntry("DILITHIUM2", pqcKid, pqcSigB64));

        HybridDualSignature hds = new HybridDualSignature(protectedB64, payloadB64, sigs);
        hds.validate();
        return hds;
    }

    /**
     * Verify a HybridDualSignature according to a verification policy
     * @param hds 
     * @param rsaPub 
     * @param pqcPub 
     * @param opts 
     * @param policy 
     */
    public void verifyHybrid(HybridDualSignature hds,
                             RSAPublicKey rsaPub,
                             PublicKey pqcPub,
                             VerificationOptions opts,
                             HybridPolicy policy) {
        Objects.requireNonNull(hds, "hds must not be null");
        Objects.requireNonNull(rsaPub, "rsaPub must not be null");
        Objects.requireNonNull(pqcPub, "pqcPub must not be null");
        if (opts == null) {
            opts = new VerificationOptions();
        }
        opts.validate();
        if (policy == null) {
            policy = HybridPolicy.BOTH_REQUIRED;
        }

        hds.validate();

        String protectedB64 = hds.getProtectedB64();
        String payloadB64 = hds.getPayloadB64();
        byte[] signingInput = (protectedB64 + "." + payloadB64).getBytes(StandardCharsets.US_ASCII);

        // Decode protected header and validate basic structure
        String headerJson = new String(Base64Url.decode(protectedB64), StandardCharsets.UTF_8);
        TokenHeader header = JsonUtil.fromJson(headerJson, TokenHeader.class);
        if (header.getTyp() != null && !"JWT".equals(header.getTyp())) {
            throw new IllegalArgumentException("protected.typ must be 'JWT' if present");
        }

        // Decode payload and validate claims
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

        // Verify signatures based on policy
        boolean rsOk = false;
        boolean pqcOk = false;
        for (HybridDualSignature.SignatureEntry e : hds.getSignatures()) {
            if ("RS256".equals(e.getAlg())) {
                rsOk = verifySha256withRsa(signingInput, Base64Url.decode(e.getSignatureB64()), rsaPub);
            } else if ("DILITHIUM2".equals(e.getAlg())) {
                pqcOk = verifyDilithium(signingInput, Base64Url.decode(e.getSignatureB64()), pqcPub);
            }
        }

        switch (policy) {
            case CLASSIC_ONLY:
                if (!rsOk) throw new IllegalStateException("RS256 signature invalid");
                break;
            case PQC_ONLY:
                if (!pqcOk) throw new IllegalStateException("DILITHIUM2 signature invalid");
                break;
            case BOTH_REQUIRED:
                if (!rsOk || !pqcOk) throw new IllegalStateException("Hybrid verification failed (both required)");
                break;
            case AT_LEAST_ONE:
                if (!rsOk && !pqcOk) throw new IllegalStateException("Hybrid verification failed (at least one required)");
                break;
            default:
                throw new IllegalArgumentException("Unsupported policy: " + policy);
        }
    }

    // Helpers
    private String base64UrlSignSha256withRsa(byte[] signingInput, RSAPrivateKey priv) {
        try {
            Signature s = Signature.getInstance("SHA256withRSA");
            s.initSign(priv, SecureRandom.getInstanceStrong());
            s.update(signingInput);
            return Base64Url.encode(s.sign());
        } catch (Exception e) {
            throw new RuntimeException("RS256 signing failed", e);
        }
    }

    private boolean verifySha256withRsa(byte[] signingInput, byte[] signature, RSAPublicKey pub) {
        try {
            Signature s = Signature.getInstance("SHA256withRSA");
            s.initVerify(pub);
            s.update(signingInput);
            return s.verify(signature);
        } catch (Exception e) {
            throw new RuntimeException("RS256 verification error", e);
        }
    }

    private String base64UrlSignDilithium(byte[] signingInput, PrivateKey priv) {
        try {
            Signature s = Signature.getInstance("DILITHIUM", "BCPQC");
            s.initSign(priv, SecureRandom.getInstanceStrong());
            s.update(signingInput);
            return Base64Url.encode(s.sign());
        } catch (Exception e) {
            throw new RuntimeException("DILITHIUM sign failed", e);
        }
    }

    private boolean verifyDilithium(byte[] signingInput, byte[] signature, PublicKey pub) {
        try {
            Signature s = Signature.getInstance("DILITHIUM", "BCPQC");
            s.initVerify(pub);
            s.update(signingInput);
            return s.verify(signature);
        } catch (Exception e) {
            throw new RuntimeException("DILITHIUM verification error", e);
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
