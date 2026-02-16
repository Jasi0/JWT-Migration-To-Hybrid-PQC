package com.example.common;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Hybrid dual-signature structure (JWS-JSON-like) carrying two signatures over the same input:
 * protectedB64 + "." + payloadB64, with one RS256 and one DILITHIUM2 signature entry.
 *
 * - protectedB64: base64url(JSON header without "alg", e.g. {"typ":"JWT","kid":"<primary-kid>"} )
 * - payloadB64:   base64url(JSON claims)
 * - signatures:   list of signature entries (RS256 + DILITHIUM2)
 *
 * This structure is intentionally similar to JWS JSON Serialization's "signatures" array
 * while remaining a pragmatic demonstration format for hybrid migration scenarios.
 */
public class HybridDualSignature {

    private String protectedB64;   // base64url(JSON)
    private String payloadB64;     // base64url(JSON)
    private List<SignatureEntry> signatures = new ArrayList<>();

    public HybridDualSignature() {
    }

    public HybridDualSignature(String protectedB64, String payloadB64, List<SignatureEntry> signatures) {
        this.protectedB64 = protectedB64;
        this.payloadB64 = payloadB64;
        if (signatures != null) {
            this.signatures = signatures;
        }
        validate();
    }

    /**
     * Validate minimal structural requirements:
     * - protectedB64, payloadB64 non-empty
     * - at least two signatures: RS256 and DILITHIUM2 present exactly once
     * - each signature entry has non-empty alg and signatureB64
     * - alg values unique within the list
     */
    public void validate() {
        if (protectedB64 == null || protectedB64.isEmpty()) {
            throw new IllegalArgumentException("protectedB64 must be non-null/non-empty");
        }
        if (payloadB64 == null || payloadB64.isEmpty()) {
            throw new IllegalArgumentException("payloadB64 must be non-null/non-empty");
        }
        if (signatures == null || signatures.isEmpty()) {
            throw new IllegalArgumentException("signatures must contain at least one entry");
        }
        Set<String> seenAlgs = new HashSet<>();
        boolean hasRs256 = false;
        boolean hasDilithium2 = false;

        for (SignatureEntry e : signatures) {
            if (e == null) {
                throw new IllegalArgumentException("signatures must not contain null entries");
            }
            e.validate();
            if (!seenAlgs.add(e.alg)) {
                throw new IllegalArgumentException("duplicate signature alg detected: " + e.alg);
            }
            if ("RS256".equals(e.alg)) hasRs256 = true;
            if ("DILITHIUM2".equals(e.alg)) hasDilithium2 = true;
        }
        if (!hasRs256) {
            throw new IllegalArgumentException("RS256 signature is required");
        }
        if (!hasDilithium2) {
            throw new IllegalArgumentException("DILITHIUM2 signature is required");
        }
    }

    public String getProtectedB64() {
        return protectedB64;
    }

    public void setProtectedB64(String protectedB64) {
        this.protectedB64 = protectedB64;
    }

    public String getPayloadB64() {
        return payloadB64;
    }

    public void setPayloadB64(String payloadB64) {
        this.payloadB64 = payloadB64;
    }

    public List<SignatureEntry> getSignatures() {
        return signatures;
    }

    public void setSignatures(List<SignatureEntry> signatures) {
        this.signatures = signatures;
    }

    /**
     * Single signature record inside the hybrid envelope.
     * alg must be exactly "RS256" or "DILITHIUM2".
     */
    public static class SignatureEntry {
        private String alg;
        private String kid;           // optional
        private String signatureB64;  // required: base64url(signature-bytes)

        public SignatureEntry() {
        }

        public SignatureEntry(String alg, String kid, String signatureB64) {
            this.alg = alg;
            this.kid = kid;
            this.signatureB64 = signatureB64;
            validate();
        }

        public void validate() {
            if (alg == null || alg.isEmpty()) {
                throw new IllegalArgumentException("signature.alg must be non-null/non-empty");
            }
            if (!Objects.equals(alg, "RS256") && !Objects.equals(alg, "DILITHIUM2")) {
                throw new IllegalArgumentException("signature.alg must be RS256 or DILITHIUM2");
            }
            if (signatureB64 == null || signatureB64.isEmpty()) {
                throw new IllegalArgumentException("signatureB64 must be non-null/non-empty");
            }
        }

        public String getAlg() {
            return alg;
        }

        public void setAlg(String alg) {
            this.alg = alg;
        }

        public String getKid() {
            return kid;
        }

        public void setKid(String kid) {
            this.kid = kid;
        }

        public String getSignatureB64() {
            return signatureB64;
        }

        public void setSignatureB64(String signatureB64) {
            this.signatureB64 = signatureB64;
        }
    }
}