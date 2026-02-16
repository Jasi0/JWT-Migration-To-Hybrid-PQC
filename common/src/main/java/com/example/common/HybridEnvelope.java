package com.example.common;

/**
 * Envelope that carries a pair of tokens:
 * - classicToken: a standard JWT (RS256)
 * - pqcToken: a PQC token (DILITHIUM2) using a JWS-compact-like format
 *
 * It also includes metadata such as algorithm identifiers, kid values, and
 * signature size comparisons for demonstration purposes.
 */
public class HybridEnvelope {

    // Classical token (RS256) and PQC token (DILITHIUM2)
    private String classicToken; // non-null
    private String pqcToken;     // non-null

    private String classicAlg;   // "RS256"
    private String pqcAlg = "DILITHIUM2"; // fixed

    private String classicKid; // optional
    private String pqcKid;     // optional

    private Long issuedAt;  // epoch seconds
    private Long expiresAt; // epoch seconds

    private String issuer;
    private String subject;

    private int classicSignatureSizeBytes;
    private int pqcSignatureSizeBytes;

    public HybridEnvelope() {
    }

    public HybridEnvelope(
            String classicToken,
            String pqcToken,
            String classicAlg,
            String pqcAlg,
            String classicKid,
            String pqcKid,
            Long issuedAt,
            Long expiresAt,
            String issuer,
            String subject,
            int classicSignatureSizeBytes,
            int pqcSignatureSizeBytes
    ) {
        this.classicToken = classicToken;
        this.pqcToken = pqcToken;
        this.classicAlg = classicAlg;
        this.pqcAlg = pqcAlg;
        this.classicKid = classicKid;
        this.pqcKid = pqcKid;
        this.issuedAt = issuedAt;
        this.expiresAt = expiresAt;
        this.issuer = issuer;
        this.subject = subject;
        this.classicSignatureSizeBytes = classicSignatureSizeBytes;
        this.pqcSignatureSizeBytes = pqcSignatureSizeBytes;
        validate();
    }

    public void validate() {
        if (classicToken == null || classicToken.isEmpty()) {
            throw new IllegalArgumentException("classicToken must be non-null/non-empty");
        }
        if (pqcToken == null || pqcToken.isEmpty()) {
            throw new IllegalArgumentException("pqcToken must be non-null/non-empty");
        }
        if (classicAlg == null || !classicAlg.equals("RS256")) {
            throw new IllegalArgumentException("classicAlg must be RS256");
        }
        if (pqcAlg == null || !pqcAlg.equals("DILITHIUM2")) {
            throw new IllegalArgumentException("pqcAlg must be DILITHIUM2");
        }
        if (classicSignatureSizeBytes < 0 || pqcSignatureSizeBytes < 0) {
            throw new IllegalArgumentException("signature size fields must be >= 0");
        }
    }

    public String getClassicToken() {
        return classicToken;
    }

    public void setClassicToken(String classicToken) {
        this.classicToken = classicToken;
    }

    public String getPqcToken() {
        return pqcToken;
    }

    public void setPqcToken(String pqcToken) {
        this.pqcToken = pqcToken;
    }

    public String getClassicAlg() {
        return classicAlg;
    }

    public void setClassicAlg(String classicAlg) {
        this.classicAlg = classicAlg;
    }

    public String getPqcAlg() {
        return pqcAlg;
    }

    public void setPqcAlg(String pqcAlg) {
        this.pqcAlg = pqcAlg;
    }

    public String getClassicKid() {
        return classicKid;
    }

    public void setClassicKid(String classicKid) {
        this.classicKid = classicKid;
    }

    public String getPqcKid() {
        return pqcKid;
    }

    public void setPqcKid(String pqcKid) {
        this.pqcKid = pqcKid;
    }

    public Long getIssuedAt() {
        return issuedAt;
    }

    public void setIssuedAt(Long issuedAt) {
        this.issuedAt = issuedAt;
    }

    public Long getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(Long expiresAt) {
        this.expiresAt = expiresAt;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getSubject() {
        return subject;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    public int getClassicSignatureSizeBytes() {
        return classicSignatureSizeBytes;
    }

    public void setClassicSignatureSizeBytes(int classicSignatureSizeBytes) {
        this.classicSignatureSizeBytes = classicSignatureSizeBytes;
    }

    public int getPqcSignatureSizeBytes() {
        return pqcSignatureSizeBytes;
    }

    public void setPqcSignatureSizeBytes(int pqcSignatureSizeBytes) {
        this.pqcSignatureSizeBytes = pqcSignatureSizeBytes;
    }
}