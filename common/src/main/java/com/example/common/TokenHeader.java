package com.example.common;

/**
 * Minimal JWS/JWT header representation for this demo.
 * PQC tokens use alg exactly "MLDSA44" (ML-DSA-44).
 * Composite tokens use alg exactly "RS256+MLDSA44".
 */
public class TokenHeader {
    private String alg; // required
    private String typ = "JWT"; // default
    private String kid; // optional

    public TokenHeader() {
    }

    public TokenHeader(String alg, String typ, String kid) {
        this.alg = alg;
        if (typ != null) {
            this.typ = typ;
        }
        this.kid = kid;
    }

    public void validatePqc() {
        if (alg == null || !"MLDSA44".equals(alg)) {
            throw new IllegalArgumentException("For PQC tokens, header.alg must be exactly 'MLDSA44'");
        }
        if (typ != null && !"JWT".equals(typ)) {
            throw new IllegalArgumentException("For PQC tokens, header.typ must be 'JWT' if present");
        }
    }

    public void validateClassic() {
        if (alg == null) {
            throw new IllegalArgumentException("Classic header.alg must be present");
        }
        // RS256 expected for classic path (not enforced here; caller should enforce)
        if (typ != null && !"JWT".equals(typ)) {
            throw new IllegalArgumentException("Classic header.typ must be 'JWT' if present");
        }
    }

    public void validateComposite() {
        if (alg == null || !"RS256+MLDSA44".equals(alg)) {
            throw new IllegalArgumentException("For composite tokens, header.alg must be exactly 'RS256+MLDSA44'");
        }
        if (typ != null && !"JWT".equals(typ)) {
            throw new IllegalArgumentException("For composite tokens, header.typ must be 'JWT' if present");
        }
    }

    public String getAlg() {
        return alg;
    }

    public void setAlg(String alg) {
        this.alg = alg;
    }

    public String getTyp() {
        return typ;
    }

    public void setTyp(String typ) {
        this.typ = typ;
    }

    public String getKid() {
        return kid;
    }

    public void setKid(String kid) {
        this.kid = kid;
    }
}