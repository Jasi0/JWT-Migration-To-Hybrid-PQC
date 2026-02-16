package com.example.common;

/**
 * Non-standard PQC key descriptor used for publishing Dilithium2 public keys.
 * This intentionally does NOT follow JWKS to avoid misinterpretation by classical validators.
 */
public class PqcKeyDescriptor {
    private String kty = "PQC";          // fixed
    private String crv = "Dilithium2";   // fixed
    private String alg = "DILITHIUM2";   // fixed
    private String pk;                   // base64url-encoded public key bytes
    private String kid;                  // optional, recommended

    public PqcKeyDescriptor() {
    }

    public PqcKeyDescriptor(String pk, String kid) {
        this.pk = pk;
        this.kid = kid;
    }

    public void validate() {
        if (kty == null || !"PQC".equals(kty)) {
            throw new IllegalArgumentException("kty must be 'PQC'");
        }
        if (crv == null || !"Dilithium2".equals(crv)) {
            throw new IllegalArgumentException("crv must be 'Dilithium2'");
        }
        if (alg == null || !"DILITHIUM2".equals(alg)) {
            throw new IllegalArgumentException("alg must be 'DILITHIUM2'");
        }
        if (pk == null || pk.isEmpty()) {
            throw new IllegalArgumentException("pk (public key) must be provided");
        }
    }

    public String getKty() {
        return kty;
    }

    public void setKty(String kty) {
        this.kty = kty;
    }

    public String getCrv() {
        return crv;
    }

    public void setCrv(String crv) {
        this.crv = crv;
    }

    public String getAlg() {
        return alg;
    }

    public void setAlg(String alg) {
        this.alg = alg;
    }

    public String getPk() {
        return pk;
    }

    public void setPk(String pk) {
        this.pk = pk;
    }

    public String getKid() {
        return kid;
    }

    public void setKid(String kid) {
        this.kid = kid;
    }
}