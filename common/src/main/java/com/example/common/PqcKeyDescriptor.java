package com.example.common;

/**
 * Non-standard PQC key descriptor used for publishing ML-DSA-44 public keys.
 * This intentionally does NOT follow JWKS to avoid misinterpretation by classical validators.
 * Neutral field names are used (no JWKS "crv" misuse).
 */
public class PqcKeyDescriptor {
    private String kty = "PQC";           // fixed
    private String sig = "ML-DSA-44";     // fixed (NIST naming)
    private String providerAlg = "DILITHIUM"; // fixed (JCA provider algorithm name)
    private String param = "dilithium2";  // fixed (parameter set)
    private String pk;                    // base64url-encoded public key bytes
    private String kid;                   // optional, recommended

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
        if (sig == null || !"ML-DSA-44".equals(sig)) {
            throw new IllegalArgumentException("sig must be 'ML-DSA-44'");
        }
        if (providerAlg == null || !"DILITHIUM".equals(providerAlg)) {
            throw new IllegalArgumentException("providerAlg must be 'DILITHIUM'");
        }
        if (param == null || !"dilithium2".equals(param)) {
            throw new IllegalArgumentException("param must be 'dilithium2'");
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

    public String getSig() {
        return sig;
    }

    public void setSig(String sig) {
        this.sig = sig;
    }

    public String getProviderAlg() {
        return providerAlg;
    }

    public void setProviderAlg(String providerAlg) {
        this.providerAlg = providerAlg;
    }

    public String getParam() {
        return param;
    }

    public void setParam(String param) {
        this.param = param;
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