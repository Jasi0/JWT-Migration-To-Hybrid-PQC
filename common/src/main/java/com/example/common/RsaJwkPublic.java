package com.example.common;

/**
 * Minimal RSA JWK (public) representation for JWKS publishing.
 * Only includes fields necessary for RS256 verification.
 */
public class RsaJwkPublic {
    private String kty = "RSA"; // fixed
    private String n;           // base64url modulus
    private String e;           // base64url exponent
    private String alg = "RS256";
    private String kid;         // optional, recommended

    public RsaJwkPublic() {
    }

    public RsaJwkPublic(String n, String e, String kid) {
        this.n = n;
        this.e = e;
        this.kid = kid;
    }

    public void validate() {
        if (n == null || n.isEmpty()) {
            throw new IllegalArgumentException("n (modulus) must be provided");
        }
        if (e == null || e.isEmpty()) {
            throw new IllegalArgumentException("e (exponent) must be provided");
        }
        if (kty == null || !"RSA".equals(kty)) {
            throw new IllegalArgumentException("kty must be 'RSA'");
        }
        if (alg == null || !"RS256".equals(alg)) {
            throw new IllegalArgumentException("alg must be 'RS256'");
        }
    }

    public String getKty() {
        return kty;
    }

    public void setKty(String kty) {
        this.kty = kty;
    }

    public String getN() {
        return n;
    }

    public void setN(String n) {
        this.n = n;
    }

    public String getE() {
        return e;
    }

    public void setE(String e) {
        this.e = e;
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
}