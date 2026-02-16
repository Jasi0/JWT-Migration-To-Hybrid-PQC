package com.example.common;

import java.time.Instant;
import java.util.Map;

/**
 * DTO representing a subset of JWT claims used in the demo.
 * All temporal values are seconds since epoch.
 */
public class JwtClaims {
    private String iss; // issuer
    private String sub; // subject
    private Long iat;   // issued-at (epoch seconds)
    private Long exp;   // expiration time (epoch seconds)
    private Long nbf;   // not-before (epoch seconds)
    private Map<String, Object> custom; // arbitrary custom claims

    public JwtClaims() {
    }

    public JwtClaims(String iss, String sub, Long iat, Long exp, Long nbf, Map<String, Object> custom) {
        this.iss = iss;
        this.sub = sub;
        this.iat = iat;
        this.exp = exp;
        this.nbf = nbf;
        this.custom = custom;
    }

    // Basic structural validation independent of current time
    // - Non-negative temporal values, if present
    // - Relationships: exp > iat (if both present), nbf <= exp (if both present)
    public void validateStructure() {
        if (iat != null && iat < 0) {
            throw new IllegalArgumentException("iat must be non-negative");
        }
        if (exp != null && exp < 0) {
            throw new IllegalArgumentException("exp must be non-negative");
        }
        if (nbf != null && nbf < 0) {
            throw new IllegalArgumentException("nbf must be non-negative");
        }
        if (exp != null && iat != null && exp <= iat) {
            throw new IllegalArgumentException("exp must be greater than iat");
        }
        if (nbf != null && exp != null && nbf > exp) {
            throw new IllegalArgumentException("nbf must be less than or equal to exp");
        }
    }

    /**
     * Check time-based acceptance with a clock skew.
     * @param nowSeconds current time in epoch seconds
     * @param clockSkewSeconds non-negative skew allowance
     * @param requireExpiration if true, tokens without exp are rejected
     * @return true if accepted considering iat/nbf/exp and skew; false otherwise
     */
    public boolean isTimeAcceptable(long nowSeconds, int clockSkewSeconds, boolean requireExpiration) {
        if (clockSkewSeconds < 0) {
            throw new IllegalArgumentException("clockSkewSeconds must be >= 0");
        }

        // exp check
        if (exp != null) {
            // Accept if now <= exp + skew
            if (nowSeconds > exp + clockSkewSeconds) {
                return false;
            }
        } else if (requireExpiration) {
            return false;
        }

        // nbf check (not before)
        if (nbf != null) {
            // Accept if now >= nbf - skew
            if (nowSeconds < nbf - clockSkewSeconds) {
                return false;
            }
        }

        // iat plausibility: now >= iat - skew
        if (iat != null) {
            if (nowSeconds < iat - clockSkewSeconds) {
                return false;
            }
        }
        return true;
    }

    // Convenience helper
    public boolean isTimeAcceptable(Instant now, int clockSkewSeconds, boolean requireExpiration) {
        return isTimeAcceptable(now.getEpochSecond(), clockSkewSeconds, requireExpiration);
    }

    // Getters and setters
    public String getIss() {
        return iss;
    }

    public void setIss(String iss) {
        this.iss = iss;
    }

    public String getSub() {
        return sub;
    }

    public void setSub(String sub) {
        this.sub = sub;
    }

    public Long getIat() {
        return iat;
    }

    public void setIat(Long iat) {
        this.iat = iat;
    }

    public Long getExp() {
        return exp;
    }

    public void setExp(Long exp) {
        this.exp = exp;
    }

    public Long getNbf() {
        return nbf;
    }

    public void setNbf(Long nbf) {
        this.nbf = nbf;
    }

    public Map<String, Object> getCustom() {
        return custom;
    }

    public void setCustom(Map<String, Object> custom) {
        this.custom = custom;
    }
}