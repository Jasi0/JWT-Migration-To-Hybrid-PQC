package com.example.common;

public class VerificationOptions {
    private String expectedIssuer; // nullable
    private int clockSkewSeconds = 60; // default 60
    private boolean requireExpiration = true; // default true
    private boolean validateIssuedAt = true; // default true

    public VerificationOptions() {}

    public VerificationOptions(String expectedIssuer, int clockSkewSeconds, boolean requireExpiration, boolean validateIssuedAt) {
        this.expectedIssuer = expectedIssuer;
        this.clockSkewSeconds = clockSkewSeconds;
        this.requireExpiration = requireExpiration;
        this.validateIssuedAt = validateIssuedAt;
        validate();
    }

    public void validate() {
        if (clockSkewSeconds < 0) {
            throw new IllegalArgumentException("clockSkewSeconds must be >= 0");
        }
    }

    public String getExpectedIssuer() {
        return expectedIssuer;
    }

    public void setExpectedIssuer(String expectedIssuer) {
        this.expectedIssuer = expectedIssuer;
    }

    public int getClockSkewSeconds() {
        return clockSkewSeconds;
    }

    public void setClockSkewSeconds(int clockSkewSeconds) {
        this.clockSkewSeconds = clockSkewSeconds;
    }

    public boolean isRequireExpiration() {
        return requireExpiration;
    }

    public void setRequireExpiration(boolean requireExpiration) {
        this.requireExpiration = requireExpiration;
    }

    public boolean isValidateIssuedAt() {
        return validateIssuedAt;
    }

    public void setValidateIssuedAt(boolean validateIssuedAt) {
        this.validateIssuedAt = validateIssuedAt;
    }
}