package com.example.hybrid;

/**
 * Verification policy for composite JWTs signed with RS256+MLDSA44.
 */
public enum CompositePolicy {
    CLASSIC_ONLY,     // Require valid RS256 only
    PQC_ONLY,         // Require valid MLDSA44 only
    BOTH_REQUIRED,    // Require both signatures to be valid
    AT_LEAST_ONE      // Accept if at least one signature is valid
}