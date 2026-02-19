# Implementation Plan

[Overview]
Migrate the demo from a custom JWS-JSON dual-signature envelope to a single compact JWT with a composite signature algorithm "RS256+MLDSA44", standardizing PQC naming and adding precise size measurements.

This plan responds directly to the review feedback by removing repository-style documentation from the thesis chapter and aligning the implementation with a practical migration path: a composite algorithm that preserves the external JWT compact structure. The codebase will standardize on ML-DSA-44 (NIST naming) instead of "Dilithium2" in headers and documentation, while continuing to use the Bouncy Castle provider algorithm "DILITHIUM" internally for JCA calls. PQC public keys will be published via a separate, non-standard endpoint using neutral fields (no "crv" misuse). The composite signature packs RS256 and ML-DSA-44 signatures into a single Base64URL blob following a deterministic byte format. The app will output exact header, payload, and signature sizes and write a CSV for thesis use. The verification logic will remain claim-agnostic and isolated from algorithm choice.

[Types]  
Introduce composite algorithm and signature packing, standardize header alg values, and define a neutral PQC key descriptor.

- TokenHeader (common/src/main/java/com/example/common/TokenHeader.java)
  - Fields:
    - alg: String
      - Valid values: "RS256", "MLDSA44", "RS256+MLDSA44"
    - typ: String, default "JWT"
    - kid: String, optional
  - Methods:
    - validateClassic(): requires alg="RS256" and typ=="JWT" if present
    - validatePqc(): requires alg="MLDSA44" and typ=="JWT" if present
    - validateComposite(): requires alg="RS256+MLDSA44" and typ=="JWT" if present

- Composite signature format (binary, then Base64URL in JWT signature)
  - Magic: ASCII "CMB1" (4 bytes)
  - rs_len: 4 bytes unsigned big-endian length of RS256 signature
  - rs_sig: rs_len bytes (RSA PKCS#1 v1.5 signature size equals modulus length, e.g., 256 bytes for 2048-bit)
  - pqc_len: 4 bytes unsigned big-endian length of ML-DSA-44 signature
  - pqc_sig: pqc_len bytes
  - Final signature part (JWT third segment): Base64URL(CMB1 || rs_len || rs_sig || pqc_len || pqc_sig), no padding

- CompositeKey (hybrid/src/main/java/com/example/hybrid/CompositeKey.java)
  - Fields:
    - rsaPublic: RSAPublicKey
    - rsaPrivate: RSAPrivateKey
    - pqcPublic: PublicKey (BCPQC Dilithium public key)
    - pqcPrivate: PrivateKey (BCPQC Dilithium private key)
    - kid: String (Base64URL(SHA-256(concat(rsaPublic.getEncoded(), pqcPublic.getEncoded()))))
  - Methods:
    - validate(): ensures non-null keys and kid

- PqcKeyDescriptor (common/src/main/java/com/example/common/PqcKeyDescriptor.java)
  - Fields (neutral, non-JWKS):
    - kty: fixed "PQC"
    - sig: fixed "ML-DSA-44"
    - providerAlg: fixed "DILITHIUM" (internal JCA algorithm name)
    - param: fixed "dilithium2"
    - pk: Base64URL(publicKey.getEncoded())
    - kid: optional
  - Methods:
    - validate(): enforces fixed fields and pk present

- VerificationOptions (existing)
  - Unchanged fields; verification is algorithm-independent.

[Files]
Create a new hybrid module, remove envelope artifacts, and update PQC naming consistently.

- New files to be created:
  - hybrid/pom.xml
    - Maven module for composite algorithm implementation, depends on common, rsa, pqc.
  - hybrid/src/main/java/com/example/hybrid/CompositeKeyManager.java
    - Generates RSA and ML-DSA-44 key pairs, computes composite kid, constructs CompositeKey.
  - hybrid/src/main/java/com/example/hybrid/CompositeJwtService.java
    - Builds compact JWT with alg="RS256+MLDSA44"; signs both algorithms; packs signatures in CMB1 format; verifies with policy.
  - app/src/main/java/com/example/app/TokenSizeReport.java
    - Utility to compute exact sizes (raw and Base64URL) and write CSV rows.

- Existing files to be modified:
  - pom.xml (parent)
    - Add <module>hybrid</module>.
  - common/src/main/java/com/example/common/TokenHeader.java
    - Add validateComposite(), restrict PQC to "MLDSA44"; remove acceptance of "DILITHIUM2".
  - common/src/main/java/com/example/common/PqcKeyDescriptor.java
    - Replace fields with neutral names: sig, providerAlg, param; remove "crv" field; set fixed values; update validate().
  - pqc/src/main/java/com/example/pqc/PqcJwtService.java
    - Change header alg from "DILITHIUM2" to "MLDSA44"; keep Signature.getInstance("DILITHIUM","BCPQC"); rename method/strings accordingly.
  - app/src/main/java/com/example/app/AppMain.java
    - Replace HybridService usage with CompositeJwtService; stop printing full tokens; produce CSV with exact sizes; standardize printed labels to RS256, MLDSA44, RS256+MLDSA44.
  - rsa/src/main/java/com/example/rsa/JwtRsaService.java
    - No functional change; ensure algorithm binding commentary aligns with composite verification.

- Files to be deleted or moved:
  - app/src/main/java/com/example/app/HybridService.java (delete)
  - common/src/main/java/com/example/common/HybridDualSignature.java (delete)
  - common/src/main/java/com/example/common/HybridEnvelope.java (delete)
  - rsa/src/main/java/com/example/rsa/JwtHmacService.java (delete file or leave as empty only if required by build; recommended delete)

- Configuration file updates:
  - Ensure Bouncy Castle repository remains in parent POM; no new external dependencies.
  - hybrid/pom.xml: declare dependencies on common, rsa, pqc.

[Functions]
Add composite token creation/verification and CSV reporting; update PQC alg naming.

- New functions:
  - CompositeJwtService.createCompositeToken(JwtClaims claims, CompositeKey key): String
    - Purpose: Produce compact JWT header.payload.signature with header.alg="RS256+MLDSA44" and signature packing both algorithms.
  - CompositeJwtService.verifyCompositeToken(String token, CompositeKey key, VerificationOptions opts, CompositePolicy policy): void
    - Purpose: Parse CMB1 signature, verify RS256 and ML-DSA-44 per policy; validate claims and issuer/skew identical to other services.
  - CompositeKeyManager.generate(int rsaBits): CompositeKey
    - Purpose: Generate RSA and ML-DSA-44 key pairs and compute a composite kid.
  - TokenSizeReport.writeCsvRow(String label, int headerRaw, int payloadRaw, int signatureRaw, int headerB64, int payloadB64, int signatureB64): void
    - Purpose: Append to app/target/token_sizes.csv; label is "RS256", "MLDSA44", or "RS256+MLDSA44".

- Modified functions:
  - TokenHeader.validateForPqc() -> validatePqc(): enforce alg=="MLDSA44".
  - PqcJwtService.createToken(...): set header.alg="MLDSA44".
  - AppMain.main(...): use CompositeJwtService; compute and write CSV; do not log full tokens.

- Removed functions:
  - HybridService.createHybrid(...), HybridService.verifyHybrid(...): replaced by CompositeJwtService API.
  - HybridDualSignature.SignatureEntry and envelope accessors: obsolete.

[Classes]
Introduce composite classes, adjust header and PQC descriptor, remove envelope classes.

- New classes:
  - CompositePolicy (hybrid/src/main/java/com/example/hybrid/CompositePolicy.java)
    - Enum values: CLASSIC_ONLY, PQC_ONLY, BOTH_REQUIRED, AT_LEAST_ONE
  - CompositeKey (hybrid/src/main/java/com/example/hybrid/CompositeKey.java)
    - Holds RSA and ML-DSA-44 key pair tuple and composite kid.
  - CompositeKeyManager (hybrid/src/main/java/com/example/hybrid/CompositeKeyManager.java)
    - Generates keys and kid; registers BCPQC provider if needed.
  - CompositeJwtService (hybrid/src/main/java/com/example/hybrid/CompositeJwtService.java)
    - Key methods:
      - packCompositeSignature(byte[] rsSig, byte[] pqcSig): byte[]
      - unpackCompositeSignature(byte[] sig): Pair<byte[], byte[]>
      - signRs256(byte[] input, RSAPrivateKey priv): byte[]
      - signMldsa44(byte[] input, PrivateKey priv): byte[]
      - verifyRs256(byte[] input, byte[] sig, RSAPublicKey pub): boolean
      - verifyMldsa44(byte[] input, byte[] sig, PublicKey pub): boolean

- Modified classes:
  - TokenHeader: add validateComposite(); restrict PQC alg name; javadoc updated to ML-DSA-44.
  - PqcKeyDescriptor: rename fields; validation updated; javadoc notes neutral endpoint and avoidance of JWKS crv misuse.

- Removed classes:
  - HybridService (app)
  - HybridDualSignature (common)
  - HybridEnvelope (common)
  - JwtHmacService (rsa) if not needed

[Dependencies]
No new external dependencies; reuse existing Bouncy Castle PQC provider and Jackson.

- Parent POM:
  - Add hybrid module.
- hybrid/pom.xml:
  - Dependencies:
    - com.example:common
    - com.example:rsa
    - com.example:pqc

[Testing]
Add unit tests for composite creation/verification and ensure claims logic remains algorithm-agnostic; verify exact size outputs and CSV generation.

- New test files:
  - hybrid/src/test/java/com/example/hybrid/CompositeJwtServiceTest.java
    - Tests: create/verify with all policies; invalid signature packing; claims validation edge cases.
  - app/src/test/java/com/example/app/TokenSizeReportTest.java
    - Tests: CSV line formatting; size calculations.
  - pqc/src/test/java/com/example/pqc/PqcJwtServiceTest.java
    - Update tests to alg="MLDSA44".
- Manual demo:
  - AppMain prints exact sizes and writes app/target/token_sizes.csv; do not print full tokens to avoid logging sensitive data.

[Implementation Order]
Implement composite types and services first, then replace app flows, then remove envelope artifacts, then finalize naming and size reporting.

1. Add hybrid module to parent pom.xml.
2. Implement CompositeKey, CompositePolicy, CompositeKeyManager, CompositeJwtService (pack/unpack CMB1, signing/verification).
3. Update TokenHeader (validateComposite, strict PQC alg) and PqcKeyDescriptor (neutral fields) and PqcJwtService (alg="MLDSA44").
4. Modify AppMain to use CompositeJwtService; add TokenSizeReport and CSV output; stop logging full tokens.
5. Remove HybridService, HybridDualSignature, and HybridEnvelope; ensure build passes without these.
6. Add and run unit tests for composite and size reporting.
7. Run the demo; collect exact sizes for RS256, MLDSA44, and RS256+MLDSA44; confirm CSV generation.