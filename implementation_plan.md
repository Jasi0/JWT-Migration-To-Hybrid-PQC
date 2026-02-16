# Implementation Plan

[Overview]
Create a Maven multi-module Java 17 project that demonstrates both classical JWT (RS256 via java-jwt) and a pragmatic PQC-safe JWS-compact-like token using Dilithium2 via Bouncy Castle PQC, plus an executable app that issues/verifies both, serves minimal HTTP endpoints (including JWKS-like publishing), and prints verification outcomes and signature size comparisons.

This project migrates from a single-file demo (JwtExample.java) to a structured, runnable, and testable setup. It preserves standard JWT interoperability for RS256 using the java-jwt library while adding a parallel PQC pipeline that emits tokens in the familiar JWS Compact shape but with alg=DILITHIUM2 and custom verification logic using the Bouncy Castle PQC provider (BCPQC). The app module runs a minimal built-in JDK HTTP server exposing classical JWKS and a PQC-keys endpoint (clearly marked non-standard), plus issuance/verification endpoints and a CLI flow that showcases both variants and their sizes.

The envelope approach is used for hybrid demonstration: the app issues a pair of tokens together—one standard JWT (RS256) and one PQC token—and verifies both independently. This enables gradual migration because existing consumers can keep using the classical token while PQC-aware consumers adopt the DILITHIUM2 variant.

[Types]  
Define explicit DTOs and helper types to ensure clear data flow and validation.

- Package com.example.common (in common module)
  - class JwtClaims
    - String iss (issuer, optional but recommended)
    - String sub (subject, optional)
    - Long iat (Issued At, epoch seconds; optional)
    - Long exp (Expiration, epoch seconds; optional)
    - Long nbf (Not Before, epoch seconds; optional)
    - Map<String, Object> custom (optional, may be empty)
    - Validation: exp > iat if both present; nbf <= exp if both present; values non-negative if present
  - class VerificationOptions
    - String expectedIssuer (nullable)
    - int clockSkewSeconds (>= 0; default 60)
    - boolean requireExpiration (default true)
    - boolean validateIssuedAt (default true)
  - class HybridEnvelope
    - String classicToken (non-null)
    - String pqcToken (non-null)
    - String classicAlg (value "RS256")
    - String pqcAlg (fixed "DILITHIUM2")
    - String classicKid (nullable)
    - String pqcKid (nullable)
    - Long issuedAt (epoch seconds)
    - Long expiresAt (epoch seconds)
    - String issuer
    - String subject
    - int classicSignatureSizeBytes
    - int pqcSignatureSizeBytes
  - class TokenHeader
    - String alg (required)
    - String typ (default "JWT")
    - String kid (optional)
    - Validation: alg must be exactly "DILITHIUM2" for PQC tokens; strictly checked to avoid downgrade
  - class RsaJwkPublic
    - String kty = "RSA"
    - String n (base64url modulus)
    - String e (base64url exponent)
    - String alg = "RS256"
    - String kid (optional, recommended)
  - class PqcKeyDescriptor (JWKS-like but non-standard)
    - String kty = "PQC"
    - String crv = "Dilithium2"
    - String alg = "DILITHIUM2"
    - String pk (base64url public key bytes)
    - String kid (optional, recommended)
    - NOTE: non-standard and clearly named to avoid misinterpretation by classical validators

[Files]
Add a new Maven multi-module project with dedicated modules for shared DTOs, RSA/HS (classical), PQC, and an executable app; remove the old root-level single-file demo afterward.

- New top-level files:
  - pom.xml (parent, packaging=pom)
    - Java 17, dependencyManagement for versions, modules: common, rsa, pqc, app
    - Plugins: maven-compiler-plugin, maven-surefire-plugin, exec-maven-plugin (in app)
- New module: common/
  - common/pom.xml
  - common/src/main/java/com/example/common/JwtClaims.java
  - common/src/main/java/com/example/common/VerificationOptions.java
  - common/src/main/java/com/example/common/HybridEnvelope.java
  - common/src/main/java/com/example/common/TokenHeader.java
  - common/src/main/java/com/example/common/RsaJwkPublic.java
  - common/src/main/java/com/example/common/PqcKeyDescriptor.java
  - common/src/main/java/com/example/common/JsonUtil.java (Jackson wrapper for shared use)
- New module: rsa/
  - rsa/pom.xml
  - rsa/src/main/java/com/example/rsa/JwtRsaService.java
  - rsa/src/main/java/com/example/rsa/RsaKeyManager.java
  - rsa/src/test/java/com/example/rsa/JwtRsaServiceTest.java
- New module: pqc/
  - pqc/pom.xml
  - pqc/src/main/java/com/example/pqc/PqcKeyManager.java
  - pqc/src/main/java/com/example/pqc/PqcJwtService.java
  - pqc/src/main/java/com/example/pqc/Base64Url.java (utility for no-padding URL-safe)
  - pqc/src/test/java/com/example/pqc/PqcJwtServiceTest.java
- New module: app/
  - app/pom.xml
  - app/src/main/java/com/example/app/AppMain.java (CLI + server bootstrap)
  - app/src/main/java/com/example/app/HttpServerApp.java (minimal HTTP server)
  - app/src/main/java/com/example/app/handlers/IssueHandler.java (issue both tokens)
  - app/src/main/java/com/example/app/handlers/VerifyHandler.java (verify both)
  - app/src/main/java/com/example/app/handlers/JwksHandler.java (classical RSA JWKS)
  - app/src/main/java/com/example/app/handlers/PqcKeysHandler.java (PQC-keys descriptor)
  - app/src/main/java/com/example/app/Config.java (clock skew, alg selection HS/RS)
  - app/src/test/java/com/example/app/EnvelopeIntegrationTest.java
- Existing file to be moved/removed:
  - JwtExample.java (root)
    - Action: Replace by module-specific services; delete or archive in docs/examples after implementation to avoid confusion.
- Configuration updates:
  - Dependency versions centralized in parent pom
  - BouncyCastle providers added in pqc module runtime; provider registration occurs programmatically at startup

[Functions]
Introduce services for token creation/verification and HTTP handlers; enforce algorithm binding and time-based claim validation with skew.

- common module
  - JsonUtil
    - static String toJson(Object)
    - static <T> T fromJson(String, Class<T>)
- rsa module
  - JwtRsaService
    - String createRs256Token(JwtClaims claims, RSAPrivateKey privateKey, String kid)
    - DecodedJWT verifyRs256Token(String token, RSAPublicKey publicKey, VerificationOptions opts)
  - RsaKeyManager
    - KeyPair generate(int keySize) // default 3072
    - String computeKid(RSAPublicKey pub) // e.g., base64url(SHA-256 of modulus)
    - RsaJwkPublic toJwk(RSAPublicKey pub, String kid)
- pqc module
  - PqcKeyManager
    - KeyPair generate() // DilithiumParameterSpec.dilithium2 via BCPQC
    - String computeKid(PublicKey pub) // base64url(SHA-256 of encoded key)
    - PqcKeyDescriptor describe(PublicKey pub, String kid)
  - PqcJwtService
    - String createToken(JwtClaims claims, PrivateKey priv, String kid)
      - Steps: build header {"alg":"DILITHIUM2","typ":"JWT","kid":kid}, serialize payload (JSON), base64url both (no padding), sign header.payload using Signature.getInstance("DILITHIUM","BCPQC"), output header.payload.signature
    - void verifyToken(String token, PublicKey pub, VerificationOptions opts)
      - Steps: parse sections, decode header JSON, require alg == "DILITHIUM2", verify signature, JSON parse payload, validate temporal claims with opts.clockSkewSeconds, expectedIssuer if provided
  - Base64Url
    - static String encode(byte[] bytes)
    - static byte[] decode(String s)
- app module
  - AppMain
    - main(String[] args): bootstrap provider(s), generate keys, create sample claims, issue classical + PQC tokens, verify both, print sizes; start HTTP server
  - HttpServerApp
    - start(int port, dependencies): registers contexts and handlers
  - IssueHandler
    - handle: creates HybridEnvelope (select RS256 via Config), returns JSON with tokens and sizes
  - VerifyHandler
    - handle: accepts JSON body with tokens; verifies both; returns verification result
  - JwksHandler
    - handle: returns JWKS with current RSA public key (n, e, alg=RS256, kid)
  - PqcKeysHandler
    - handle: returns non-standard PQC key descriptor (kty=PQC, crv=Dilithium2, alg=DILITHIUM2, pk, kid)

[Classes]
Add service classes per module and DTOs as specified; no inheritance beyond JDK types; composition over inheritance.

- New classes: all listed in [Files] with methods in [Functions]
- Modified classes: none (the original JwtExample.java is superseded)
- Removed classes: JwtExample.java (reason: absorbed into rsa services); migration strategy: functionality preserved and extended in rsa module; references updated in app module

[Dependencies]
Add java-jwt for classical JWT; Jackson for JSON; Bouncy Castle providers for PQC; JUnit 5 for tests.

- Parent pom (dependencyManagement with versions)
  - com.auth0: java-jwt: 4.4.0
  - com.fasterxml.jackson.core: jackson-databind: 2.17.1
  - org.bouncycastle: bcprov-jdk18on: 1.78.1
  - org.bouncycastle: bcpkix-jdk18on: 1.78.1
  - org.bouncycastle: bcpqc-jdk18on: 1.78.1
  - org.junit.jupiter: junit-jupiter: 5.10.2
- common module
  - com.fasterxml.jackson.core: jackson-databind
- rsa module
  - com.auth0: java-jwt
  - com.fasterxml.jackson.core: jackson-databind (test/help)
  - com.example: common (module dependency)
- pqc module
  - org.bouncycastle: bcprov-jdk18on
  - org.bouncycastle: bcpkix-jdk18on
  - org.bouncycastle: bcpqc-jdk18on
  - com.fasterxml.jackson.core: jackson-databind
  - com.example: common (module dependency)
- app module
  - module dependencies on common, rsa and pqc
  - No web framework dependency; use com.sun.net.httpserver.HttpServer (JDK)

[Testing]
Adopt JUnit 5; cover creation/verification flows, temporal claim validation with skew, algorithm binding enforcement, and HTTP endpoints.

- rsa tests
  - RS256: happy path create/verify; bad issuer; expired with/without skew; key mismatch negative case
- pqc tests
  - DILITHIUM2: create/verify; tampered signature; alg header mismatch; payload tamper; temporal claim validation with clock skew
- app integration tests
  - Start server on random port; GET /jwks returns expected RSA JWK; GET /pqckeys returns PQC descriptor
  - POST /issue returns HybridEnvelope with both tokens
  - POST /verify (with issued tokens) returns success for both
- Also assert signature size comparisons are printed or present in JSON (pqc signature significantly larger than RS256)

[Implementation Order]
Scaffold Maven project first, then build capabilities per module with tests, finally wire HTTP server and end-to-end demo.

1) Initialize parent pom with modules common, rsa, pqc, app; set Java 17 and managed versions.
2) Implement common module (DTOs + JsonUtil).
3) Implement rsa module (HMAC, RSA services, key manager) + unit tests; green build.
4) Implement pqc module (provider registration, key manager, Base64Url, PQC-JWS create/verify) + unit tests; green build.
5) Implement app module (CLI printout, HTTP server and handlers) + integration tests.
6) Remove/retire root JwtExample.java and add README with run instructions.
7) Final verification: mvn -q -DskipTests=false test; then run app to see tokens and endpoints.