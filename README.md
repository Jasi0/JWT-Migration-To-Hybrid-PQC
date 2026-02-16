# JWT PQC Hybrid Demo

Hybrid Java/Maven project demonstrating:
- Classical JWT (RS256) using java-jwt
- PQC-secure JWS-compact-like tokens using Dilithium2 via Bouncy Castle PQC FIPS provider
- Hybrid Dual-Signature format carrying both RS256 and DILITHIUM2 signatures over the same content

The PQC path preserves the familiar JWS Compact structure but signs/verifies using Java’s JCA with the Bouncy Castle PQC (FIPS) provider. The JOSE header uses a clear, non-standard alg label “DILITHIUM2”. Claims (exp, nbf, iat) and issuer checks are consistently validated with a configurable clock skew.

---

## Table of Contents

- [Project Structure](#project-structure)
- [Requirements](#requirements)
- [One-time Setup: Install PQC Provider Locally](#one-time-setup-install-pqc-provider-locally)
- [Build](#build)
- [Run the Demo](#run-the-demo)
  - [Expected Output Highlights](#expected-output-highlights)
- [Hybrid Dual-Signature (RS256 + DILITHIUM2)](#hybrid-dual-signature-rs256--dilithium2)
  - [Format](#format)
  - [Policies](#policies)
  - [What the Hybrid Demo Does](#what-the-hybrid-demo-does)
- [Security and Interoperability Notes](#security-and-interoperability-notes)
- [Troubleshooting](#troubleshooting)
- [Extending the Demo](#extending-the-demo)
- [License](#license)

---

## Project Structure

- common  
  Shared DTOs/utilities:
  - `JwtClaims`, `TokenHeader`, `VerificationOptions`
  - `Base64Url`, `JsonUtil`
  - `RsaJwkPublic`, `PqcKeyDescriptor`
  - `HybridDualSignature`, `HybridPolicy` (dual-signature DTO and verification policy)

- rsa  
  Classical JWT using java-jwt:
  - `RsaKeyManager`: RSA key generation, `kid` computation, minimal JWK export
  - `JwtRsaService`: RS256 token creation/verification with issuer/time claim validation

- pqc  
  PQC JWS-compact-like implementation:
  - `PqcKeyManager`: registers BCPQC provider; generates Dilithium2 keys via  
    `KeyPairGenerator("DILITHIUM","BCPQC")` with `DilithiumParameterSpec.dilithium2`
  - `PqcJwtService`: issues/verifies compact tokens with `header.alg="DILITHIUM2"`;  
    signature via `Signature("DILITHIUM","BCPQC")` over ASCII(`base64url(header) + "." + base64url(payload)`)

- app  
  Executable CLI demo:
  - `AppMain`: Shows RS256, DILITHIUM2, and Hybrid Dual‑Signature flows, prints token parts and signature sizes
  - `HybridService`: Creates and verifies the hybrid dual-signature envelope

---

## Requirements

- Java 17 (project targets `--release 17`)
- Maven 3.8+
- Bouncy Castle PQC FIPS provider JAR (provided at project root):  
  `./bcpqc-fips-2.0.0.jar`

---

## One-time Setup: Install PQC Provider Locally

Install the provided JAR into your local Maven repository (so `pqc` can resolve it):

```bash
mvn install:install-file \
  -Dfile=./bcpqc-fips-2.0.0.jar \
  -DgroupId=org.bouncycastle \
  -DartifactId=bcpqc-fips \
  -Dversion=2.0.0 \
  -Dpackaging=jar \
  -DgeneratePom=true
```

The `pqc` module depends on: `org.bouncycastle:bcpqc-fips:2.0.0`.

---

## Build

From the repository root:

```bash
mvn -DskipTests package
```

All modules should build successfully:
- `common`
- `rsa`
- `pqc`
- `app`

---

## Run the Demo

Option A: Install modules to local Maven repo, then run the app module:

```bash
mvn -DskipTests install && mvn -q -f app/pom.xml -DskipTests exec:java
```

Option B: Run via reactor, building dependencies automatically:

```bash
mvn -DskipTests -pl app -am exec:java
```

### Expected Output Highlights

- RS256 flow:
  - Compact token printed (header.payload.signature)
  - Header size ≈ 79 bytes
  - Signature size ≈ 256 bytes
  - Verification OK

- DILITHIUM2 flow:
  - Compact token printed
  - Header size ≈ 84 bytes
  - Signature size typically in kilobytes (e.g., ~2.4 KB for Dilithium2)
  - Verification OK

- Hybrid Dual-Signature flow:
  - JSON-like envelope printed containing:
    - `protected` (Base64URL of header without alg)
    - `payload` (Base64URL of claims)
    - `signatures` array with two entries: RS256 and DILITHIUM2
  - Sizes of protected, payload, and both signatures printed
  - Verification OK for each policy (see next section)

The demo prints `header.alg`, payload size, and signature size for each variant to illustrate differences.

---

## Hybrid Dual-Signature (RS256 + DILITHIUM2)

### Format

A pragmatic JWS-JSON-like envelope carrying two signatures over the same input:

```json
{
  "protected": "<base64url(JSON header without 'alg'>",
  "payload": "<base64url(JSON claims)>",
  "signatures": [
    { "alg": "RS256",      "kid": "<rsa-kid>", "signatureB64": "<base64url(sig_rs)>" },
    { "alg": "DILITHIUM2", "kid": "<pqc-kid>", "signatureB64": "<base64url(sig_pqc)>" }
  ]
}
```

- Signing input for both: ASCII(protected + "." + payload)
- `protected` contains common header (typ=k“JWT”, optional primary kid) without `alg` to ensure identical signing input for both signatures.

### Policies

Hybrid verification is demonstrated with these policies (see `HybridPolicy`):
- `CLASSIC_ONLY`: RS256 must be valid
- `PQC_ONLY`: DILITHIUM2 must be valid
- `BOTH_REQUIRED`: both RS256 and DILITHIUM2 must be valid
- `AT_LEAST_ONE`: at least one of RS256 or DILITHIUM2 must be valid

### What the Hybrid Demo Does

- Reuses your configured claims and options (issuer, iat, exp/nbf with clock skew)
- Builds `protected` and `payload` (JSON → Base64URL) once
- Signs the same input with:
  - RS256 (SHA256withRSA)
  - DILITHIUM2 (`Signature("DILITHIUM","BCPQC")`)
- Verifies signatures according to the selected policy
- Prints signature sizes for both algorithms

---

## Security and Interoperability Notes

- Algorithm binding:
  - Classic path uses standard alg headers handled by java-jwt
  - PQC path uses “DILITHIUM2” (non-standard label) to explicitly bind the algorithm  
    `TokenHeader.validateForPqc()` enforces this label to avoid downgrade
- Time-based claims:
  - `VerificationOptions` provides `clockSkewSeconds`, `requireExpiration`, and optional `validateIssuedAt`
- Provider:
  - PQC relies on the BCPQC (FIPS) provider available from the installed JAR; keep provider/params up to date
- Interoperability:
  - PQC tokens follow JWS Compact structure but require custom signing/verification logic;  
    existing JWT libraries won’t verify the PQC signature without custom support
  - The hybrid envelope is JWS-JSON-like; production adoption can align fully to JWS JSON Serialization semantics if desired

---

## Troubleshooting

- `ClassNotFoundException` or `no such algorithm`:
  - Ensure `bcpqc-fips-2.0.0.jar` was installed with the exact coordinates above
  - Confirm Java 17 is active (`java -version`)
- App module cannot resolve `com.example:*`:
  - Run `mvn -DskipTests install` from the root to publish the modules to your local Maven repo
- Provider not registered:
  - PQC services register BCPQC automatically via static initializers.  
    Ensure your entry point runs those classes (as in `AppMain`), or add:
    ```java
    Security.addProvider(new org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider());
    ```

---


---

## Extending the Demo

- Add HTTP endpoints in `app` (e.g., `/issue`, `/verify`, `/jwks`, `/pqckeys`, `/hybrid/issue`, `/hybrid/verify`)
- Publish RSA public keys (JWKS) and PQC descriptors for external verification
- Support additional PQC parameter sets or algorithm labels when corresponding provider JARs are available

---

## License

Demo project intended for testing and evaluation purposes.