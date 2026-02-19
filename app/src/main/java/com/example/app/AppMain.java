package com.example.app;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.common.Base64Url;
import com.example.common.JwtClaims;
import com.example.common.VerificationOptions;
import com.example.hybrid.CompositeJwtService;
import com.example.hybrid.CompositeKey;
import com.example.hybrid.CompositeKeyManager;
import com.example.hybrid.CompositePolicy;
import com.example.pqc.PqcJwtService;
import com.example.pqc.PqcKeyManager;
import com.example.rsa.JwtRsaService;
import com.example.rsa.RsaKeyManager;

import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

public class AppMain {

    public static void main(String[] args) {
        System.out.println("=== JWT PQC Composite Demo (RS256 + MLDSA44) ===");
        try {
            // Common claims
            long now = Instant.now().getEpochSecond();
            JwtClaims claims = new JwtClaims();
            claims.setIss("demo-issuer");
            claims.setSub("alice");
            claims.setIat(now);
            claims.setExp(now + 600); // 10 minutes

            Map<String, Object> custom = new HashMap<>();
            custom.put("role", "admin");
            claims.setCustom(custom);

            VerificationOptions opts = new VerificationOptions();
            opts.setExpectedIssuer("demo-issuer");
            opts.setClockSkewSeconds(60);
            opts.setValidateIssuedAt(true);
            opts.setRequireExpiration(true);

            // RSA (RS256) classical flow
            System.out.println("\n-- RS256 flow --");
            RsaKeyManager rsaKeyManager = new RsaKeyManager();
            KeyPair rsaKeyPair = rsaKeyManager.generate(2048);
            RSAPrivateKey rsaPriv = (RSAPrivateKey) rsaKeyPair.getPrivate();
            RSAPublicKey rsaPub = (RSAPublicKey) rsaKeyPair.getPublic();
            String rsaKid = rsaKeyManager.computeKid(rsaPub);

            JwtRsaService jwtRsaService = new JwtRsaService();
            String rsaToken = jwtRsaService.createRs256Token(claims, rsaPriv, rsaKid);
            printSizesAndCsv("RS256", rsaToken);
            DecodedJWT rsaVerified = jwtRsaService.verifyRs256Token(rsaToken, rsaPub, opts);
            System.out.println("RS256 verification: OK, subject=" + rsaVerified.getSubject());

            // PQC ML-DSA-44 (Dilithium2 params via BCPQC)
            System.out.println("\n-- MLDSA44 flow --");
            PqcKeyManager pqcKeyManager = new PqcKeyManager();
            KeyPair pqcKeyPair = pqcKeyManager.generate();
            String pqcKid = pqcKeyManager.computeKid(pqcKeyPair.getPublic());
            PqcJwtService pqcJwtService = new PqcJwtService();
            String pqcToken = pqcJwtService.createToken(claims, pqcKeyPair.getPrivate(), pqcKid);
            printSizesAndCsv("MLDSA44", pqcToken);
            pqcJwtService.verifyToken(pqcToken, pqcKeyPair.getPublic(), opts);
            System.out.println("MLDSA44 verification: OK");

            // Composite compact JWT (RS256+MLDSA44)
            System.out.println("\n-- Composite compact JWT (RS256+MLDSA44) --");
            CompositeKeyManager compositeKeyManager = new CompositeKeyManager();
            CompositeKey compositeKey = compositeKeyManager.generate(2048);
            CompositeJwtService compositeService = new CompositeJwtService();
            String compositeToken = compositeService.createCompositeToken(claims, compositeKey);
            printSizesAndCsv("RS256+MLDSA44", compositeToken);

            // Verify under different policies
            compositeService.verifyCompositeToken(compositeToken, compositeKey, opts, CompositePolicy.CLASSIC_ONLY);
            System.out.println("Composite verification (CLASSIC_ONLY): OK");
            compositeService.verifyCompositeToken(compositeToken, compositeKey, opts, CompositePolicy.PQC_ONLY);
            System.out.println("Composite verification (PQC_ONLY): OK");
            compositeService.verifyCompositeToken(compositeToken, compositeKey, opts, CompositePolicy.BOTH_REQUIRED);
            System.out.println("Composite verification (BOTH_REQUIRED): OK");

            System.out.println("\nToken size CSV written to target/token_sizes.csv");
            System.out.println("\n=== Demo complete ===");
        } catch (Exception e) {
            System.err.println("Demo failed: " + e.getMessage());
            e.printStackTrace(System.err);
            System.exit(1);
        }
    }

    private static void printSizesAndCsv(String label, String token) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length != 3) {
                System.out.println(label + " token: invalid compact format");
                return;
            }
            byte[] headerBytes = Base64Url.decode(parts[0]);
            byte[] payloadBytes = Base64Url.decode(parts[1]);
            byte[] sigBytes = Base64Url.decode(parts[2]);

            System.out.println(label + " header size (bytes)=" + headerBytes.length);
            System.out.println(label + " payload size (bytes)=" + payloadBytes.length);
            System.out.println(label + " signature size (bytes)=" + sigBytes.length);

            TokenSizeReport.appendRow(label, token);
        } catch (Exception e) {
            System.out.println(label + " token size computation failed: " + e.getMessage());
        }
    }
}