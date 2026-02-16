package com.example.app;

import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.common.Base64Url;
import com.example.common.HybridDualSignature;
import com.example.common.HybridPolicy;
import com.example.common.JsonUtil;
import com.example.common.JwtClaims;
import com.example.common.TokenHeader;
import com.example.common.VerificationOptions;
import com.example.pqc.PqcJwtService;
import com.example.pqc.PqcKeyManager;
import com.example.rsa.JwtRsaService;
import com.example.rsa.RsaKeyManager;

public class AppMain {

    public static void main(String[] args) {
        System.out.println("=== JWT PQC Hybrid Demo ===");
        try {
            // Common claims
            long now = Instant.now().getEpochSecond();
            JwtClaims claims = new JwtClaims();
            claims.setIss("demo-issuer");
            claims.setSub("alice");
            claims.setIat(now);
            claims.setExp(now + 600); 

            Map<String, Object> custom = new HashMap<>();
            custom.put("role", "admin");
            claims.setCustom(custom);

            VerificationOptions opts = new VerificationOptions();
            opts.setExpectedIssuer("demo-issuer");
            opts.setClockSkewSeconds(60);
            opts.setValidateIssuedAt(true);
            opts.setRequireExpiration(true);

            //RSA (RS256) 
            System.out.println("\n-- RS256 flow --");
            RsaKeyManager rsaKeyManager = new RsaKeyManager();
            KeyPair rsaKeyPair = rsaKeyManager.generate(2048);
            RSAPrivateKey rsaPriv = (RSAPrivateKey) rsaKeyPair.getPrivate();
            RSAPublicKey rsaPub = (RSAPublicKey) rsaKeyPair.getPublic();
            String rsaKid = rsaKeyManager.computeKid(rsaPub);
            JwtRsaService jwtRsaService = new JwtRsaService();
            String rsaToken = jwtRsaService.createRs256Token(claims, rsaPriv, rsaKid);
            System.out.println("RS256 token (compact): " + rsaToken);
            printTokenParts("RS256", rsaToken);
            DecodedJWT rsaVerified = jwtRsaService.verifyRs256Token(rsaToken, rsaPub, opts);
            System.out.println("RS256 verification: OK, subject=" + rsaVerified.getSubject());

            //PQC ML-DSA 
            System.out.println("\n-- PQC Dilithium2 flow --");
            PqcKeyManager pqcKeyManager = new PqcKeyManager();
            KeyPair pqcKeyPair = pqcKeyManager.generate();
            String pqcKid = pqcKeyManager.computeKid(pqcKeyPair.getPublic());
            PqcJwtService pqcJwtService = new PqcJwtService();
            String pqcToken = pqcJwtService.createToken(claims, pqcKeyPair.getPrivate(), pqcKid);
            System.out.println("DILITHIUM2 token (compact): " + pqcToken);
            printTokenParts("DILITHIUM2", pqcToken);
            pqcJwtService.verifyToken(pqcToken, pqcKeyPair.getPublic(), opts);
            System.out.println("DILITHIUM2 verification: OK");


            // Hybrid Dual-Signature (RS256 + DILITHIUM2)
            System.out.println("\n-- Hybrid Dual-Signature (RS256 + DILITHIUM2) --");
            HybridService hybridService = new HybridService();
            HybridDualSignature hds = hybridService.createHybrid(
                    claims,
                    rsaPriv, rsaKid,
                    pqcKeyPair.getPrivate(), pqcKid
            );
            // Print sizes
            String hdsJson = com.example.common.JsonUtil.toJson(hds);
            System.out.println("Hybrid JSON (compact overview):");
            System.out.println(hdsJson);
            byte[] protBytes = com.example.common.Base64Url.decode(hds.getProtectedB64());
            byte[] paylBytes = com.example.common.Base64Url.decode(hds.getPayloadB64());
            System.out.println("Hybrid protected size (bytes)=" + protBytes.length);
            System.out.println("Hybrid payload size (bytes)=" + paylBytes.length);
            for (com.example.common.HybridDualSignature.SignatureEntry e : hds.getSignatures()) {
                byte[] sig = com.example.common.Base64Url.decode(e.getSignatureB64());
                System.out.println("Hybrid signature alg=" + e.getAlg() + " size (bytes)=" + sig.length);
            }
            // Verify
            hybridService.verifyHybrid(hds, rsaPub, pqcKeyPair.getPublic(), opts, HybridPolicy.CLASSIC_ONLY);
            System.out.println("Hybrid verification (CLASSIC_ONLY): OK");
            hybridService.verifyHybrid(hds, rsaPub, pqcKeyPair.getPublic(), opts, HybridPolicy.PQC_ONLY);
            System.out.println("Hybrid verification (PQC_ONLY): OK");
            hybridService.verifyHybrid(hds, rsaPub, pqcKeyPair.getPublic(), opts, HybridPolicy.BOTH_REQUIRED);
            System.out.println("Hybrid verification (BOTH_REQUIRED): OK");

            System.out.println("\n=== Demo complete ===");
        } catch (Exception e) {
            System.err.println("Demo failed: " + e.getMessage());
            e.printStackTrace(System.err);
            System.exit(1);
        }
    }

    private static void printTokenParts(String label, String token) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length != 3) {
                System.out.println(label + " token: invalid compact format");
                return;
            }
            byte[] headerBytes = Base64Url.decode(parts[0]);
            byte[] payloadBytes = Base64Url.decode(parts[1]);
            byte[] sigBytes = Base64Url.decode(parts[2]);

            String headerJson = new String(headerBytes);
            TokenHeader header = JsonUtil.fromJson(headerJson, TokenHeader.class);

            System.out.println(label + " header.alg=" + header.getAlg());
            System.out.println(label + " header size (bytes)=" + headerBytes.length);
            System.out.println(label + " payload size (bytes)=" + payloadBytes.length);
            System.out.println(label + " signature size (bytes)=" + sigBytes.length);
        } catch (Exception e) {
            System.out.println(label + " token parts print failed: " + e.getMessage());
        }
    }
}