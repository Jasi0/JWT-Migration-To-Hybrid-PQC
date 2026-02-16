package com.example.rsa;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.common.JwtClaims;
import com.example.common.VerificationOptions;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.Objects;

/**
 * RS256 JWT creation and verification using java-jwt, with time-claim checks.
 */
public class JwtRsaService {

    public String createRs256Token(JwtClaims claims, RSAPrivateKey privateKey, String kid) {
        Objects.requireNonNull(privateKey, "privateKey must not be null");
        if (claims == null) {
            claims = new JwtClaims();
        }
        claims.validateStructure();

        Algorithm alg = Algorithm.RSA256(null, privateKey);

        JWTCreator.Builder builder = JWT.create();

        // Optionally set kid in header if provided
        if (kid != null && !kid.isEmpty()) {
            builder.withKeyId(kid);
        }

        if (claims.getSub() != null) {
            builder.withSubject(claims.getSub());
        }
        if (claims.getIss() != null) {
            builder.withIssuer(claims.getIss());
        }
        if (claims.getIat() != null) {
            builder.withIssuedAt(Date.from(Instant.ofEpochSecond(claims.getIat())));
        }
        if (claims.getExp() != null) {
            builder.withExpiresAt(Date.from(Instant.ofEpochSecond(claims.getExp())));
        }
        if (claims.getNbf() != null) {
            builder.withNotBefore(Date.from(Instant.ofEpochSecond(claims.getNbf())));
        }
        Map<String, Object> custom = claims.getCustom();
        if (custom != null) {
            custom.forEach((k, v) -> {
                if (v instanceof String) {
                    builder.withClaim(k, (String) v);
                } else if (v instanceof Integer) {
                    builder.withClaim(k, (Integer) v);
                } else if (v instanceof Long) {
                    builder.withClaim(k, (Long) v);
                } else if (v instanceof Boolean) {
                    builder.withClaim(k, (Boolean) v);
                } else if (v != null) {
                    builder.withClaim(k, v.toString());
                }
            });
        }

        return builder.sign(alg);
    }

    public DecodedJWT verifyRs256Token(String token, RSAPublicKey publicKey, VerificationOptions opts) {
        Objects.requireNonNull(token, "token must not be null");
        Objects.requireNonNull(publicKey, "publicKey must not be null");
        if (opts == null) {
            opts = new VerificationOptions();
        }
        opts.validate();

        Algorithm alg = Algorithm.RSA256(publicKey, null);
        com.auth0.jwt.interfaces.Verification builder = JWT.require(alg);
        if (opts.getExpectedIssuer() != null) {
            builder.withIssuer(opts.getExpectedIssuer());
        }

        JWTVerifier verifier = builder.acceptLeeway(opts.getClockSkewSeconds()).build();
        DecodedJWT jwt = verifier.verify(token);

        if (opts.isRequireExpiration() && jwt.getExpiresAt() == null) {
            throw new IllegalStateException("Token missing 'exp' while requireExpiration=true");
        }

        if (opts.isValidateIssuedAt()) {
            Instant now = Instant.now();
            Date iat = jwt.getIssuedAt();
            if (iat != null) {
                long nowSec = now.getEpochSecond();
                long iatSec = iat.toInstant().getEpochSecond();
                if (nowSec < (iatSec - opts.getClockSkewSeconds())) {
                    throw new IllegalStateException("Token 'iat' is in the future beyond allowed clock skew");
                }
            }
        }

        return jwt;
    }
}