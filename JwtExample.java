package jwt;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.Objects;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;


// Demonstrates JWT creation and verification using java-jwt
public class JwtExample {


     // Creates an RS256-signed JWT using an RSA private key
     /** 
      @param subject       
      @param issuer     
      @param issuedAt     
      @param expiresAt    
      @param customClaims  
      @param privateKey    
      @return 
    */ 
    public static String createRs256Token(
            String subject,
            String issuer,
            Instant issuedAt,
            Instant expiresAt,
            Map<String, String> customClaims,
            RSAPrivateKey privateKey
    ) {
        Objects.requireNonNull(privateKey, "privateKey must not be null");
        Algorithm alg = Algorithm.RSA256((RSAPublicKey) null, privateKey);

        JWTCreator.Builder builder = JWT.create();

        if (subject != null) {
            builder.withSubject(subject);
        }
        if (issuer != null) {
            builder.withIssuer(issuer);
        }
        if (issuedAt != null) {
            builder.withIssuedAt(Date.from(issuedAt));
        }
        if (expiresAt != null) {
            builder.withExpiresAt(Date.from(expiresAt));
        }
        if (customClaims != null) {
            customClaims.forEach(builder::withClaim);
        }

        return builder.sign(alg);
    }

    // Verifies an RS256-signed JWT using an RSA public key and optional expected issuer
    /**  
      @param token          
      @param publicKey      
      @param expectedIssuer 
      @return 
     */
    public static DecodedJWT verifyRs256Token(String token, RSAPublicKey publicKey, String expectedIssuer) {
        Objects.requireNonNull(token, "token must not be null");
        Objects.requireNonNull(publicKey, "publicKey must not be null");

        Algorithm alg = Algorithm.RSA256(publicKey, null);
        JWTVerifier verifier = (expectedIssuer != null)
                ? JWT.require(alg).withIssuer(expectedIssuer).build()
                : JWT.require(alg).build();
        return verifier.verify(token);
    }
}
