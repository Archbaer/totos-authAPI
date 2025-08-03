package com.authAPI.authAPI.services;

import com.authAPI.authAPI.models.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;

@Service
public class JWTService {

    private final KeyPair keyPair;
    private final long EXPIRATION_MS = 3600000; // 1 hour

    public JWTService(
            @Value("${jwt.private-key-base64}") String privateKeyBase64,
            @Value("${jwt.public-key-base64}") String publicKeyBase64
    ) {
        this.keyPair = loadKeyPair(privateKeyBase64, publicKeyBase64);
    }

    private KeyPair loadKeyPair(String privateKeyBase64, String publicKeyBase64) {
        try {
            byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyBase64);
            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyBase64);

            PKCS8EncodedKeySpec privateSpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(publicKeyBytes);

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = keyFactory.generatePrivate(privateSpec);
            PublicKey publicKey = keyFactory.generatePublic(publicSpec);

            return new KeyPair(publicKey, privateKey);
        } catch (Exception e) {
            throw new RuntimeException("Failed to load key pair from environment variables", e);
        }
    }

    public String generateToken(User user) {
        return Jwts.builder()
                .setSubject(user.getUsername())
                .claim("role", user.getRole())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_MS))
                .signWith(keyPair.getPrivate(), SignatureAlgorithm.RS256)
                .compact();
    }

    public String getRole(String token){
        Claims claims = extractClaims(token);
        return claims.get("role", String.class);
    }

    public Claims extractClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(keyPair.getPublic())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public PublicKey getPublicKey() {
        return keyPair.getPublic();
    }

    public String extractUsername(String token) {
        return extractClaims(token).getSubject();
    }

    public boolean isTokenExpired(String token) {
        return extractClaims(token).getExpiration().before(new Date());
    }

    public boolean validateToken(String token, String username) {
        return (username.equals(extractUsername(token)) && !isTokenExpired(token));
    }

    public String getUsername(String token) {
        return extractClaims(token).getSubject();
    }
}

