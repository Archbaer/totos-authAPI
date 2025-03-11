package com.authAPI.authAPI.services;


import com.authAPI.authAPI.models.User;
import com.authAPI.authAPI.utility.KeyGenerator;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Date;

@Service
public class JWTService {

    private final KeyPair keyPair = KeyGenerator.generateKeyPair();
    private final long EXPIRATION_MS = 3600000; // 1 hour

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
        System.out.println("All claims in token: "+ claims.toString());
        String role = claims.get("role", String.class);
        System.out.println("Extracted role: "+ role);
        return extractClaims(token).get("role", String.class);
    }

    public Claims extractClaims(String token) {
        return Jwts.parser()
                .setSigningKey(keyPair.getPublic())
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
        return Jwts.parser().setSigningKey(keyPair.getPrivate()).parseClaimsJws(token).getBody().getSubject();
    }
}

