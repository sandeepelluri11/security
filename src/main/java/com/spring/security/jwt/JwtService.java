package com.spring.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    private final static String SECRET_KEY = "JsrcvUns2IrjyLYsOHmhExhik/FPQte3ypzTkQIlzTFNdx70HNuFwGlpOaPYSCNd";

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims,T> claimResolver) {
        final Claims alClaims = extractAllClaims(token);
        return claimResolver.apply(alClaims);
    }

    public Claims extractAllClaims(String token) {
        return Jwts.parserBuilder().setSigningKey(getSigningKey()).build()
                .parseClaimsJws(token).getBody();
    }

    private Key getSigningKey() {
        byte[] key = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(key);
    }

    public String generateToken(
            Map<String,Object> claims,
            UserDetails userDetails
    ) {
        return Jwts.builder().signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .setClaims(claims).setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 24*60*60*100))
                .compact();
    }

    public boolean validateToken(String token, UserDetails userDetails) {
        String username = extractClaim(token, Claims::getSubject);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    private boolean isTokenExpired(String token) {
        return expirationToken(token).before(new Date());
    }

    private Date expirationToken(String token) {
        return extractClaim(token, Claims::getExpiration);
    }
}
