package com.lms.util;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

@Component	
public class JwtUtil {
	
    private final String jwtSecret = "MySuperSecretKeyForJWTGeneration12345!"; 
    private final long jwtExpirationMs = 1000 * 60 * 60; // 1 hour
    
    private Key getSigningKey() {
        return Keys.hmacShaKeyFor(jwtSecret.getBytes());
    }
     
    public String generateToken(Long userId, String username, String role) {
        return Jwts.builder()          
                .setSubject(Long.toString(userId))
                .setIssuer("LMSAdmin")
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + jwtExpirationMs))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .claim("username", username)
                .claim("role", role)
                .compact();
    }
    
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }
    
    public Long getUserIdFromJWT(String token) {
        if (StringUtils.hasText(token) && token.startsWith("Bearer ")) {
            token = token.substring(7);
        }
        Claims claims =
                Jwts.parserBuilder()
                        .setSigningKey(getSigningKey())
                        .build()
                        .parseClaimsJws(token)
                        .getBody();
        return Long.parseLong(claims.getSubject());
    }
    
    public Map<String, Object> getClaimsFromJWT(String token) {
		if (StringUtils.hasText(token) && token.startsWith("Bearer ")) {
			token = token.substring(7);
		}
		Claims claims =
				Jwts.parserBuilder()
						.setSigningKey(getSigningKey())
						.build()
						.parseClaimsJws(token)
						.getBody();
		Map<String, Object> claimsMap = new HashMap<>();
		claimsMap.put("userId", claims.getSubject());
		claimsMap.put("username", claims.get("username"));
		claimsMap.put("role", claims.get("role"));
		return claimsMap;
	}

}
