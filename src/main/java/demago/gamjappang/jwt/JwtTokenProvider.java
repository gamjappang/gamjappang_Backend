package demago.gamjappang.jwt;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class JwtTokenProvider {

    private final byte[] secretBytes;
    private final long accessSeconds;
    private final long refreshSeconds;

    public JwtTokenProvider(
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.access-seconds}") long accessSeconds,
            @Value("${jwt.refresh-seconds}") long refreshSeconds
    ) {
        this.secretBytes = secret.getBytes(StandardCharsets.UTF_8);
        this.accessSeconds = accessSeconds;
        this.refreshSeconds = refreshSeconds;
    }

    public String createAccessToken(String username, String role) {
        Instant now = Instant.now();
        return Jwts.builder()
                .subject(username)
                .claim("role", role)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(accessSeconds)))
                .signWith(Keys.hmacShaKeyFor(secretBytes))
                .compact();
    }

    public String createRefreshToken(String username) {
        Instant now = Instant.now();
        return Jwts.builder()
                .subject(username)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(refreshSeconds)))
                .signWith(Keys.hmacShaKeyFor(secretBytes))
                .compact();
    }

    public String getUsername(String token) {
        return Jwts.parser()
                .verifyWith(Keys.hmacShaKeyFor(secretBytes))
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();
    }

    public boolean validate(String token) {
        try {
            Jwts.parser()
                    .verifyWith(Keys.hmacShaKeyFor(secretBytes))
                    .build()
                    .parseSignedClaims(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
