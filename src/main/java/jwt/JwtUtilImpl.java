package jwt;

import api.JwtUtil;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.WeakKeyException;

import java.security.Key;
import java.util.Collection;
import java.util.Date;
import java.util.Map;

public class JwtUtilImpl implements JwtUtil {

    private int expirationInMs = 5*60*60*1000;
    private String secret = null;
    private Key key;

    public JwtUtilImpl(String secret){
        this.secret = secret;
        initKey();
    }

    public JwtUtilImpl(String secret, int expirationInMs){
        this.secret = secret;
        this.expirationInMs = expirationInMs;
        initKey();
    }

    @Override
    public String generateToken(String subject) {
//        return Jwts.builder()
//                .setSubject(subject)
//                .setIssuedAt(new Date(System.currentTimeMillis()))
//                .setExpiration(new Date(System.currentTimeMillis() + expirationInMs))
       return initializedBuilder(subject)
                .signWith(key)
                .compact();
    }

    @Override
    public boolean validate(String token) {
        try {
            Jws<Claims> jwtClaims = Jwts
                    .parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token);

            String subject  = jwtClaims.getBody().getSubject();
            return subject != null;
        } catch (JwtException e) {
            //don't trust the JWT!
            return false;
        }
    }

    @Override
    public String getSubject(String token) throws UnsupportedJwtException,  MalformedJwtException, ExpiredJwtException {
        Jws<Claims> jwtClaims = Jwts
                .parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token);
        return jwtClaims.getBody().getSubject();
    }

    @Override
    public Jws<Claims> parse(String token) throws JwtException {
        Jws<Claims> jwtClaims = Jwts
                .parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token);
        return jwtClaims;
    }

    @Override
    public void setExpirationInMs(int expirationInMs) {
        this.expirationInMs = expirationInMs;
    }


    @Override
    public String generateToken(String subject, Collection<String> roles) {
        return initializedBuilder(subject)
                .claim("roles", roles)
                .signWith(key)
                .compact();
    }

    @Override
    public String generateToken(String subject, Collection<String> roles, Map<String, Object> otherClaims) {
        return initializedBuilder(subject)
                .claim("roles", roles)
                .addClaims(otherClaims)
                .signWith(key)
                .compact();
    }

    public int getExpirationInMs() {
        return expirationInMs;
    }

    void initKey() {
            key = Keys.hmacShaKeyFor(secret.getBytes());
    }

    private JwtBuilder initializedBuilder(String subject){
        return Jwts.builder()
                .setSubject(subject)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expirationInMs));
    }
}
