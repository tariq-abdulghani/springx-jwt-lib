package api;

import io.jsonwebtoken.*;

import java.util.Collection;
import java.util.Map;

public interface JwtUtil {
	
	boolean validate(String token);

	String getSubject(String token) throws UnsupportedJwtException,  MalformedJwtException, ExpiredJwtException;

	String generateToken(String subject);

	Jws<Claims> parse(String token) throws JwtException;

	void setExpirationInMs(int expirationInMs);

	String generateToken(String subject, Collection<String> roles);

	String generateToken(String subject, Collection<String> roles, Map<String, Object> otherClaims);
}
