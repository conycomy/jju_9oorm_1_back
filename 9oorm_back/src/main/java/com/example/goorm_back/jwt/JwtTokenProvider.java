package com.example.goorm_back.jwt;

import io.github.cdimascio.dotenv.Dotenv;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import java.security.Key;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

@Log4j2
@Component
public class JwtTokenProvider {

	private final Dotenv dotenv = Dotenv.load();

	private Key secretKey;
	private final long expirationTime = Long.parseLong(dotenv.get("JWT_EXPIRATION")); // 밀리초 단위


	@PostConstruct
	public void init() {
		String rawKey = dotenv.get("JWT_SECRET_KEY");
		this.secretKey = Keys.hmacShaKeyFor(rawKey.getBytes());
		System.out.println("🔐 secretKey = " + secretKey);
		System.out.println("⏱ expirationTime = " + expirationTime);
	}

	public String generateToken(Long userId, String email, String role) {
		Date now = new Date();
		Date expiryDate = new Date(now.getTime() + expirationTime);

		return Jwts.builder()
			.setSubject(userId.toString())
			.claim("email", email)
			.claim("role", role)
			.setIssuedAt(now)
			.setExpiration(expiryDate)
			.signWith(secretKey, SignatureAlgorithm.HS256)
			.compact();
	}

	public boolean validateToken(String token) {
		try {
			Jwts.parserBuilder()
				.setSigningKey(secretKey)
				.build()
				.parseClaimsJws(token);
			return true;
		} catch (Exception e) {
			log.warn("유효하지 않은 토큰: " + e.getMessage());
			return false;
		}
	}

	public Long getUserIdFromToken(String token) {
		Claims claims = Jwts.parserBuilder()
			.setSigningKey(secretKey)
			.build()
			.parseClaimsJws(token)
			.getBody();
		return Long.parseLong(claims.getSubject());
	}

	public String getRoleFromToken(String token) {
		Claims claims = Jwts.parserBuilder()
			.setSigningKey(secretKey)
			.build()
			.parseClaimsJws(token)
			.getBody();

		return claims.get("role", String.class);
	}

	public Collection<? extends GrantedAuthority> getAuthorities(String role) {
		return List.of(new SimpleGrantedAuthority("ROLE_" + role));
	}

	public String resolveToken(HttpServletRequest request) {
		String bearerToken = request.getHeader("Authorization");
		if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
			return bearerToken.substring(7);
		}
		return null;
	}

}