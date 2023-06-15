package com.security.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

@Component
public class JwtTokenProvider {

    private final Logger logger = LoggerFactory.getLogger(JwtTokenProvider.class);

    private final long jwtTokenValidateMillisecondRemember;
    private final long jwtTokenValidateMilliseconds;

    private final Key key;
    private final JwtParser jwtParser;

    public JwtTokenProvider() {
        byte[] keyByte;
        String secret = "amF2YWhvbGlj";
        keyByte = Decoders.BASE64.decode(secret);
        key = Keys.hmacShaKeyFor(keyByte);
        jwtParser = Jwts.parserBuilder().setSigningKey(key).build();
        this.jwtTokenValidateMillisecondRemember = 1000 * 86_400;
        this.jwtTokenValidateMilliseconds = 1000 * 3_600;
    }

    public String createJwtToken(Authentication authentication, boolean rememberMe) {
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority).collect(Collectors.joining(","));
        long now = (new Date()).getTime();
        Date validate;
        if (rememberMe)
            validate = new Date(now + jwtTokenValidateMillisecondRemember);
        else
            validate = new Date(now + jwtTokenValidateMilliseconds);

        return Jwts.builder()
                .setSubject(authentication.getName())
                .claim("auth", authorities)
                .signWith(key, SignatureAlgorithm.HS512)
                .setExpiration(validate)
                .compact();
    }

    public Authentication getAuthentication(String jwt) {
        Claims claims = jwtParser.parseClaimsJwt(jwt).getBody();
        Collection<? extends GrantedAuthority> authorities = Arrays
                .stream(claims.get("auth").toString().split(","))
                .filter(auth -> !auth.trim().isEmpty())
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
        org.springframework.security.core.userdetails.User principal = new User(claims.getSubject(), "", authorities);
        return new UsernamePasswordAuthenticationToken(principal, jwt, authorities);
    }

    public boolean validateToken(String jwt) {
        try {
            jwtParser.parseClaimsJwt(jwt);
            return true;
        } catch (ExpiredJwtException e) {
            logger.error("ExpiredJwtException");
        } catch (UnsupportedJwtException e) {
            logger.error("UnsupportedJwtException");
        } catch (MalformedJwtException e) {
            logger.error("MalformedJwtException");
        } catch (SignatureException e) {
            logger.error("SignatureException");
        } catch (IllegalArgumentException e) {
            logger.error("IllegalArgumentException");
        }

        return false;
    }

}
