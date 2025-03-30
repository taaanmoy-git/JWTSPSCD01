package com.jwt.d01.jwtscd01.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
public class JwtHelper {

    // Token validity duration: 5 hours (in seconds)
    public static final long JWT_TOKEN_VALIDITY = 5 * 60 * 60;

    // Secret key used for signing and verifying JWT tokens
    // NOTE: In production, store this securely using environment variables or a key vault service
    private final String secret = "afafasfafafasfasfasfafacasdasfasxASFACASDFACASDFASFASFDAFASFASDAADSCSDFADCVSGCFVADXCcadwavfsfarvf";

    /**
     * Extract the username (subject) from the JWT token.
     * 
     * @param token The JWT token.
     * @return The username stored in the token.
     */
    public String getUsernameFromToken(String token) {
        // Extract the subject claim (username) using a resolver
        return getClaimFromToken(token, Claims::getSubject);
    }

    /**
     * Extract the expiration date of the JWT token.
     * 
     * @param token The JWT token.
     * @return The expiration date stored in the token.
     */
    public Date getExpirationDateFromToken(String token) {
        // Extract the expiration claim using a resolver
        return getClaimFromToken(token, Claims::getExpiration);
    }

    /**
     * Extract specific claims from the JWT token using a custom resolver function.
     * 
     * @param token The JWT token.
     * @param claimsResolver A functional interface to extract specific claims.
     * @return The value of the requested claim.
     * @param <T> Generic type for claim value (e.g., String, Date, etc.).
     */
    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        // Get all claims from the token
        final Claims claims = getAllClaimsFromToken(token);
        // Resolve the specific claim using the provided resolver
        return claimsResolver.apply(claims);
    }

    /**
     * Extract all claims from the JWT token using the secret key.
     * 
     * @param token The JWT token.
     * @return The claims stored in the token.
     */
    private Claims getAllClaimsFromToken(String token) {
        // Parse the token using the secret key and return all claims
        return Jwts.parser()
                .setSigningKey(secret) // Verify the token using the secret key
                .parseClaimsJws(token) // Parse the token
                .getBody(); // Get the body containing the claims
    }

    /**
     * Check if the token has expired.
     * 
     * @param token The JWT token.
     * @return true if the token has expired; false otherwise.
     */
    private Boolean isTokenExpired(String token) {
        // Get the expiration date from the token
        final Date expiration = getExpirationDateFromToken(token);
        // Compare the expiration date with the current time
        return expiration.before(new Date());
    }

    /**
     * Generate a JWT token for the given user details.
     * 
     * @param userDetails The user details containing the username.
     * @return The generated JWT token.
     */
    public String generateToken(UserDetails userDetails) {
        // Create an empty map for claims (can be extended for additional claims)
        Map<String, Object> claims = new HashMap<>();
        // Generate the token with the username and claims
        return doGenerateToken(claims, userDetails.getUsername());
    }

    /**
     * Create the JWT token with claims, subject, issued date, and expiration.
     * 
     * @param claims Additional claims to include in the token.
     * @param subject The subject (username) for the token.
     * @return The generated JWT token.
     */
    private String doGenerateToken(Map<String, Object> claims, String subject) {
        // Use the JJWT builder to construct the token
        return Jwts.builder()
                .setClaims(claims) // Set the claims (custom key-value data)
                .setSubject(subject) // Set the subject (usually the username)
                .setIssuedAt(new Date(System.currentTimeMillis())) // The issue date
                .setExpiration(new Date(System.currentTimeMillis() + JWT_TOKEN_VALIDITY * 1000)) // The expiration date
                .signWith(SignatureAlgorithm.HS512, secret) // Sign the token with the secret key and HS512 algorithm
                .compact(); // Compact the token into a string
    }

    /**
     * Validate the JWT token.
     * 
     * @param token The JWT token to validate.
     * @param userDetails The user details to match against the token.
     * @return true if the token is valid; false otherwise.
     */
    public Boolean validateToken(String token, UserDetails userDetails) {
        // Extract the username from the token
        final String username = getUsernameFromToken(token);
        // Validate the username and check for token expiration
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }
}